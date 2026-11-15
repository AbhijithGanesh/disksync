use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashMap, HashSet},
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        mpsc::{self, SyncSender},
        Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

mod report;
use report::Exe;

const IGNORE: &str = include_str!("../ignore.txt");
// Only these extensions are ever copied (case-insensitive).
const KEEP: [&str; 7] = ["jpg", "jpeg", "png", "mp4", "mp3", "txt", "pdf"];

struct Rules {
    names: Vec<String>, // lowercase, may start/end with `*`
    paths: Vec<PathBuf>,
}

fn rules(root: &Path) -> Rules {
    let mut r = Rules { names: vec![], paths: vec![] };
    for l in IGNORE.lines().map(str::trim) {
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        match l.strip_prefix('/') {
            Some(p) => r.paths.push(root.join(p)),
            None => r.names.push(l.to_lowercase()),
        }
    }
    r
}

#[derive(Default)]
struct Stats {
    copied: AtomicU64,
    bytes: AtomicU64,
    unchanged: AtomicU64,
    dupes: AtomicU64,
    errors: AtomicU64,
    dir: Mutex<PathBuf>, // where the walk currently is, for progress lines
}

impl Stats {
    fn line(&self) -> String {
        format!(
            "copied {} ({} MB), unchanged {}, dupes {}, errors {}",
            self.copied.load(Relaxed),
            self.bytes.load(Relaxed) >> 20,
            self.unchanged.load(Relaxed),
            self.dupes.load(Relaxed),
            self.errors.load(Relaxed)
        )
    }
}

// "C:" alone means "current dir on C:" to Windows; make it the drive root.
fn root(arg: &str) -> PathBuf {
    if arg.len() == 2 && arg.ends_with(':') { PathBuf::from(format!("{arg}\\")) } else { PathBuf::from(arg) }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let [src_arg, dst_arg] = &args[..] else {
        eprintln!("usage: windowsyncutility <source-drive> <backup-drive>   e.g. windowsyncutility C: F:");
        return ExitCode::from(2);
    };
    let src = root(src_arg);
    // C: -> F:\C\..., D: -> F:\D\... so several source drives can share one backup disk.
    let tag: String = src_arg.chars().filter(|c| c.is_alphanumeric()).collect();
    let dest = root(dst_arg).join(if tag.is_empty() { "backup".into() } else { tag.to_uppercase() });
    if !src.is_dir() {
        eprintln!("source {} not found", src.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::create_dir_all(&dest) {
        eprintln!("cannot create {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }

    let mut rules = rules(&src);
    rules.paths.push(dest.clone()); // never back up the backup if it lives on the source drive

    let st = backup(&src, &dest, &rules);
    println!("{}", st.line());
    if st.errors.load(Relaxed) > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

// `/` rules match a file or dir; a `*` component matches any one name. Case-insensitive like NTFS.
fn excluded(path: &Path, rules: &Rules) -> bool {
    rules.paths.iter().any(|pat| {
        let (mut a, mut b) = (pat.components(), path.components());
        loop {
            match (a.next(), b.next()) {
                (None, None) => return true,
                (Some(x), Some(y)) if x.as_os_str() == "*" || x.as_os_str().eq_ignore_ascii_case(y.as_os_str()) => {}
                _ => return false,
            }
        }
    })
}

fn name_hit(name: &OsStr, rules: &Rules) -> bool {
    let n = name.to_string_lossy().to_lowercase();
    rules.names.iter().any(|p| {
        let core = p.trim_matches('*');
        match (p.starts_with('*'), p.len() > 1 && p.ends_with('*')) {
            (true, true) => n.contains(core),
            (true, false) => n.ends_with(core),
            (false, true) => n.starts_with(core),
            _ => n == core,
        }
    })
}

fn skip_dir(path: &Path, rules: &Rules) -> bool {
    name_hit(path.file_name().unwrap_or_default(), rules)
        || excluded(path, rules)
        || path.join("CACHEDIR.TAG").exists()
}

fn skip_file(path: &Path, rules: &Rules) -> bool {
    let keep = path.extension().is_some_and(|e| KEEP.iter().any(|k| e.eq_ignore_ascii_case(k)));
    !keep || name_hit(path.file_name().unwrap_or_default(), rules) || excluded(path, rules)
}

type Job = (PathBuf, PathBuf);
type Sizes = HashMap<PathBuf, u64>;

// Scan and file copies run on every CPU; the walk (which feeds the copiers) is one thread.
fn backup(src: &Path, dst: &Path, rules: &Rules) -> Stats {
    let t = Instant::now();
    eprintln!("[scan] sizing {} ...", src.display());
    let (sizes, mut exes) = dir_sizes(src, rules);
    let total = sizes.get(src).copied().unwrap_or(0);
    eprintln!("[scan] {} MB to check, {} executables skipped, took {:.0?}", total >> 20, exes.len(), t.elapsed());

    let st = Stats::default();
    let (tx, rx) = mpsc::sync_channel::<Job>(4096);
    let rx = Mutex::new(rx);
    let done = AtomicBool::new(false);
    let n = threads();
    thread::scope(|s| {
        let workers: Vec<_> = (0..n)
            .map(|_| {
                s.spawn(|| loop {
                    let job = rx.lock().unwrap().recv();
                    let Ok((from, to)) = job else { break };
                    if let Err(e) = sync_file(&from, &to, &st) {
                        report(&from, e, &st);
                    }
                })
            })
            .collect();
        s.spawn(|| {
            let mut ticks = 0u32;
            while !done.load(Relaxed) {
                thread::sleep(Duration::from_millis(100));
                ticks += 1;
                if ticks % 50 == 0 {
                    eprintln!("[progress] {} | {}", st.line(), st.dir.lock().unwrap().display());
                }
            }
        });
        walk(src, dst, rules, &sizes, &st, &tx);
        drop(tx); // workers exit once the queue drains
        for w in workers {
            w.join().unwrap();
        }
        done.store(true, Relaxed);
    });
    if let Err(e) = report::write(dst, src, &mut exes) {
        report(&dst.join("_executables.*"), e, &st);
    }
    st
}

// Pre-pass, on every CPU: bytes of wanted files under every dir, plus every executable seen
// (for the report). Sizes drive the largest-first order, and dirs with 0 are never walked, so
// the backup doesn't mirror every empty folder on the drive.
// ponytail: so 0-byte files are never copied; fine for photos/media/docs.
// Junctions/symlinks (e.g. "Documents and Settings") are not dirs here, so never followed.
fn dir_sizes(root: &Path, rules: &Rules) -> (Sizes, Vec<Exe>) {
    // Shared stack of dirs still to read + how many are being read right now.
    let work = Mutex::new((vec![root.to_path_buf()], 0usize));
    let (cv, own, exes) = (Condvar::new(), Mutex::new(vec![]), Mutex::new(vec![]));
    thread::scope(|s| {
        for _ in 0..threads() {
            s.spawn(|| loop {
                let dir = {
                    let mut g = work.lock().unwrap();
                    loop {
                        if let Some(d) = g.0.pop() {
                            g.1 += 1;
                            break d;
                        }
                        if g.1 == 0 {
                            return; // nothing queued, nobody reading: done
                        }
                        g = cv.wait(g).unwrap();
                    }
                };
                let (mut bytes, mut subs, mut found) = (0, vec![], vec![]);
                for e in fs::read_dir(&dir).into_iter().flatten().flatten() {
                    let Ok(ft) = e.file_type() else { continue };
                    let path = e.path();
                    if ft.is_dir() {
                        if !skip_dir(&path, rules) {
                            subs.push(path);
                        }
                    } else if ft.is_file() && !skip_file(&path, rules) {
                        bytes += e.metadata().map_or(0, |m| m.len());
                    } else if ft.is_file() && report::is_exec(&path) {
                        if let Ok(m) = e.metadata() {
                            found.push(Exe { path, size: m.len(), modified: m.modified().unwrap_or(UNIX_EPOCH) });
                        }
                    }
                }
                own.lock().unwrap().push((dir, bytes));
                exes.lock().unwrap().extend(found);
                let mut g = work.lock().unwrap();
                g.0.extend(subs);
                g.1 -= 1;
                cv.notify_all();
            });
        }
    });
    // Roll each dir's own bytes up into its ancestors, deepest dirs first.
    let mut own = own.into_inner().unwrap();
    own.sort_by_cached_key(|(p, _)| Reverse(p.components().count()));
    let mut sizes = Sizes::new();
    for (p, b) in own {
        let total = sizes.get(&p).copied().unwrap_or(0) + b;
        if p != root {
            *sizes.entry(p.parent().unwrap().to_path_buf()).or_default() += total;
        }
        sizes.insert(p, total);
    }
    (sizes, exes.into_inner().unwrap())
}

fn threads() -> usize {
    thread::available_parallelism().map_or(4, |n| n.get())
}

// A dir's entries, biggest first: dirs by total size from the pre-pass, files by their own size.
fn largest_first(dir: &Path, sizes: &Sizes) -> io::Result<Vec<fs::DirEntry>> {
    let mut v: Vec<_> = fs::read_dir(dir)?.flatten().collect();
    v.sort_by_cached_key(|e| {
        Reverse(match e.file_type() {
            Ok(ft) if ft.is_dir() => sizes.get(&e.path()).copied().unwrap_or(0),
            Ok(ft) if ft.is_file() => e.metadata().map_or(0, |m| m.len()),
            _ => 0,
        })
    });
    Ok(v)
}

fn walk(src: &Path, dst: &Path, rules: &Rules, sizes: &Sizes, st: &Stats, tx: &SyncSender<Job>) {
    *st.dir.lock().unwrap() = src.to_path_buf();
    let mut entries = match largest_first(src, sizes).and_then(|e| fs::create_dir_all(dst).map(|_| e)) {
        Ok(e) => e,
        Err(e) => return report(src, e, st),
    };
    // before dedup, so a skipped file is never the kept "original"
    entries.retain(|e| match e.file_type() {
        Ok(ft) if ft.is_dir() => sizes.get(&e.path()).is_some_and(|&n| n > 0),
        Ok(ft) if ft.is_file() => !skip_file(&e.path(), rules),
        _ => false, // symlinks, junctions, devices
    });
    let dupes = skip_duplicates(&entries, dst, st);
    for entry in entries {
        let target = dst.join(entry.file_name());
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&entry.path(), &target, rules, sizes, st, tx);
        } else if !dupes.contains(&entry.file_name()) {
            let _ = tx.send((entry.path(), target)); // dst dir already exists
        }
    }
}

// Files in one dir with identical content (same size, then same SHA-256) are copied once:
// the alphabetically first name is the original, the rest are skipped and listed in
// `<dst>/_duplicates.log` as `original | sha256 | copy, copy`. Empty files are never deduped.
// (.log, not .txt, so it can't collide with a backed-up file.) Returns the names to skip.
// ponytail: hashing runs on the walk thread (only same-size files); move to workers if it stalls.
fn skip_duplicates(entries: &[fs::DirEntry], dst: &Path, st: &Stats) -> HashSet<OsString> {
    let mut by_size: HashMap<u64, Vec<&fs::DirEntry>> = HashMap::new();
    for e in entries {
        if e.file_type().is_ok_and(|t| t.is_file()) {
            match e.metadata().map(|m| m.len()) {
                Ok(0) | Err(_) => {}
                Ok(len) => by_size.entry(len).or_default().push(e),
            }
        }
    }
    let mut by_sha: BTreeMap<String, Vec<OsString>> = BTreeMap::new();
    for e in by_size.into_values().filter(|g| g.len() > 1).flatten() {
        if let Ok(h) = sha256(&e.path()) {
            by_sha.entry(h).or_default().push(e.file_name()); // unreadable: copy worker reports it
        }
    }
    let (mut skip, mut txt) = (HashSet::new(), String::new());
    for (sha, mut names) in by_sha.into_iter().filter(|(_, n)| n.len() > 1) {
        names.sort();
        let copies: Vec<_> = names[1..].iter().map(|n| n.to_string_lossy()).collect();
        txt += &format!("{} | {sha} | {}\n", names[0].to_string_lossy(), copies.join(", "));
        st.dupes.fetch_add(copies.len() as u64, Relaxed);
        skip.extend(names.into_iter().skip(1));
    }
    if !txt.is_empty() {
        let out = dst.join("_duplicates.log");
        if let Err(e) = fs::write(&out, txt) {
            report(&out, e, st);
        }
    }
    skip
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// SHA-256 (FIPS 180-4), hand-rolled to stay stdlib-only.
fn sha256(path: &Path) -> io::Result<String> {
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let (mut f, mut buf, mut pending, mut len) = (fs::File::open(path)?, vec![0; 1 << 16], vec![], 0u64);
    loop {
        let n = match f.read(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => r?,
        };
        if n == 0 {
            break;
        }
        len += n as u64;
        pending.extend_from_slice(&buf[..n]);
        let full = pending.len() / 64 * 64;
        pending[..full].chunks_exact(64).for_each(|b| compress(&mut h, b));
        pending.drain(..full);
    }
    pending.push(0x80);
    while pending.len() % 64 != 56 {
        pending.push(0);
    }
    pending.extend_from_slice(&(len * 8).to_be_bytes());
    pending.chunks_exact(64).for_each(|b| compress(&mut h, b));
    Ok(h.iter().map(|x| format!("{x:08x}")).collect())
}

fn compress(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let t1 = hh.wrapping_add(s1).wrapping_add((e & f) ^ (!e & g)).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let t2 = s0.wrapping_add((a & b) ^ (a & c) ^ (b & c));
        (hh, g, f, e, d, c, b, a) = (g, f, e, d.wrapping_add(t1), c, b, a, t1.wrapping_add(t2));
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(y);
    }
}

// Incremental: a file is re-copied only when its size or mtime differs from the backup copy.
fn sync_file(src: &Path, dst: &Path, st: &Stats) -> io::Result<()> {
    let sm = fs::metadata(src)?;
    if let Ok(dm) = fs::metadata(dst) {
        if dm.len() == sm.len() && same_mtime(dm.modified()?, sm.modified()?) {
            st.unchanged.fetch_add(1, Relaxed);
            return Ok(());
        }
        fs::remove_file(dst)?;
    }
    st.bytes.fetch_add(fs::copy(src, dst)?, Relaxed);
    // Windows copies the read-only attribute, which would block set_modified and the next update.
    let mut p = fs::metadata(dst)?.permissions();
    if p.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        p.set_readonly(false);
        fs::set_permissions(dst, p)?;
    }
    fs::File::options().write(true).open(dst)?.set_modified(sm.modified()?)?;
    st.copied.fetch_add(1, Relaxed);
    Ok(())
}

// Backup disks store mtime coarser than NTFS (exFAT: 10ms, FAT32: 2s), so exact equality
// would re-copy everything every run.
// ponytail: a same-size edit within 2s of the last backup is missed; hash files if that matters.
fn same_mtime(a: SystemTime, b: SystemTime) -> bool {
    a.duration_since(b).unwrap_or_else(|e| e.duration()) < Duration::from_secs(2)
}

fn report(path: &Path, e: io::Error, st: &Stats) {
    eprintln!("{}: {e}", path.display());
    st.errors.fetch_add(1, Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backs_up_wanted_types_incrementally() {
        let root = env::temp_dir().join(format!("winsync-test-{}", std::process::id()));
        let (src, dst) = (root.join("src"), root.join("dst"));
        for d in ["Pics/sub", "Users/bob/AppData/Local", "Games/Trainer v2", "Windows/Web", "Empty", "Browser/User Data"] {
            fs::create_dir_all(src.join(d)).unwrap();
        }
        let files = [
            ("Pics/a.JPG", "photo"), ("Pics/sub/song.mp3", "music"), ("Pics/doc.pdf", "pdf"),
            ("Pics/notes.txt", "hi"), ("Pics/setup.exe", "MZ"), ("Pics/x.zip", "PK"), ("Pics/m.docm", "d"),
            ("Pics/passwords.txt", "hunter2"), ("Users/bob/AppData/Local/c.png", "p"),
            ("Games/Trainer v2/readme.txt", "r"), ("Windows/Web/wall.jpg", "w"), ("Empty/run.bat", "x"),
            ("Browser/User Data/t.png", "t"), ("Users/bob/AppData/Local/app.exe", "MZ"),
        ];
        for (f, c) in files {
            fs::write(src.join(f), c).unwrap();
        }

        let n = |a: &AtomicU64| a.load(Relaxed);
        let rules = rules(&src);
        let st = backup(&src, &dst, &rules);
        assert_eq!((n(&st.copied), n(&st.errors)), (4, 0));
        for f in ["Pics/a.JPG", "Pics/sub/song.mp3", "Pics/doc.pdf", "Pics/notes.txt"] {
            assert_eq!(fs::read(dst.join(f)).unwrap(), fs::read(src.join(f)).unwrap());
        }
        for f in &files[4..] {
            assert!(!dst.join(f.0).exists(), "{} should be skipped", f.0);
        }
        for d in ["Empty", "Users", "Windows", "Games"] {
            assert!(!dst.join(d).exists(), "{d}: no empty dirs mirrored");
        }

        // executables report: found in walked areas (even folders with nothing to copy), not in AppData
        for f in ["_executables.xlsx", "_executables.pdf"] {
            let r = String::from_utf8_lossy(&fs::read(dst.join(f)).unwrap()).into_owned();
            assert!(r.contains("setup.exe") && r.contains("run.bat") && !r.contains("app.exe"), "{f}");
        }

        let st = backup(&src, &dst, &rules);
        assert_eq!((n(&st.copied), n(&st.unchanged)), (0, 4));

        fs::write(src.join("Pics/notes.txt"), "changed").unwrap();
        let st = backup(&src, &dst, &rules);
        assert_eq!(n(&st.copied), 1);
        assert_eq!(fs::read_to_string(dst.join("Pics/notes.txt")).unwrap(), "changed");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn skips_duplicates_per_dir() {
        let root = env::temp_dir().join(format!("winsync-dupes-{}", std::process::id()));
        let (src, dst) = (root.join("src"), root.join("dst"));
        fs::create_dir_all(src.join("sub")).unwrap();
        for (f, c) in [("x.jpg", "same"), ("z.jpg", "same"), ("y.jpg", "same"), ("w.jpg", "diff"), ("sub/x.jpg", "same")] {
            fs::write(src.join(f), c).unwrap();
        }
        let abc = root.join("abc");
        fs::write(&abc, "abc").unwrap();
        assert_eq!(sha256(&abc).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        let n = |a: &AtomicU64| a.load(Relaxed);
        let st = backup(&src, &dst, &rules(&root));
        assert_eq!((n(&st.copied), n(&st.dupes), n(&st.errors)), (3, 2, 0)); // x w sub/x
        assert!(!dst.join("y.jpg").exists() && !dst.join("z.jpg").exists());
        let sha = sha256(&src.join("x.jpg")).unwrap();
        assert_eq!(fs::read_to_string(dst.join("_duplicates.log")).unwrap(), format!("x.jpg | {sha} | y.jpg, z.jpg\n"));
        assert!(!dst.join("sub/_duplicates.log").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn drive_arg_becomes_root() {
        assert_eq!(root("C:"), PathBuf::from("C:\\"));
        assert_eq!(root("D:\\Photos"), PathBuf::from("D:\\Photos"));
    }
}
