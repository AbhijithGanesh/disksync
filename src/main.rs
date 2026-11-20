use std::{
    cmp::Reverse,
    collections::{BTreeMap, HashMap, HashSet},
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, Read, Write},
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
mod restore;
mod safety;
use report::Exe;

const IGNORE: &str = include_str!("../ignore.txt");
const GAMES: &str = include_str!("../games.txt");
// Only these extensions are ever copied (case-insensitive). Each has a header check in safety.rs.
const KEEP: &[&str] = &[
    // photos, incl. iPhone HEIC and camera RAW
    "jpg", "jpeg", "png", "tif", "tiff", "heic", "heif", "webp", "gif", "bmp",
    "dng", "cr2", "cr3", "nef", "arw", "orf", "rw2", "raf",
    "mp4", "mp3", "txt", "pdf",
];

#[derive(Clone)]
struct Rules {
    names: Vec<String>, // `*` globs
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
            None => r.names.push(l.to_string()),
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
    seen: AtomicU64, // bytes of walked files handled so far (copied, unchanged, blocked, dupes)
    dir: Mutex<PathBuf>, // where the walk currently is, for progress lines
    folders: Mutex<BTreeMap<PathBuf, Folder>>, // backup dir -> what's in it, for _folders.xlsx
    blocked: Mutex<Vec<Exe>>,                  // failed safety checks, for _blocked.xlsx
}

#[derive(Default)]
struct Folder {
    src: PathBuf,
    game: Option<&'static str>,
    files: Vec<(String, String)>, // (name, sha256)
    bytes: u64,
    copied: u64,
}

// (backup file path relative to the backup root) -> (size, mtime ns, sha256)
type Hashes = HashMap<PathBuf, (u64, u128, String)>;

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

    // `12:34:56Z [######--------------]  30.1%  1200/4000 MB  ETA 7m12s`
    fn progress(&self, total: u64, start: Instant) -> String {
        let seen = self.seen.load(Relaxed).min(total);
        let frac = if total == 0 { 1.0 } else { seen as f64 / total as f64 };
        let fill = (frac * 20.0) as usize;
        let eta = match start.elapsed().as_secs_f64() {
            t if seen > 0 && t > 0.0 => {
                hms((t * (total - seen) as f64 / seen as f64) as u64)
            }
            _ => "?".into(),
        };
        format!("{} [{}{}] {:5.1}%  {}/{} MB  ETA {eta}", clock(), "#".repeat(fill), "-".repeat(20 - fill), frac * 100.0, seen >> 20, total >> 20)
    }
}

// Human-readable timestamp for log lines, e.g. "15 Nov 2026, 5:37:36 PM".
fn clock() -> String {
    clock_at(SystemTime::now())
}

fn clock_at(t: SystemTime) -> String {
    let utc = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (s, zone) = match utc_offset() {
        Some(off) => (utc + off, ""),
        None => (utc, " UTC"),
    };
    let (y, m, d, rem) = report::civil(s);
    let mon = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][m as usize - 1];
    let (h, ampm) = (rem / 3600, if rem < 12 * 3600 { "AM" } else { "PM" });
    format!("{d} {mon} {y}, {}:{:02}:{:02} {ampm}{zone}", (h + 11) % 12 + 1, rem / 60 % 60, rem % 60)
}

// Local time's offset from UTC in seconds, from Windows' local vs UTC clock (stdlib-only FFI).
#[cfg(windows)]
fn utc_offset() -> Option<i64> {
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime { y: u16, mo: u16, dow: u16, d: u16, h: u16, mi: u16, s: u16, ms: u16 }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLocalTime(t: *mut SystemTime);
        fn GetSystemTime(t: *mut SystemTime);
    }
    let (mut l, mut u) = (SystemTime::default(), SystemTime::default());
    unsafe {
        GetLocalTime(&mut l);
        GetSystemTime(&mut u);
    }
    let mins = |t: &SystemTime| t.h as i64 * 60 + t.mi as i64;
    let day = |t: &SystemTime| (t.y, t.mo, t.d);
    let wrap = match day(&l).cmp(&day(&u)) {
        std::cmp::Ordering::Greater => 1440,
        std::cmp::Ordering::Less => -1440,
        std::cmp::Ordering::Equal => 0,
    };
    let off = mins(&l) - mins(&u) + wrap;
    Some((off as f64 / 15.0).round() as i64 * 15 * 60) // zones are whole quarter hours
}

// ponytail: non-Windows (dev/tests) shows UTC; read TZ if this ever runs elsewhere for real.
#[cfg(not(windows))]
fn utc_offset() -> Option<i64> {
    None
}

// 7m12s, or 1h05m once it's over an hour.
fn hms(s: u64) -> String {
    if s >= 3600 { format!("{}h{:02}m", s / 3600, s / 60 % 60) } else { format!("{}m{:02}s", s / 60, s % 60) }
}

// Upfront ETA: time the backup disk on small files (written in parallel, like the copy) and on
// one flushed 32 MB file, then scale to the scan's file count and bytes.
// ponytail: ignores source read speed, antivirus and incremental skips; the live ETA corrects it.
fn estimate(dst: &Path, files: u64, bytes: u64, n: usize) -> io::Result<Duration> {
    let dir = dst.join("_speedtest.tmp");
    fs::create_dir_all(&dir)?;
    let run = || -> io::Result<Duration> {
        const PER: usize = 20;
        let small = vec![0u8; 64 << 10];
        let t = Instant::now();
        thread::scope(|s| {
            let hs: Vec<_> = (0..n)
                .map(|i| {
                    let (dir, small) = (&dir, &small);
                    s.spawn(move || (0..PER).try_for_each(|j| fs::write(dir.join(format!("{i}_{j}")), small)))
                })
                .collect();
            hs.into_iter().try_for_each(|h| h.join().unwrap())
        })?;
        let per_file = t.elapsed().as_secs_f64() / (n * PER) as f64;
        let big = vec![0u8; 32 << 20];
        let t = Instant::now();
        let mut f = fs::File::create(dir.join("big"))?;
        f.write_all(&big)?;
        f.sync_all()?; // past the write cache, to the disk
        let bps = big.len() as f64 / t.elapsed().as_secs_f64().max(1e-6);
        Ok(Duration::from_secs_f64(files as f64 * per_file + bytes as f64 / bps))
    };
    let res = run();
    let _ = fs::remove_dir_all(&dir);
    res
}

// "C:" alone means "current dir on C:" to Windows; make it the drive root.
fn root(arg: &str) -> PathBuf {
    if arg.len() == 2 && arg.ends_with(':') { PathBuf::from(format!("{arg}\\")) } else { PathBuf::from(arg) }
}

// Bare drive (F: or F:\) -> F:\C\..., so several source drives can share one backup disk.
// A folder (H:\C_Backup) is used as-is: H:\C_Backup\Users\...
fn dest(src_arg: &str, dst_arg: &str) -> PathBuf {
    let d = dst_arg.trim_end_matches(['\\', '/']);
    if d.len() != 2 || !d.ends_with(':') {
        return PathBuf::from(dst_arg);
    }
    let tag: String = src_arg.chars().filter(|c| c.is_alphanumeric()).collect();
    root(d).join(if tag.is_empty() { "backup".into() } else { tag.to_uppercase() })
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if let [flag, dir] = &args[..] && flag == "--verify" {
        return if verify(Path::new(dir)) == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE };
    }
    if args.first().is_some_and(|a| a == "--restore") && args.len() >= 3 && args[3..].iter().all(|a| a == "--writable-ok" || a == "--no-hashes") {
        let has = |f: &str| args[3..].iter().any(|a| a == f);
        return restore_cmd(Path::new(&args[1]), Path::new(&args[2]), has("--writable-ok"), has("--no-hashes"));
    }
    let [src_arg, dst_arg] = &args[..] else {
        eprintln!("usage: disksync <source-drive> <backup-drive-or-folder>");
        eprintln!("       disksync --restore <backup-folder> <destination-folder> [--writable-ok] [--no-hashes]");
        eprintln!("            e.g. disksync --restore F:\\C D:\\Restored");
        eprintln!("       e.g. disksync C: F:            -> F:\\C\\...");
        eprintln!("            disksync C: H:\\C_Backup   -> H:\\C_Backup\\...");
        eprintln!("       disksync --verify <backup-folder>       e.g. disksync --verify F:\\C");
        return ExitCode::from(2);
    };
    let src = root(src_arg);
    let dest = dest(src_arg, dst_arg);
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
    println!("{} {}", clock(), st.line());
    if st.errors.load(Relaxed) > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS }
}

fn restore_cmd(backup: &Path, dest: &Path, writable_ok: bool, no_hashes: bool) -> ExitCode {
    if !backup.is_dir() {
        eprintln!("{} not found", backup.display());
        return ExitCode::FAILURE;
    }
    if !backup.join(HASHES).is_file() {
        if !no_hashes {
            eprintln!("{} has no {HASHES}: point at the backup folder (e.g. F:\\C).", backup.display());
            eprintln!("If the backup never finished, add --no-hashes to restore without the SHA-256 check.");
            return ExitCode::FAILURE;
        }
        eprintln!("WARNING: no {HASHES}: files can't be checked against the backup (SHA-256 check skipped).");
    }
    // Read-only so nothing on this PC (Defender included) can delete or change the originals.
    if restore::read_only_volume(backup) != Some(true) && !writable_ok {
        eprintln!("The backup disk is not read-only. To protect the originals, in an admin Command Prompt:");
        eprintln!("    diskpart");
        eprintln!("    list volume");
        eprintln!("    select volume <number of the backup disk>");
        eprintln!("    attributes volume set readonly");
        eprintln!("    exit");
        eprintln!("then unplug and replug the disk and run this again (or add --writable-ok to skip this).");
        return ExitCode::FAILURE;
    }
    if let Err(e) = fs::create_dir_all(dest) {
        eprintln!("cannot create {}: {e}", dest.display());
        return ExitCode::FAILURE;
    }
    match (fs::canonicalize(backup), fs::canonicalize(dest)) {
        (Ok(b), Ok(d)) if d.starts_with(&b) || b.starts_with(&d) => {
            eprintln!("destination and backup must not be inside each other");
            return ExitCode::FAILURE;
        }
        (Ok(_), Ok(_)) => {}
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    }
    let out = match restore::restore(backup, dest, !no_hashes, restore::defender) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("restore failed, nothing more released: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("{} restored {}, already there {}, held back {}", clock(), out.restored, out.already, out.held.len());
    if out.held.is_empty() {
        return ExitCode::SUCCESS;
    }
    let held = dest.join(restore::HELD);
    println!("held files are untouched on the backup; list: {}", held.join("_held.xlsx").display());
    restore::open_sandbox(&held.join("inspect.wsb"));
    ExitCode::FAILURE
}

// `/` rules match a file or dir; a `*` component matches any one name. Case-insensitive like NTFS.
fn excluded(path: &Path, rules: &Rules) -> bool {
    rules.paths.iter().any(|pat| {
        let (mut a, mut b) = (pat.components(), path.components());
        loop {
            match (a.next(), b.next()) {
                (None, None) => return true,
                (Some(x), Some(y)) if glob(&x.as_os_str().to_string_lossy(), y.as_os_str()) => {}
                _ => return false,
            }
        }
    })
}

fn name_hit(name: &OsStr, rules: &Rules) -> bool {
    rules.names.iter().any(|p| glob(p, name))
}

// Case-insensitive match of one name against a pattern where `*` is any run of characters.
fn glob(pat: &str, name: &OsStr) -> bool {
    let (pat, n) = (pat.to_lowercase(), name.to_string_lossy().to_lowercase());
    let parts: Vec<&str> = pat.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if parts.len() == 1 {
        return n == first;
    }
    if n.len() < first.len() + last.len() || !n.starts_with(first) || !n.ends_with(last) {
        return false;
    }
    let mut rest = &n[first.len()..n.len() - last.len()];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
}

// Existing dirs matching `/a/*/b` under root, each with its game name.
fn game_dirs(root: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut out = vec![];
    for l in GAMES.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let Some((game, pat)) = l.split_once('|') else { continue };
        let mut found = vec![root.to_path_buf()];
        for part in pat.trim().split(['/', '\\']).filter(|p| !p.is_empty()) {
            found = found
                .iter()
                .flat_map(|d| {
                    fs::read_dir(d).into_iter().flatten().flatten().filter(|e| {
                        e.file_type().is_ok_and(|t| t.is_dir()) && glob(part, &e.file_name())
                    })
                })
                .map(|e| e.path())
                .collect();
        }
        out.extend(found.into_iter().map(|p| (game.trim(), p)));
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out.dedup_by(|a, b| a.1 == b.1);
    out
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

type Job = (PathBuf, PathBuf, Option<&'static str>, u64); // (from, to, game, bytes toward progress)
type Sizes = HashMap<PathBuf, u64>;

// Scan and file copies run on every CPU; the walk (which feeds the copiers) is one thread.
fn backup(src: &Path, dst: &Path, rules: &Rules) -> Stats {
    let t = Instant::now();
    let games = game_dirs(src);
    for (g, d) in &games {
        eprintln!("[game] {g}: {}", d.display());
    }
    let mut rules = rules.clone();
    rules.paths.extend(games.iter().map(|g| g.1.clone())); // copied by the game pass, not the walk
    let rules = &rules;
    let cache = load_hashes(dst);
    eprintln!("[scan] sizing {} ...", src.display());
    let (sizes, mut exes, files) = dir_sizes(src, rules);
    let total = sizes.get(src).copied().unwrap_or(0);
    eprintln!("[scan] {files} files, {} MB to check, {} executables skipped, took {:.0?}", total >> 20, exes.len(), t.elapsed());

    let st = Stats::default();
    let (tx, rx) = mpsc::sync_channel::<Job>(4096);
    let rx = Mutex::new(rx);
    let done = AtomicBool::new(false);
    // Small files are latency-bound (open/close, antivirus), not CPU-bound: oversubscribe.
    // ponytail: fixed 4x; tune down if the backup disk is a slow HDD that thrashes.
    let n = threads() * 4;
    match estimate(dst, files, total, n) {
        Ok(d) => {
            let end = SystemTime::now() + d;
            eprintln!("[estimate] ~{} if everything needs copying (first run), done ~{}", hms(d.as_secs()), clock_at(end));
        }
        Err(e) => eprintln!("[estimate] backup disk speed test failed: {e}"),
    }
    let start = Instant::now();
    thread::scope(|s| {
        let workers: Vec<_> = (0..n)
            .map(|_| {
                s.spawn(|| loop {
                    let job = rx.lock().unwrap().recv();
                    let Ok((from, to, game, size)) = job else { break };
                    // Content check on every run, also for unchanged files: a backup copy
                    // made before a check existed (or got stricter) is removed.
                    // ponytail: re-reads every PDF each run; cache verdicts by hash if too slow.
                    // Game saves are their own formats: they only get the extension filter.
                    let verdict = if game.is_some() { Ok(None) } else { safety::risk(&from) };
                    let res = match verdict {
                        Ok(None) => sync_file(&from, &to, &st).and_then(|(copied, sha)| record(&from, &to, game, copied, sha, dst, &cache, &st)),
                        Ok(Some(reason)) => block(&from, &to, reason, &st),
                        Err(e) => Err(e),
                    };
                    if let Err(e) = res {
                        report(&from, e, &st);
                    }
                    st.seen.fetch_add(size, Relaxed);
                })
            })
            .collect();
        s.spawn(|| {
            let mut ticks = 0u32;
            while !done.load(Relaxed) {
                thread::sleep(Duration::from_millis(100));
                ticks += 1;
                if ticks % 50 == 0 {
                    eprintln!("{} | {}", st.progress(total, start), st.line());
                    eprintln!("    in {}", st.dir.lock().unwrap().display());
                }
            }
        });
        walk(src, dst, rules, &sizes, &st, &tx);
        for (game, dir) in &games {
            let rel = dir.strip_prefix(src).unwrap_or(dir);
            copy_tree(dir, &dst.join(rel), game, &st, &tx);
        }
        drop(tx); // workers exit once the queue drains
        for w in workers {
            w.join().unwrap();
        }
        done.store(true, Relaxed);
        eprintln!("{}", st.progress(total, start));
    });
    exes.append(&mut st.blocked.lock().unwrap());
    eprintln!("[safety] {} files blocked, see _blocked.xlsx", exes.len());
    if let Err(e) = report::write(dst, "_blocked", "Files NOT backed up (executables / unsafe content)", src, &mut exes) {
        report(&dst.join("_blocked.*"), e, &st);
    }
    if let Err(e) = write_folders(dst, &st) {
        report(&dst.join("_folders.xlsx"), e, &st);
    }
    st
}

// Pre-pass, on every CPU: bytes of wanted files under every dir, plus every executable seen
// (for the report). Sizes drive the largest-first order, and dirs with 0 are never walked, so
// the backup doesn't mirror every empty folder on the drive.
// ponytail: so 0-byte files are never copied; fine for photos/media/docs.
// Junctions/symlinks (e.g. "Documents and Settings") are not dirs here, so never followed.
fn dir_sizes(root: &Path, rules: &Rules) -> (Sizes, Vec<Exe>, u64) {
    // Shared stack of dirs still to read + how many are being read right now.
    let work = Mutex::new((vec![root.to_path_buf()], 0usize));
    let (cv, own, exes, files) = (Condvar::new(), Mutex::new(vec![]), Mutex::new(vec![]), AtomicU64::new(0));
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
                        files.fetch_add(1, Relaxed);
                    } else if ft.is_file() && report::is_exec(&path) {
                        if let Ok(m) = e.metadata() {
                            let reason = "executable / script".into();
                            found.push(Exe { path, size: m.len(), modified: m.modified().unwrap_or(UNIX_EPOCH), reason });
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
    (sizes, exes.into_inner().unwrap(), files.into_inner())
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
        let size = entry.metadata().map_or(0, |m| m.len());
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            walk(&entry.path(), &target, rules, sizes, st, tx);
        } else if dupes.contains(&entry.file_name()) {
            st.seen.fetch_add(size, Relaxed);
        } else {
            let _ = tx.send((entry.path(), target, None, size)); // dst dir already exists
        }
    }
}

// Game saves: everything, empty folders included, same layout as the source.
fn copy_tree(src: &Path, dst: &Path, game: &'static str, st: &Stats, tx: &SyncSender<Job>) {
    *st.dir.lock().unwrap() = src.to_path_buf();
    let entries = match fs::read_dir(src).and_then(|e| fs::create_dir_all(dst).map(|_| e)) {
        Ok(e) => e,
        Err(e) => return report(src, e, st),
    };
    for e in entries.flatten() {
        let (path, target) = (e.path(), dst.join(e.file_name()));
        match e.file_type() {
            Ok(t) if t.is_dir() => copy_tree(&path, &target, game, st, tx),
            // the source PC may be infected: no executables/scripts even from save folders
            Ok(t) if t.is_file() && !report::is_exec(&path) => {
                let _ = tx.send((path, target, Some(game), 0)); // not in the scan total
            }
            _ => {} // symlinks, junctions
        }
    }
}

// After a file is synced: get its SHA-256 (computed during the copy, or from the cache if the
// backup copy is untouched since it was last hashed, else by reading it) and add it to its folder.
#[allow(clippy::too_many_arguments)]
fn record(src: &Path, dst: &Path, game: Option<&'static str>, copied: bool, fresh: Option<String>, root: &Path, cache: &Hashes, st: &Stats) -> io::Result<()> {
    let m = fs::metadata(dst)?;
    let mtime = m.modified()?.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let rel = dst.strip_prefix(root).unwrap_or(dst);
    let sha = match (fresh, cache.get(rel)) {
        (Some(sha), _) => sha,
        (None, Some((len, t, sha))) if !copied && *len == m.len() && *t == mtime => sha.clone(),
        _ => sha256(fs::File::open(dst)?)?,
    };
    let (Some(dir), Some(name)) = (dst.parent(), dst.file_name()) else { return Ok(()) };
    let mut folders = st.folders.lock().unwrap();
    let f = folders.entry(dir.to_path_buf()).or_default();
    f.src = src.parent().unwrap_or(src).to_path_buf();
    f.game = game;
    f.files.push((name.to_string_lossy().into_owned(), sha));
    f.bytes += m.len();
    f.copied += copied as u64;
    Ok(())
}

fn block(src: &Path, dst: &Path, reason: String, st: &Stats) -> io::Result<()> {
    let m = fs::metadata(src)?;
    let removed = fs::remove_file(dst).is_ok(); // an older backup copy of it, if any
    let reason = if removed { format!("{reason} (old backup copy deleted)") } else { reason };
    st.blocked.lock().unwrap().push(Exe { path: src.to_path_buf(), size: m.len(), modified: m.modified()?, reason });
    Ok(())
}

const HASHES: &str = "_hashes.tsv";

// `_hashes.tsv` in the backup root: `relative path<TAB>size<TAB>mtime ns<TAB>sha256` per file.
// It lets unchanged files skip re-hashing, and is what `--verify` checks against.
fn load_hashes(root: &Path) -> Hashes {
    let txt = fs::read_to_string(root.join(HASHES)).unwrap_or_default();
    txt.lines()
        .filter_map(|l| {
            let mut c = l.split('\t');
            let (p, len, t, sha) = (c.next()?, c.next()?.parse().ok()?, c.next()?.parse().ok()?, c.next()?);
            Some((PathBuf::from(p), (len, t, sha.to_string())))
        })
        .collect()
}

// One Excel row per backup folder (files directly in it; subfolders get their own rows).
// Folder SHA-256 = SHA-256 of the folder's `name<TAB>file sha256<LF>` lines, sorted by name:
// any added, removed, renamed or changed file changes it.
fn write_folders(root: &Path, st: &Stats) -> io::Result<()> {
    let mut folders = st.folders.lock().unwrap();
    let (mut rows, mut tsv) = (vec![], String::new());
    for (dir, f) in folders.iter_mut() {
        f.files.sort();
        let mut lines = String::new();
        for (name, sha) in &f.files {
            lines += &format!("{name}\t{sha}\n");
            let path = dir.join(name);
            if let Ok(m) = fs::metadata(&path) {
                let t = m.modified()?.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
                let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
                tsv += &format!("{rel}\t{}\t{t}\t{sha}\n", m.len());
            }
        }
        use report::Cell::{N, T};
        rows.push(vec![
            T(f.game.unwrap_or("").into()),
            T(f.src.display().to_string()),
            T(dir.display().to_string()),
            N(f.files.len() as u64),
            N(f.bytes),
            N(f.copied),
            T(sha256(lines.as_bytes())?),
        ]);
    }
    fs::write(root.join(HASHES), tsv)?;
    let cols = [
        ("Game", 24.0), ("Source folder", 70.0), ("Backup folder", 70.0), ("Files", 8.0),
        ("Size (bytes)", 16.0), ("Copied this run", 15.0), ("Folder SHA-256", 68.0),
    ];
    fs::write(root.join("_folders.xlsx"), report::xlsx(&cols, &rows))
}

// `--verify <backup folder>`: re-read every file listed in _hashes.tsv, on every CPU, and report
// any that are missing or whose content no longer matches. Returns the number of problems.
fn verify(root: &Path) -> u64 {
    let hashes: Vec<_> = load_hashes(root).into_iter().collect();
    if hashes.is_empty() {
        eprintln!("no {HASHES} in {} (run a backup first)", root.display());
        return 1;
    }
    let (next, bad) = (AtomicU64::new(0), AtomicU64::new(0));
    thread::scope(|s| {
        for _ in 0..threads() {
            s.spawn(|| loop {
                let Some((rel, (_, _, want))) = hashes.get(next.fetch_add(1, Relaxed) as usize) else { break };
                let path = root.join(rel);
                match fs::File::open(&path).and_then(sha256) {
                    Ok(got) if got == *want => continue,
                    Ok(_) => eprintln!("CHANGED  {}", path.display()),
                    Err(e) => eprintln!("MISSING  {}: {e}", path.display()),
                }
                bad.fetch_add(1, Relaxed);
            });
        }
    });
    let bad = bad.into_inner();
    println!("verified {} files, {bad} problems", hashes.len());
    bad
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
        if let Ok(h) = fs::File::open(e.path()).and_then(sha256) {
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
fn sha256(mut f: impl Read) -> io::Result<String> {
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let (mut buf, mut pending, mut len) = (vec![0; 1 << 16], vec![], 0u64);
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

// Files up to this size are copied through memory and hashed on the way, so the backup disk
// isn't re-read just to hash them. Bigger ones (videos) use fs::copy and are hashed after.
const SMALL: u64 = 64 << 20;

// Incremental: a file is re-copied only when its size or mtime differs from the backup copy.
// Returns whether it was copied, and its SHA-256 if that was computed during the copy.
fn sync_file(src: &Path, dst: &Path, st: &Stats) -> io::Result<(bool, Option<String>)> {
    let sm = fs::metadata(src)?;
    if let Ok(dm) = fs::metadata(dst) {
        if dm.len() == sm.len() && same_mtime(dm.modified()?, sm.modified()?) {
            st.unchanged.fetch_add(1, Relaxed);
            return Ok((false, None));
        }
        fs::remove_file(dst)?;
    }
    let sha = if sm.len() <= SMALL {
        let data = fs::read(src)?;
        fs::File::create(dst)?.write_all(&data)?; // fresh file: no read-only attribute copied
        st.bytes.fetch_add(data.len() as u64, Relaxed);
        Some(sha256(&data[..])?)
    } else {
        st.bytes.fetch_add(fs::copy(src, dst)?, Relaxed);
        // Windows copies the read-only attribute, which would block set_modified and the next update.
        let mut p = fs::metadata(dst)?.permissions();
        if p.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            p.set_readonly(false);
            fs::set_permissions(dst, p)?;
        }
        None
    };
    // Separate handle, after the data handle is closed, so the OS can't overwrite it on close.
    fs::File::options().write(true).open(dst)?.set_modified(sm.modified()?)?;
    st.copied.fetch_add(1, Relaxed);
    Ok((true, sha))
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

    // Test file with a real header for its type, so it passes the safety magic-byte check.
    fn put(p: &Path, c: &str) {
        let ext = p.extension().unwrap_or_default().to_string_lossy().to_lowercase();
        let magic: &[u8] = match ext.as_str() {
            "jpg" | "jpeg" => b"\xff\xd8\xff",
            "png" => b"\x89PNG\r\n\x1a\n",
            "mp3" => b"ID3",
            "pdf" => b"%PDF-1.4\n",
            _ => b"",
        };
        fs::write(p, [magic, c.as_bytes()].concat()).unwrap();
    }

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
            put(&src.join(f), c);
        }
        fs::write(src.join("Pics/fake.jpg"), "MZ\x00\x00this is a program").unwrap();

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
        assert!(!dst.join("Pics/fake.jpg").exists());
        for f in ["_blocked.xlsx", "_blocked.pdf"] {
            let r = String::from_utf8_lossy(&fs::read(dst.join(f)).unwrap()).into_owned();
            assert!(r.contains("setup.exe") && r.contains("run.bat") && !r.contains("app.exe"), "{f}");
            assert!(r.contains("fake.jpg") && r.contains("disguised"), "{f}");
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
            put(&src.join(f), c);
        }
        let abc = root.join("abc");
        fs::write(&abc, "abc").unwrap();
        assert_eq!(sha256(fs::File::open(&abc).unwrap()).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        let n = |a: &AtomicU64| a.load(Relaxed);
        let st = backup(&src, &dst, &rules(&root));
        assert_eq!((n(&st.copied), n(&st.dupes), n(&st.errors)), (3, 2, 0)); // x w sub/x
        assert!(!dst.join("y.jpg").exists() && !dst.join("z.jpg").exists());
        let sha = sha256(fs::File::open(src.join("x.jpg")).unwrap()).unwrap();
        assert_eq!(fs::read_to_string(dst.join("_duplicates.log")).unwrap(), format!("x.jpg | {sha} | y.jpg, z.jpg\n"));
        assert!(!dst.join("sub/_duplicates.log").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn game_saves_hashes_and_verify() {
        let root = env::temp_dir().join(format!("winsync-games-{}", std::process::id()));
        let (src, dst) = (root.join("src"), root.join("dst"));
        let saves = [
            "Users/bob/AppData/LocalLow/Kumi Souls Games/The Last Faith/slot0.data",
            "Users/bob/AppData/Roaming/RenPy/CollegeKings2-1622130584/persistent",
            "Program Files (x86)/Steam/userdata/42/761600/remote/file",
            "Games/Steam/userdata/42/2638890/remote/win64_save/data00.bin",
        ];
        for f in saves {
            fs::create_dir_all(src.join(f).parent().unwrap()).unwrap();
            fs::write(src.join(f), f).unwrap();
        }
        fs::create_dir_all(src.join("Users/bob/AppData/LocalLow/Kumi Souls Games/The Last Faith/empty")).unwrap();
        fs::write(src.join("Users/bob/AppData/LocalLow/Kumi Souls Games/The Last Faith/x.exe"), "MZ").unwrap();
        fs::create_dir_all(src.join("Pics")).unwrap();
        put(&src.join("Pics/a.jpg"), "a");

        let n = |a: &AtomicU64| a.load(Relaxed);
        let st = backup(&src, &dst, &rules(&src));
        assert_eq!((n(&st.copied), n(&st.errors)), (5, 0));
        for f in saves {
            assert_eq!(fs::read_to_string(dst.join(f)).unwrap(), f); // same layout, any file type
        }
        assert!(dst.join("Users/bob/AppData/LocalLow/Kumi Souls Games/The Last Faith/empty").is_dir());
        assert!(!dst.join("Users/bob/AppData/LocalLow/Kumi Souls Games/The Last Faith/x.exe").exists());
        let x = String::from_utf8_lossy(&fs::read(dst.join("_folders.xlsx")).unwrap()).into_owned();
        assert!(x.contains("The Last Faith") && x.contains("College Kings 2") && x.contains("Onimusha: Way of the Sword"));
        // folder hash of Pics = sha256("a.jpg\t<sha of a>\n")
        let line = format!("a.jpg\t{}\n", sha256(fs::File::open(src.join("Pics/a.jpg")).unwrap()).unwrap());
        assert!(x.contains(&sha256(line.as_bytes()).unwrap()));

        assert_eq!(verify(&dst), 0);
        let st = backup(&src, &dst, &rules(&src)); // unchanged: hashes come from the cache
        assert_eq!((n(&st.copied), n(&st.unchanged)), (0, 5));
        fs::write(dst.join("Pics/a.jpg"), "X").unwrap(); // bit rot on the backup disk
        assert_eq!(verify(&dst), 1);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn progress_bar() {
        let st = Stats::default();
        st.seen.store(50 << 20, Relaxed);
        let p = st.progress(100 << 20, Instant::now() - Duration::from_secs(60));
        assert!(p.contains("[##########----------]  50.0%  50/100 MB  ETA 1m00s"), "{p}");
        assert!(Stats::default().progress(0, Instant::now()).contains("100.0%"));
        assert_eq!((hms(59), hms(3900)), ("0m59s".into(), "1h05m".into()));
        if utc_offset().is_none() {
            assert_eq!(clock_at(UNIX_EPOCH + Duration::from_secs(1_709_210_096)), "29 Feb 2024, 12:34:56 PM UTC");
            assert_eq!(clock_at(UNIX_EPOCH), "1 Jan 1970, 12:00:00 AM UTC");
        }
        let d = env::temp_dir().join(format!("winsync-est-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        assert!(estimate(&d, 1000, 1 << 30, 2).unwrap() > Duration::ZERO);
        assert_eq!(fs::read_dir(&d).unwrap().count(), 0, "speed test cleans up");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn globs() {
        let g = |p, n: &str| glob(p, OsStr::new(n));
        assert!(g("*college*kings*2*", "CollegeKings2-1622130584") && g("*college*kings*2*", "College Kings 2"));
        assert!(!g("*college*kings*2*", "CollegeKings-1") && g("*.EXE", "a.exe") && g("*", "x") && !g("ab", "abc"));
    }

    #[test]
    fn drive_arg_becomes_root() {
        assert!(report::is_exec(Path::new("x/evil.JS")) && !report::is_exec(Path::new("slot0.data")));
        assert_eq!(root("C:"), PathBuf::from("C:\\"));
        assert_eq!(root("D:\\Photos"), PathBuf::from("D:\\Photos"));
        assert_eq!(dest("C:", "F:"), PathBuf::from("F:\\").join("C"));
        assert_eq!(dest("d:", "F:\\"), PathBuf::from("F:\\").join("D"));
        assert_eq!(dest("C:", "H:\\C_Backup"), PathBuf::from("H:\\C_Backup"));
    }
}
