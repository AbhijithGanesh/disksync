// `--restore <backup folder> <destination>`: copy a backup made on a possibly infected PC onto
// a clean one without trusting it. Every layer fails closed: a file that isn't proven clean is
// held back. Held files are never deleted: the original stays on the (read-only) backup disk.
//
//  1. backup volume must be read-only (checked in main): nothing, Defender included, can change
//     or delete the originals while we read them
//  2. allowlist: only what the backup itself would copy (KEEP, ignore.txt, game saves w/o programs)
//  3. SHA-256 must match the backup's _hashes.tsv (catches tampering / bit rot since the backup)
//  4. content checks (safety.rs) on the copy: disguised programs, PDFs with scripts, ...
//  5. copies land in a quarantine folder where nothing is allowed to execute
//  6. Windows Defender scans the quarantine, report-only (-DisableRemediation)
//  7. clean files move to the destination, tagged "downloaded from the internet" (Protected View)
//
// Held files are listed in <dest>\_held\_held.xlsx/.pdf; _held\inspect.wsb opens them from the
// backup in a throwaway Windows Sandbox (read-only, no network).

use super::{clock, game_dirs, load_hashes, rules, sha256, skip_dir, skip_file, threads, HASHES};
use crate::{report, safety};
use report::Exe;
use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering::Relaxed},
        Mutex,
    },
    thread,
    time::{Duration, UNIX_EPOCH},
};

pub const QUARANTINE: &str = "_restore_quarantine";
pub const HELD: &str = "_held";

#[cfg_attr(not(windows), allow(dead_code))] // Clean/Threats come from Defender, Windows only
pub enum Scan {
    Clean,
    Threats(Vec<(String, String)>), // (file path as Defender printed it, threat name)
    Failed(String),
}

#[derive(Default)]
pub struct Outcome {
    pub restored: u64,
    pub already: u64,
    pub held: Vec<Exe>,
}

pub fn restore(backup: &Path, dest: &Path, scan: impl Fn(&Path) -> Scan) -> io::Result<Outcome> {
    let hashes = load_hashes(backup);
    if hashes.is_empty() {
        return Err(io::Error::other(format!("no {HASHES} in {} - not a backup folder?", backup.display())));
    }
    let q = dest.join(QUARANTINE);
    let _ = fs::remove_dir_all(&q); // leftovers of an interrupted run; the originals are on the backup
    fs::create_dir_all(&q)?;
    lock_down(&q)?;

    eprintln!("{} [restore] listing {} ...", clock(), backup.display());
    let games: Vec<PathBuf> = game_dirs(backup).into_iter().map(|g| g.1).collect();
    let (mut items, mut held) = (vec![], vec![]);
    list(backup, backup, &rules(backup), &games, true, false, &mut items, &mut held);
    eprintln!("{} [restore] {} files to check, {} held already (not something the backup copies)", clock(), items.len(), held.len());

    // Layers 2-4, on every CPU (I/O-bound, so oversubscribed like the backup).
    let (next, done, already) = (AtomicU64::new(0), AtomicBool::new(false), AtomicU64::new(0));
    let (staged, held_m) = (Mutex::new(vec![]), Mutex::new(held));
    thread::scope(|s| {
        let ws: Vec<_> = (0..threads() * 2)
            .map(|_| {
                s.spawn(|| loop {
                    let Some((rel, game)) = items.get(next.fetch_add(1, Relaxed) as usize) else { break };
                    match stage(backup, dest, &q, rel, *game, &hashes) {
                        Ok(true) => staged.lock().unwrap().push(rel.clone()),
                        Ok(false) => _ = already.fetch_add(1, Relaxed),
                        Err(why) => held_m.lock().unwrap().push(held_entry(backup, rel, why)),
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
                    eprintln!("{} [restore] checked {}/{}", clock(), next.load(Relaxed).min(items.len() as u64), items.len());
                }
            }
        });
        ws.into_iter().for_each(|w| w.join().unwrap());
        done.store(true, Relaxed);
    });
    let (staged, mut held) = (staged.into_inner().unwrap(), held_m.into_inner().unwrap());

    // Layer 6. Anything we can't map back to a file means we don't know what's infected: hold all.
    eprintln!("{} [defender] scanning {} files in {} ...", clock(), staged.len(), q.display());
    let key = |p: &str| p.replace('\\', "/").to_lowercase();
    let mut threats: HashMap<String, String> = HashMap::new();
    let fail = match scan(&q) {
        Scan::Clean => None,
        Scan::Failed(why) => Some(format!("Defender scan failed: {why}")),
        Scan::Threats(t) => {
            let marker = format!("{}/", QUARANTINE.to_lowercase());
            let mut unknown = None;
            for (path, name) in t {
                match key(&path).split_once(&marker) {
                    Some((_, rel)) => _ = threats.insert(rel.to_string(), name),
                    None => unknown = Some(format!("Defender found {name} in {path}, outside the quarantine")),
                }
            }
            unknown
        }
    };
    eprintln!("{} [defender] {}", clock(), fail.as_deref().unwrap_or(&format!("{} threats", threats.len())));

    // Layer 7.
    let mut out = Outcome { already: already.into_inner(), ..Default::default() };
    for rel in staged {
        let (qp, to) = (q.join(&rel), dest.join(&rel));
        let why = if let Some(f) = &fail {
            Some(f.clone())
        } else if let Some(t) = threats.get(&key(&rel.to_string_lossy())) {
            Some(format!("Defender: {t}"))
        } else if !qp.exists() {
            Some("removed by Defender real-time protection".into())
        } else if to.exists() {
            Some("a file appeared at the destination meanwhile (not overwritten)".into())
        } else {
            None
        };
        if let Some(why) = why {
            held.push(held_entry(backup, &rel, why));
            continue;
        }
        let res = to.parent().map_or(Ok(()), fs::create_dir_all).and_then(|_| fs::rename(&qp, &to));
        match res {
            Ok(()) => {
                out.restored += 1;
                if let Err(e) = mark_downloaded(&to) {
                    eprintln!("{}: can't tag as downloaded ({e}); open with care", to.display());
                }
            }
            Err(e) => held.push(held_entry(backup, &rel, format!("move from quarantine failed: {e}"))),
        }
    }
    fs::remove_dir_all(&q)?; // only held copies are left in it

    let hd = dest.join(HELD);
    fs::create_dir_all(&hd)?;
    report::write(&hd, "_held", "Files NOT restored (held back, originals untouched on the backup)", backup, &mut held)?;
    let paths: String = held.iter().map(|e| format!("{}\t{}\r\n", e.path.display(), e.reason)).collect();
    fs::write(hd.join("_held.txt"), paths)?;
    let wsb = hd.join("inspect.wsb");
    if held.is_empty() {
        let _ = fs::remove_file(&wsb);
    } else {
        fs::write(&wsb, sandbox_config(backup, &hd))?;
    }
    out.held = held;
    Ok(out)
}

// Backup-relative paths to check, plus `held` for files that shouldn't be in a backup at all.
#[allow(clippy::too_many_arguments)]
fn list(root: &Path, dir: &Path, rules: &super::Rules, games: &[PathBuf], ok: bool, game: bool, items: &mut Vec<(PathBuf, bool)>, held: &mut Vec<Exe>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return held.push(Exe { path: dir.to_path_buf(), size: 0, modified: UNIX_EPOCH, reason: "folder can't be read".into() });
    };
    for e in rd.flatten() {
        let (path, Ok(ft)) = (e.path(), e.file_type()) else { continue };
        let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        let name = e.file_name().to_string_lossy().to_lowercase();
        if ft.is_dir() {
            let g = game || games.contains(&path);
            list(root, &path, rules, games, g || (ok && !skip_dir(&path, rules)), g, items, held);
        } else if name == "_duplicates.log" || (dir == root && (name == HASHES || name.starts_with("_blocked.") || name == "_folders.xlsx")) {
            // the backup's own reports
        } else if !ft.is_file() {
            held.push(held_entry(root, &rel, "link, not followed".into()));
        } else if game && !report::is_exec(&path) {
            items.push((rel, true));
        } else if !game && ok && !skip_file(&path, rules) {
            items.push((rel, false));
        } else {
            held.push(held_entry(root, &rel, "not a file type the backup copies (shouldn't be on it)".into()));
        }
    }
}

// Layers 3 and 4 for one file. Ok(true) = in quarantine, Ok(false) = already restored, Err = held.
fn stage(backup: &Path, dest: &Path, q: &Path, rel: &Path, game: bool, hashes: &super::Hashes) -> Result<bool, String> {
    let Some((_, _, want)) = hashes.get(rel) else {
        return Err(format!("not in {HASHES}: added or renamed after the backup"));
    };
    let to = dest.join(rel);
    if to.exists() {
        let have = fs::File::open(&to).and_then(sha256).map_err(|e| format!("destination exists, can't read it: {e}"))?;
        return if have == *want { Ok(false) } else { Err("a different file already exists at the destination (not overwritten)".into()) };
    }
    let qp = q.join(rel);
    let checked = (|| -> io::Result<Option<String>> {
        fs::create_dir_all(qp.parent().unwrap())?;
        let got = copy_hashed(&backup.join(rel), &qp)?;
        if got != *want {
            return Ok(Some("content changed since the backup (SHA-256 mismatch)".into()));
        }
        // Game saves are their own formats: they only get the no-programs rule.
        if game { Ok(None) } else { safety::risk(&qp) }
    })();
    match checked {
        Ok(None) => Ok(true),
        res => {
            let _ = fs::remove_file(&qp);
            Err(match res {
                Ok(Some(why)) => why,
                Err(e) => format!("can't be read/checked: {e}"),
                Ok(None) => unreachable!(),
            })
        }
    }
}

// Copy, hashing on the way so the backup is read once. Keeps the backup's modified time.
fn copy_hashed(from: &Path, to: &Path) -> io::Result<String> {
    struct Tee<'a>(fs::File, &'a mut fs::File);
    impl Read for Tee<'_> {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = self.0.read(b)?;
            self.1.write_all(&b[..n])?;
            Ok(n)
        }
    }
    let mut out = fs::File::create(to)?;
    let sha = sha256(Tee(fs::File::open(from)?, &mut out))?;
    drop(out);
    fs::File::options().write(true).open(to)?.set_modified(fs::metadata(from)?.modified()?)?;
    Ok(sha)
}

fn held_entry(backup: &Path, rel: &Path, reason: String) -> Exe {
    let path = backup.join(rel);
    let m = fs::symlink_metadata(&path).ok();
    Exe { size: m.as_ref().map_or(0, |m| m.len()), modified: m.and_then(|m| m.modified().ok()).unwrap_or(UNIX_EPOCH), path, reason }
}

// Windows Sandbox config: the backup and the held list, both read-only, no network/clipboard.
fn sandbox_config(backup: &Path, held: &Path) -> String {
    let e = |p: &Path| report::xml_esc(&p.display().to_string());
    format!(
        "<Configuration>\n  <Networking>Disable</Networking>\n  <ClipboardRedirection>Disable</ClipboardRedirection>\n  \
         <PrinterRedirection>Disable</PrinterRedirection>\n  <AudioInput>Disable</AudioInput>\n  <VideoInput>Disable</VideoInput>\n  \
         <ProtectedClient>Enable</ProtectedClient>\n  <MappedFolders>\n    \
         <MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\\Backup</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>\n    \
         <MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\\Held</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>\n  \
         </MappedFolders>\n  <LogonCommand><Command>notepad.exe C:\\Held\\_held.txt</Command></LogonCommand>\n</Configuration>\n",
        e(backup),
        e(held)
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
// MpCmdRun exit codes: 0 = clean, 2 = threats (listed with -DisableRemediation), else failure.
pub fn parse_defender(code: Option<i32>, out: &str) -> Scan {
    match code {
        Some(0) => return Scan::Clean,
        Some(2) => {}
        c => return Scan::Failed(format!("MpCmdRun exit code {c:?}: {}", out.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim())),
    }
    let (mut threat, mut found) = (String::from("threat"), vec![]);
    for l in out.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        match k.trim().to_lowercase().as_str() {
            "threat" => threat = v.trim().to_string(),
            "file" => found.push((v.trim().split("->").next().unwrap().to_string(), threat.clone())),
            _ => {}
        }
    }
    if found.is_empty() { Scan::Failed("Defender found threats but didn't list the files".into()) } else { Scan::Threats(found) }
}

#[cfg(windows)]
pub fn defender(dir: &Path) -> Scan {
    use std::process::Command;
    let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
    let exe = Path::new(&pf).join("Windows Defender").join("MpCmdRun.exe");
    // Best effort: an offline PC scans with the definitions it has.
    match Command::new(&exe).arg("-SignatureUpdate").output() {
        Ok(o) if o.status.success() => eprintln!("[defender] definitions updated"),
        _ => eprintln!("[defender] couldn't update definitions (offline?); scanning with the installed ones"),
    }
    match Command::new(&exe).args(["-Scan", "-ScanType", "3", "-File"]).arg(dir).arg("-DisableRemediation").output() {
        Ok(o) => parse_defender(o.status.code(), &String::from_utf8_lossy(&o.stdout)),
        Err(e) => Scan::Failed(format!("can't run {}: {e}", exe.display())),
    }
}

#[cfg(not(windows))]
pub fn defender(_: &Path) -> Scan {
    Scan::Failed("Windows Defender only exists on Windows".into())
}

// Deny execute to Everyone on every file that lands in the quarantine.
#[cfg(windows)]
fn lock_down(q: &Path) -> io::Result<()> {
    let st = std::process::Command::new("icacls").arg(q).args(["/deny", "*S-1-1-0:(OI)(IO)(X)"]).output()?;
    if st.status.success() { Ok(()) } else { Err(io::Error::other(format!("icacls failed: {}", String::from_utf8_lossy(&st.stdout)))) }
}

#[cfg(not(windows))]
fn lock_down(_: &Path) -> io::Result<()> {
    Ok(()) // ponytail: dev/tests only; the real tool runs on Windows
}

// Mark of the Web: Office/PDF readers then open the file in Protected View. NTFS only.
#[cfg(windows)]
fn mark_downloaded(p: &Path) -> io::Result<()> {
    let mut ads = p.as_os_str().to_owned();
    ads.push(":Zone.Identifier");
    fs::write(ads, "[ZoneTransfer]\r\nZoneId=3\r\n")
}

#[cfg(not(windows))]
fn mark_downloaded(_: &Path) -> io::Result<()> {
    Ok(())
}

// Volume flag FILE_READ_ONLY_VOLUME of the drive `p` is on. None if it can't be told (UNC, error).
#[cfg(windows)]
pub fn read_only_volume(p: &Path) -> Option<bool> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetVolumeInformationW(root: *const u16, name: *mut u16, name_len: u32, serial: *mut u32, max_comp: *mut u32, flags: *mut u32, fs: *mut u16, fs_len: u32) -> i32;
    }
    let s = p.to_str()?;
    (s.len() >= 2 && s.as_bytes()[1] == b':').then_some(())?;
    let root: Vec<u16> = std::ffi::OsStr::new(&format!("{}:\\", &s[..1])).encode_wide().chain([0]).collect();
    let (mut flags, null): (u32, *mut u16) = (0, std::ptr::null_mut());
    let ok = unsafe { GetVolumeInformationW(root.as_ptr(), null, 0, null.cast(), null.cast(), &mut flags, null, 0) };
    (ok != 0).then_some(flags & 0x0008_0000 != 0)
}

#[cfg(not(windows))]
pub fn read_only_volume(_: &Path) -> Option<bool> {
    None
}

// Open inspect.wsb in Windows Sandbox, or say how to turn it on.
pub fn open_sandbox(wsb: &Path) {
    let sys = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    let exe = Path::new(&sys).join("System32").join("WindowsSandbox.exe");
    if cfg!(windows) && exe.exists() {
        match std::process::Command::new(&exe).arg(wsb).spawn() {
            Ok(_) => eprintln!("[sandbox] opened {} (close the window to wipe it)", wsb.display()),
            Err(e) => eprintln!("[sandbox] can't start: {e}; double-click {}", wsb.display()),
        }
    } else {
        eprintln!("[sandbox] Windows Sandbox isn't enabled (needs Windows Pro/Enterprise). To turn it on, in an admin PowerShell:");
        eprintln!("          Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM   (then restart)");
        eprintln!("          then double-click {}", wsb.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restores_only_proven_clean_files() {
        let root = std::env::temp_dir().join(format!("winsync-restore-{}", std::process::id()));
        let (src, bk, dest) = (root.join("src"), root.join("bk"), root.join("dest"));
        fs::create_dir_all(src.join("Pics")).unwrap();
        for (f, c) in [("Pics/a.jpg", "a"), ("Pics/b.jpg", "b"), ("Pics/c.jpg", "c"), ("Pics/doc.pdf", "d")] {
            let magic: &[u8] = if f.ends_with("pdf") { b"%PDF-1.4\n" } else { b"\xff\xd8\xff" };
            fs::write(src.join(f), [magic, c.as_bytes()].concat()).unwrap();
        }
        let save = "Users/bob/AppData/LocalLow/Kumi Souls Games/The Last Faith/slot0.data";
        fs::create_dir_all(src.join(save).parent().unwrap()).unwrap();
        fs::write(src.join(save), "save").unwrap();
        super::super::backup(&src, &bk, &rules(&src));
        let originals: Vec<_> = ["Pics/a.jpg", "Pics/b.jpg", "Pics/c.jpg"].map(|f| fs::read(bk.join(f)).unwrap()).into();

        // after the backup: one file altered, one added, one sneaked-in program
        fs::write(bk.join("Pics/c.jpg"), b"\xff\xd8\xffEVIL").unwrap();
        fs::write(bk.join("Pics/new.jpg"), b"\xff\xd8\xffnew").unwrap();
        fs::write(bk.join("Pics/run.exe"), "MZ").unwrap();
        let fake_defender = |q: &Path| Scan::Threats(vec![(q.join("Pics/b.jpg").display().to_string(), "EICAR".into())]);

        let out = restore(&bk, &dest, fake_defender).unwrap();
        assert_eq!(out.restored, 3, "a.jpg, doc.pdf, the game save");
        assert_eq!(fs::read(dest.join("Pics/a.jpg")).unwrap(), originals[0]);
        assert_eq!(fs::read_to_string(dest.join(save)).unwrap(), "save");
        for f in ["Pics/b.jpg", "Pics/c.jpg", "Pics/new.jpg", "Pics/run.exe"] {
            assert!(!dest.join(f).exists(), "{f} must be held");
            assert!(bk.join(f).exists(), "{f}: original never deleted");
        }
        assert_eq!(fs::read(bk.join("Pics/b.jpg")).unwrap(), originals[1]);
        assert!(!dest.join(QUARANTINE).exists());
        let txt = fs::read_to_string(dest.join(HELD).join("_held.txt")).unwrap();
        for why in ["Defender: EICAR", "SHA-256 mismatch", "not in _hashes.tsv", "not a file type"] {
            assert!(txt.contains(why), "{why} in {txt}");
        }
        let wsb = fs::read_to_string(dest.join(HELD).join("inspect.wsb")).unwrap();
        assert!(wsb.contains(&bk.display().to_string()) && wsb.contains("<ReadOnly>true</ReadOnly>") && wsb.contains("<Networking>Disable"));

        // Re-run: done files are recognised, nothing overwritten. A scan failure releases nothing.
        let out = restore(&bk, &dest, |_: &Path| Scan::Failed("boom".into())).unwrap();
        assert_eq!((out.restored, out.already), (0, 3));
        let out = restore(&bk, &root.join("dest2"), |_: &Path| Scan::Failed("boom".into())).unwrap();
        assert_eq!(out.restored, 0);
        assert!(fs::read_dir(root.join("dest2")).unwrap().all(|e| e.unwrap().file_name() == HELD));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_defender_output() {
        let out = "Scan starting...\nScan finished.\nScanning D:\\R\\_restore_quarantine found 1 threats.\n\n\
                   Threat                  : Virus:DOS/EICAR_Test_File\nResources               : 1 total\n    \
                   file                : D:\\R\\_restore_quarantine\\Pics\\b.jpg\n";
        let Scan::Threats(t) = parse_defender(Some(2), out) else { panic!() };
        assert_eq!(t, vec![("D:\\R\\_restore_quarantine\\Pics\\b.jpg".into(), "Virus:DOS/EICAR_Test_File".into())]);
        assert!(matches!(parse_defender(Some(0), ""), Scan::Clean));
        assert!(matches!(parse_defender(Some(2), "found 1 threats"), Scan::Failed(_)), "threats without files: fail closed");
        assert!(matches!(parse_defender(Some(1), "error"), Scan::Failed(_)));
        assert!(matches!(parse_defender(None, ""), Scan::Failed(_)));
    }
}
