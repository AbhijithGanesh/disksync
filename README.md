# disksync

Incremental backup of a Windows drive (below), plus a **restore** mode: bring a backup made on an infected PC onto a
clean PC without trusting it.

```
disksync.exe --restore F:\C D:\Restored
```

Every step fails closed: a file not proven clean is **held back, never deleted**: the original
stays on the backup disk.

1. **Backup disk must be read-only**, so nothing on the new PC (Defender's auto-delete included)
   can change or remove the originals. If it isn't, the tool stops and prints the `diskpart`
   steps (`attributes volume set readonly`). `--writable-ok` skips this check.
2. **Allowlist**: only what the backup itself copies (photos, mp4, mp3, txt, pdf, game saves
   without programs). Anything else found on the backup is held.
3. **SHA-256** of every file must match the backup's `_hashes.tsv`: altered or added files are held.
4. **Content checks** (`src/safety.rs`) again: disguised programs, PDFs with scripts etc.
5. Copies land in `D:\Restored\_restore_quarantine`, where execute is denied to everyone.
6. **Windows Defender** scans the quarantine in report-only mode
   (`MpCmdRun -Scan -ScanType 3 -DisableRemediation`, definitions updated first if online).
   Any scan failure, or a threat it can't pin to a file, holds **everything**.
7. Clean files move to `D:\Restored\...` (same layout) and are tagged "downloaded from the
   internet", so Office/PDF readers open them in Protected View. Existing files are never
   overwritten; re-running skips files already restored.

Held files: `D:\Restored\_held\_held.xlsx` / `.pdf` / `.txt` (backup path + reason).
If any, `_held\inspect.wsb` opens them in **Windows Sandbox**: a throwaway Windows with the backup
and the list mapped read-only, no network, no clipboard. Close the window and it's wiped.
Windows Sandbox needs Windows Pro/Enterprise, enabled once in an admin PowerShell (then restart):
`Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM`.

Notes: restored files keep the quarantine's "no execute" permission (harmless for photos, media,
documents and game saves). Mark-of-the-Web needs an NTFS destination; elsewhere a warning is printed.

---

## Backup mode

Incremental, multi-threaded backup of one Windows drive to another. Copies only photos
(`.jpg .png .tiff .heic .webp .gif .bmp` and camera RAW), `.mp4 .mp3 .txt .pdf`; never copies executables, installers, cracks, archives,
macro Office files, AppData or browser profiles (see `ignore.txt`).

```
disksync.exe C: F:     # -> F:\C\...
disksync.exe C: H:\C_Backup   # -> H:\C_Backup\... (a folder is used as-is)
```

- Only new/changed files are copied; deletions are never propagated.
- After the scan it prints a rough total ETA (from a quick backup-disk speed test), then a
  progress bar with live ETA every 5 s, timestamped in local time.
- Identical files in one folder are copied once (`_duplicates.log`).
- Every file's contents are checked before copying (fail closed). Blocked, with the reason, in
  `_blocked.xlsx` / `_blocked.pdf`:
  - executables and scripts found on the drive;
  - files whose contents don't match their extension (e.g. a program renamed `.jpg`);
  - PDFs with JavaScript, launch actions, attachments, XFA forms or submit/import actions,
    including ones hidden in compressed object streams; encrypted or uninspectable PDFs.
- Still: treat the backup as untrusted and scan it before opening files on a clean PC.
- Game saves listed in `games.txt` (Onimusha, College Kings 2, The Last Faith) are copied in full,
  any file type, to the same path on the backup.
- `_folders.xlsx`: one row per backed-up folder with its location, file count, size and a
  folder SHA-256 (hash of the sorted `name<TAB>file-sha256` lines of the files in it).
  Per-file hashes are kept in `_hashes.tsv`.
- `disksync.exe --verify F:\C` re-reads every backed-up file and reports any that
  are missing or changed (e.g. a failing disk).

Build: `cargo build --release` (Windows; GitHub Actions builds the .exe on push).
