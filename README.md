# windowsyncutility

Incremental, multi-threaded backup of one Windows drive to another. Copies only photos
(`.jpg .png .tiff .heic .webp .gif .bmp` and camera RAW), `.mp4 .mp3 .txt .pdf`; never copies executables, installers, cracks, archives,
macro Office files, AppData or browser profiles (see `ignore.txt`).

```
windowsyncutility.exe C: F:     # -> F:\C\...
windowsyncutility.exe C: H:\C_Backup   # -> H:\C_Backup\... (a folder is used as-is)
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
- `windowsyncutility.exe --verify F:\C` re-reads every backed-up file and reports any that
  are missing or changed (e.g. a failing disk).

Download the exe from [Releases](../../releases), or build: `cargo build --release`.
