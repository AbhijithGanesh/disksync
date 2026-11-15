# windowsyncutility

Incremental, multi-threaded backup of one Windows drive to another. Copies only
`.jpg .jpeg .png .mp4 .mp3 .txt .pdf`; never copies executables, installers, cracks, archives,
macro Office files, AppData or browser profiles (see `ignore.txt`).

```
windowsyncutility.exe C: F:     # -> F:\C\...
```

- Only new/changed files are copied; deletions are never propagated.
- Identical files in one folder are copied once (`_duplicates.log`).
- Executables found are listed in `_executables.xlsx` and `_executables.pdf` on the backup.

Download the exe from [Releases](../../releases), or build: `cargo build --release`.
