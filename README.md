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
- Game saves listed in `games.txt` (Onimusha, College Kings 2, The Last Faith) are copied in full,
  any file type, to the same path on the backup.
- `_folders.xlsx`: one row per backed-up folder with its location, file count, size and a
  folder SHA-256 (hash of the sorted `name<TAB>file-sha256` lines of the files in it).
  Per-file hashes are kept in `_hashes.tsv`.
- `windowsyncutility.exe --verify F:\C` re-reads every backed-up file and reports any that
  are missing or changed (e.g. a failing disk).

Download the exe from [Releases](../../releases), or build: `cargo build --release`.

## If the PC may be infected

Treat the backup as untrusted: PDFs and other "harmless" files can still carry malware, so scan
the backup before opening anything from it on a clean machine.

Better: don't boot the infected Windows at all. Boot a Linux live USB (e.g. Ubuntu) so the malware
isn't running while you copy, mount the Windows drive **read-only**, and run the Linux build:

```
lsblk -f                                  # find the Windows NTFS partition, e.g. nvme0n1p3
sudo mkdir -p /mnt/c
sudo mount -o ro /dev/nvme0n1p3 /mnt/c    # read-only: nothing on C: can change
chmod +x windowsyncutility-linux-x86_64
sudo ./windowsyncutility-linux-x86_64 /mnt/c /media/ubuntu/BACKUPDISK   # -> BACKUPDISK/C/...
```

- BitLocker drive: unlock it first with your recovery key
  (`sudo cryptsetup open --type bitlk /dev/nvme0n1p3 win`, then mount `/dev/mapper/win`).
- Mount a second drive at `/mnt/d` to get a `D` folder, just like `D:` on Windows.
