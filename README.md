# disksync

Get your photos, videos, music, documents and game saves back from a backup disk that was made
on an **infected PC**, without bringing the virus along.

disksync copies files from the backup onto a clean PC only after each one passes several safety
checks, including a Windows Defender scan. Anything that doesn't pass is **held back, never
deleted**: it stays on the backup disk, and you get a list of what was held and why.

---

## Restore your files, step by step

### What you need

- A **clean** Windows 10/11 PC (not the infected one).
- The **backup disk**.
- `disksync.exe`, from the [**Releases**](../../releases/latest) page.
- Enough free space on the clean PC for your files.

> ⚠️ **Don't open anything on the backup disk yourself** (no double-clicking photos or PDFs on
> it). Let disksync do the copying.

### 1. Update Windows Defender

While the PC is online: **Start → Windows Security → Virus & threat protection →
Protection updates → Check for updates**. disksync uses Defender, so fresh definitions matter.

### 2. Plug in the backup disk and find the backup folder

Open **File Explorer → This PC** and note the backup disk's **drive letter** (say `F:`).
The backup folder is the one that contains a file called `_hashes.tsv`. Usually it's named after
the old PC's drive, e.g. **`F:\C`**. Look at the folder names only; don't open any files.

### 3. Make the backup disk read-only

This guarantees nothing (not even Defender) can change or delete your originals.

1. Click **Start**, type `cmd`, right-click **Command Prompt → Run as administrator**.
2. Type these one at a time, pressing Enter after each:

   ```
   diskpart
   list volume
   ```

3. In the list, find the backup disk by its letter (**Ltr** column) and size. Note its
   **Volume ###** number. Double-check it: picking the wrong one would lock the wrong drive.
4. Then, using that number (here `5`):

   ```
   select volume 5
   attributes volume set readonly
   exit
   ```

5. Unplug the backup disk and plug it back in.

### 4. Run the restore

In the **administrator Command Prompt**, go to where you downloaded disksync and run it:

```
cd %USERPROFILE%\Downloads
disksync.exe --restore F:\C C:\Restored
```

- `F:\C` is the backup folder from step 2.
- `C:\Restored` is where your files will go. It's created if needed and must be on the clean PC.
- If it says the folder **has no `_hashes.tsv`** (the backup was stopped before it finished),
  add `--no-hashes` to the end. Every check still runs except step 3 below (the fingerprint
  check), so a file changed on the disk after the backup can't be caught.

If Windows shows **"Windows protected your PC"**, click **More info → Run anyway**. The exe
isn't code-signed.

It prints progress every few seconds. A big backup can take a while, so leave it running.
At the end you'll see something like:

```
restored 18342, already there 0, held back 12
```

Your files are now in `C:\Restored`, in the same folders as on the old PC. 🎉

### 5. Check what was held back (if anything)

If anything was held back, disksync writes a list to **`C:\Restored\_held\`**:

| File | What it is |
|---|---|
| `_held.xlsx` / `_held.pdf` | every held file: where it is on the backup and **why** it was held |
| `_held.txt` | the same list as plain text |
| `inspect.wsb` | opens the held files in a throwaway, isolated Windows (see below) |

Common reasons:

| Reason | Meaning |
|---|---|
| `Defender: <name>` | Defender thinks it's malware. Leave it. |
| `content changed since the backup` | The file on the disk isn't what was backed up (tampering or a failing disk). |
| `not in _hashes.tsv` | The file was added to the disk after the backup. Suspicious. |
| `disguised: … is really a Windows program` | A program pretending to be a photo or document. |
| `PDF has JavaScript …` | A PDF that can run code. |
| `a different file already exists at the destination` | Something is already in `C:\Restored` with that name. Nothing was overwritten. |
| `Defender scan failed` | **Everything** was held, to be safe. Make sure Windows Security is on, then run again. |

**Looking at held files safely:** double-click `C:\Restored\_held\inspect.wsb`. It opens
**Windows Sandbox**, a disposable Windows with no internet that can only *read* the backup
(at `C:\Backup` inside it). Close the window and everything in it is wiped.
Sandbox needs Windows **Pro** or **Enterprise**. To switch it on once, run this in an
*administrator PowerShell*, then restart:

```
Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
```

Don't copy held files out of the sandbox or off the backup unless you're sure they're fine.

### 6. Afterwards

- Running the restore again is safe: files already restored are skipped, and nothing is ever
  overwritten.
- **Keep the backup disk** as it is until you've checked your restored files.
- To make the backup disk writable again later, repeat step 3 with
  `attributes volume clear readonly`.

---

## How it keeps you safe

Each file has to pass every check. If any check fails, or can't run, the file is held back.

1. **Read-only backup disk:** the tool refuses to start otherwise (`--writable-ok` overrides).
2. **Only expected file types:** photos, videos, music, text, PDFs, game saves. No programs.
3. **Fingerprint check:** each file's SHA-256 must match the one recorded at backup time.
4. **Content check:** the file must really be what its extension says; risky PDFs are blocked.
5. **Quarantine:** copies first land in a folder where nothing is allowed to run.
6. **Windows Defender scan** of the quarantine, report-only, so Defender never deletes anything.
7. **Release:** clean files move into place, tagged "downloaded from the internet", so
   Word, Excel and PDF readers open them in Protected View.

Notes: restored files keep a "can't be run" permission (harmless for photos, media, documents
and game saves). The Protected View tag needs an NTFS drive (normal Windows drives are).

---

## Backup mode

Incremental, multi-threaded backup of one Windows drive to another. Copies only photos
(`.jpg .png .tiff .heic .webp .gif .bmp` and camera RAW), `.mp4 .mp3 .txt .pdf`; never copies
executables, installers, cracks, archives, macro Office files, AppData or browser profiles
(see `ignore.txt`).

```
disksync.exe C: F:            # -> F:\C\...
disksync.exe C: H:\C_Backup   # -> H:\C_Backup\... (a folder is used as-is)
disksync.exe --verify F:\C    # re-read every backed-up file, report missing/changed ones
```

- Only new/changed files are copied; deletions are never propagated.
- Rough upfront ETA, then a live progress bar every 5 s.
- Identical files in one folder are copied once (`_duplicates.log`).
- Contents checked before copying (fail closed); blocked files, with reasons, in
  `_blocked.xlsx` / `_blocked.pdf`: executables, disguised files, PDFs with active content.
- Game saves listed in `games.txt` are copied in full (no programs) to the same path.
- `_folders.xlsx`: per-folder file count, size and SHA-256; per-file hashes in `_hashes.tsv`.

## Building

`cargo build --release` on Windows (no dependencies). GitHub Actions builds and tests
`disksync.exe` on every push; pushing a tag like `v0.1.0` publishes it to Releases.
