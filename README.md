# macOS Path Safety Scanner

A small GUI utility for locating files and folders whose names or filesystem
properties may cause trouble when copying, syncing, archiving, uploading, or
moving data between macOS, Windows, Linux, NAS/SMB shares, cloud services, and scripts.

## What it flags

### Critical
- filename containing invalid/non-UTF-8 filesystem bytes
- filename that cannot be represented as strict UTF-8
- control characters or newlines in filenames
- Windows-reserved names such as `CON`, `NUL`, `COM1`
- names ending in a space or dot
- unreadable files/directories
- files that cannot actually be opened
- broken symlinks
- directory enumeration errors

### Warning
- characters known to be problematic on Windows/SMB: `< > : " \ | ? *`
- leading/trailing spaces
- invisible Unicode characters
- unusually long path components
- unusually long full paths
- special filesystem objects

### Info
- decomposed / non-NFC Unicode filenames
- shell-sensitive characters such as `$`, `&`, `;`, `'`, `"`, `*`, `?`

The Unicode checks are especially useful on macOS because filenames containing
accented characters can be stored in decomposed form. Such files are legal on
macOS but can occasionally behave differently on Linux, Windows, NAS devices,
ZIP tools, scripts, or web applications.

## Run

Use the launcher so the project virtual environment is created or reused and
the scanner runs with a Tk-enabled Python interpreter:

```bash
./run.command
```

The launcher prefers `uv` to create `.venv` with Python 3.12 and checks that
`tkinter` is available before starting the GUI.

Then:

1. Click **Choose…**
2. Select a folder.
3. Click **Scan**.
4. Inspect the flagged paths and reasons.
5. Double-click a row, or click **Reveal in Finder**.
6. Use **Export CSV…** to save the list.

## Optional: make a standalone `.app`

Install PyInstaller:

```bash
python3 -m pip install --user pyinstaller
```

Build:

```bash
python3 -m PyInstaller \
  --windowed \
  --name "Path Safety Scanner" \
  --osx-bundle-identifier "com.focsd.pathsafetyscanner" \
  path_safety_scanner.py
```

The app will be created in:

```text
dist/Path Safety Scanner.app
```

## Important distinction

This utility does **not** assume that every flagged filename is broken.

For example:

- decomposed Unicode is normal on macOS;
- shell-sensitive characters are legal;
- long paths can work perfectly on APFS.

The program marks them because they are common interoperability risks when data
is copied to another filesystem or consumed by software that has stricter path handling.

## Future additions

Useful next steps would be:

- a **Safe / Avoid** classification mode
- check destination rules for:
  - Windows
  - SMB/NAS
  - FAT32/exFAT
  - ZIP/archive
  - web upload
  - shell scripts
- detect Unicode-normalization collisions
- detect case-insensitive collisions (`Photo.jpg` vs `photo.jpg`)
- suggest safe renamed filenames
- batch rename with dry-run and undo manifest
- drag-and-drop folder support
