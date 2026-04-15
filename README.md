# MiniAntivirus

MiniAntivirus is a C++17 antivirus demo project with:

- recursive folder scanning with `std::filesystem`
- SHA-256 hashing with OpenSSL
- local signature matching
- a score-based heuristic engine
- console and CSV reporting
- local quarantine handling
- an interactive CLI menu
- a native Windows GUI frontend

## Build

### Linux

```bash
make
```

### Windows (MinGW)

```bat
build_windows.bat
```

This produces:

- `MiniAntivirus.exe` for console mode
- `MiniAntivirusGUI.exe` for the Windows GUI

## Usage

### Direct scan

```bash
./MiniAntivirus /path/to/folder
```

### Interactive CLI

```bash
./MiniAntivirus --interactive
```

### Windows GUI

Run `MiniAntivirusGUI.exe`, choose a folder, and start the scan from the interface.
"# MiniAntivirus-C-" 
