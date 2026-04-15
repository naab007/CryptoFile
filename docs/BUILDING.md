# CryptoFile — Building from source

## Requirements

- **Python 3.11+** (3.12 tested).
- **Windows 10 or 11** for shell integration + the PyInstaller exe target.
  The core crypto + expansion modules run on macOS and Linux too (tests
  pass); only `shell_integration.py` and the batch coordinator's
  Windows-specific locking path require Windows.

## Dev setup

From the project root (`D:\App Dev\CryptoFile` on the reference machine):

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -e ".[dev]"
```

This installs:

- `cryptography >= 42.0.0` — AES-GCM primitive.
- `argon2-cffi >= 23.1.0` — Argon2id KDF.
- `pytest >= 8.0` — tests.
- `pyinstaller >= 6.0` — producing the single-file exe.

## Running tests

```powershell
.venv\Scripts\python -m pytest
```

Expected: **47 passed, 2 skipped** on Windows. The two skipped tests
exercise POSIX symlink creation — they require admin on Windows, so the
tests mark themselves skipped automatically via
`@pytest.mark.skipif(sys.platform == "win32", …)`. On macOS or Linux
they run and pass.

For faster iteration:

```powershell
.venv\Scripts\python -m pytest tests/test_crypto.py -x -q
```

The suite uses a deliberately-cheap Argon2id configuration
(`memory_kib=8`, `time_cost=1`, `parallelism=1`) in test fixtures so
round-trips take ~5 ms instead of ~1 second. Never ship these test
parameters — the header cost fields are what matter for real-world
security, and those come from `cryptofile.crypto.ARGON2_*` defaults.

## Running from source (no build)

```powershell
.venv\Scripts\python -m cryptofile                    # Settings window
.venv\Scripts\python -m cryptofile encrypt path\to\file
.venv\Scripts\python -m cryptofile decrypt path\to\file.lock
```

Shell integration in dev mode: the `install()` helper detects that we're
running from source (not a frozen exe) and writes a registry command
that uses `pythonw.exe` + a path to `__main__.py`. This lets you test
the full right-click flow without rebuilding.

## Producing the release exe

```powershell
.venv\Scripts\python build_exe.py
```

Internals: `build_exe.py` calls `PyInstaller.__main__.run([...])` with:

- `--name CryptoFile`
- `--onefile` — single exe, no extra DLL files to distribute
- `--windowed` — no console window behind the tk UI
- `--clean` — fresh build environment every time
- `--hidden-import argon2.low_level`
- `--hidden-import cryptography.hazmat.primitives.ciphers.aead`
- `--specpath build/` / `--distpath dist/` / `--workpath build/work/`

Output: `dist\CryptoFile.exe` (≈ 14.3 MB as of 1.0.0).

The hidden-import flags are required because PyInstaller's static
analysis misses `argon2-cffi`'s low-level entry points and some of
`cryptography`'s AEAD imports. Removing them causes runtime
`ModuleNotFoundError` when the frozen exe tries to encrypt.

### Verifying the built exe

Before shipping, sanity-check the frozen import graph:

```powershell
.venv\Scripts\python -c "
import sys
sys.path.insert(0, '.')
import cryptofile, cryptofile.crypto, cryptofile.file_ops
import cryptofile.gui, cryptofile.shell_integration
import cryptofile.__main__, cryptofile.batch
print('imports OK')
"
```

Then run the exe once to open the Settings window, click Install →
right-click a test file → Encrypt → enter a password → confirm
success → Decrypt → confirm the bytes round-trip.

## Releasing

1. Bump `__version__` in `cryptofile/__init__.py` AND `version` in
   `pyproject.toml`.
2. Add a new section to `CHANGELOG.md` with the date.
3. Run the full test suite — must be 47/47 on Windows (2 skipped).
4. `.venv\Scripts\python build_exe.py`.
5. Smoke-test the exe (Settings opens, Install works, file round-trips).
6. Ship `dist\CryptoFile.exe`.

## Directory layout reference

```
D:\App Dev\CryptoFile\
├── cryptofile\              ← the package
│   ├── __init__.py
│   ├── __main__.py
│   ├── crypto.py
│   ├── file_ops.py
│   ├── batch.py
│   ├── gui.py
│   └── shell_integration.py
├── tests\
│   ├── test_crypto.py
│   ├── test_file_ops.py
│   ├── test_batch.py
│   └── test_expansion.py
├── docs\
│   ├── ARCHITECTURE.md
│   ├── PROTOCOL.md
│   ├── SECURITY.md
│   └── BUILDING.md          ← you are here
├── build\                   ← PyInstaller scratch (ignored)
├── dist\                    ← built exe
│   └── CryptoFile.exe
├── .venv\                   ← local venv (ignored)
├── pyproject.toml
├── build_exe.py
├── CHANGELOG.md
├── README.md
└── .gitignore
```

## Troubleshooting

- **"Module not found: argon2" at runtime** in the frozen exe → add
  `--hidden-import argon2.low_level` and rebuild.
- **Tk window flashes briefly then disappears** in dev mode → you're
  running via `python.exe` rather than `pythonw.exe`. The build path
  uses `--windowed` to avoid this for the shipped exe.
- **Secondary instance gets stuck** "sending to primary" → stale
  coordinator files under `%LOCALAPPDATA%\CryptoFile\`. The locks
  auto-release when the holding process dies; if they don't, delete
  `encrypt.lock` / `encrypt.port` / `decrypt.lock` / `decrypt.port`
  and try again. Report a bug if this happens without a crash.
- **"Wrong password or corrupted file" on a file you just encrypted**
  with the same password → the file was modified mid-transit or on a
  flaky drive. Try the original source if you still have it. A
  single-bit flip in the ciphertext is enough to fail the per-chunk
  GCM tag.
- **`is_installed()` returns False after upgrading** from 0.x → the
  folder-verb registration is new in 1.0.0. Click **Reinstall** in
  Settings once and the check will flip to True.
