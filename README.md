# OrphanGuard

Some Windows applications sneakily (or lazily) leave processes behind after their parent app has been closed. Consequences range from mild annoyance (memory bloat) to actual workflow problems (Citrix leaves processes behind that interferes with subsequent connection attempts).

This utility makes it easy to detect and clean them up, working directly from your system tray.

## Features

- **System tray** monitoring with configurable scan interval
- **Three detection modes**:
  - **Window** — app is "running" only while it has a visible window
  - **Process** — app is "running" while its indicator process exists
  - **Blocklist** — processes are always unwanted (bloatware cleanup)
- **Auto-kill** option per profile for hands-free cleanup
- **Process browser** to discover and add target processes
- **Start with Windows** via registry
- Built-in profiles for Edge, Teams, Zoom, Citrix, and common Windows bloatware

## Requirements

- Windows 10/11
- Python 3.10+

## Setup

```
git clone https://github.com/michaelv2/orphan-guard.git
cd orphan-guard
```

Run `setup.bat` to create a virtual environment and install dependencies, or manually:

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
run.bat
```

Or directly:

```
pythonw orphan_guard.py
```

OrphanGuard appears in the system tray. Right-click for options:

- **View Details** — see all detected orphans
- **Kill All / Kill [Profile]** — terminate orphaned processes
- **Scan Now** — run an immediate scan
- **Settings** — manage profiles, scan interval, and auto-kill

## Configuration

A `config.json` is created automatically on first run with default profiles (all disabled). Edit it through the Settings UI or directly:

```json
{
  "scan_interval_seconds": 15,
  "profiles": [
    {
      "name": "Microsoft Edge",
      "enabled": false,
      "indicator": { "process": "msedge.exe", "mode": "window" },
      "targets": ["msedge.exe", "msedgewebview2.exe"],
      "auto_kill": false
    }
  ]
}
```

## License

MIT
