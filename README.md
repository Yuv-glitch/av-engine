# av-engine 🛡️

A Python-based antivirus engine for Ubuntu LTS servers using YARA rules for signature-based malware detection, real-time filesystem monitoring, and automated quarantine.

---

## Features

- **YARA Signature Scanning** — 4 rule files covering shells, webshells, rootkits, cryptominers, and ransomware
- **Real-Time Monitoring** — inotify-based filesystem watcher using `watchdog`, auto-quarantines on detection
- **Shannon Entropy Scoring** — per-file entropy calculation to flag packed/encrypted payloads
- **Quarantine System** — safe file isolation with `chmod 000`, full restore capability, and JSON audit log
- **JSON Scan Reports** — timestamped reports saved to `logs/` for every scan run
- **CLI Interface** — single entry point for all operations via `cli.py`

---

## Project Structure

```
av-engine/
├── rules/
│   ├── base.yar          # Shells, webshells, credential harvesting, encoded payloads
│   ├── rootkits.yar      # Syscall hooking, LKM rootkits, process/network hiding
│   ├── miners.yar        # Stratum protocol, XMRig, miner droppers, config files
│   └── ransomware.yar    # File encryption, ransom notes, shadow copy deletion
├── scanner.py            # Core YARA scan engine + entropy scoring
├── monitor.py            # Real-time filesystem watcher
├── quarantine.py         # File isolation, restore, and audit log
├── cli.py                # CLI entry point
├── quarantine/           # Isolated malware (auto-created)
└── logs/                 # JSON scan reports (auto-created)
```

---

## Setup

**Requirements:** Ubuntu LTS, Python 3.10+

```bash
# Install system dependencies
sudo apt update && sudo apt install -y yara python3-pip python3-venv

# Clone and set up environment
git clone https://github.com/YOUR_USERNAME/av-engine.git
cd av-engine
python3 -m venv venv && source venv/bin/activate
pip install yara-python watchdog rich click

# Verify YARA rules load
python3 -c "from scanner import load_rules; load_rules()"
```

---

## Usage

### Scan a file
```bash
python3 cli.py scan /path/to/file
```

### Scan a directory and save report
```bash
python3 cli.py scan /var/www/html --report
```

### Scan and auto-quarantine infected files
```bash
python3 cli.py scan /home --quarantine
```

### Real-time monitor (watches /tmp and /home by default)
```bash
python3 cli.py monitor /tmp /home /var/www/html
```

### Monitor without auto-quarantine
```bash
python3 cli.py monitor /tmp --no-quarantine
```

### Quarantine management
```bash
python3 cli.py quarantine list        # list all quarantined files
python3 cli.py quarantine restore 1   # restore file by index
```

### View scan reports
```bash
python3 cli.py report --last 5
```

---

## YARA Rule Coverage

| Rule File | Rules | Detects |
|---|---|---|
| `base.yar` | 6 | Reverse shells, base64 payloads, ELF suspicious binaries, PHP webshells, Python malware, credential harvesting |
| `rootkits.yar` | 4 | Syscall hooking, process hiding, LKM rootkits, network port hiding |
| `miners.yar` | 4 | Stratum mining protocol, XMRig/cpuminer binaries, shell droppers, miner config files |
| `ransomware.yar` | 4 | File encryption routines, ransom note patterns, shadow copy deletion, mass file rename |

---

## How It Works

### Scanning
`scanner.py` loads all `.yar` files from `rules/` at startup using `yara.compile()`. Each file scan runs `rules.match()` and returns a structured result containing the file hash, matched rules, severity, and metadata.

### Entropy Scoring
Every scanned file gets a Shannon entropy score (0.0–8.0). Normal text files score around 3.0–4.0, compiled binaries around 5.5–6.5, and packed or encrypted payloads score above 7.0. This metadata is included in every scan result and report.

### Real-Time Monitor
`monitor.py` uses `watchdog` to hook into Linux inotify events. On `create`, `modify`, or `move` events, the file is immediately scanned. A debounce mechanism prevents duplicate scans from multiple rapid filesystem events on the same file. Infected files are auto-quarantined by default.

### Quarantine
`quarantine.py` moves flagged files to `quarantine/` with a timestamp-prefixed filename and strips all permissions with `chmod 000`. Every quarantine action is logged to `quarantine/quarantine_log.json` with the original path, SHA256 hash, matched rule names, and timestamp. Files can be restored by index.

---

## Sample Output

```
[*] Scanning directory: /tmp
  [!] INFECTED: /tmp/shell.sh
      Rule     : Suspicious_Shell_Commands
      Severity : high
      Desc     : Detects reverse shell and command execution patterns
  [+] Clean    : /tmp/notes.txt

[*] Scan complete. Scanned: 2 | Infected: 1 | Clean: 1
[!] Quarantined: /tmp/shell.sh -> quarantine/20260323_185020__shell.sh
[+] Report saved to: logs/scan_20260323_185020.json
```

---

## Tech Stack

- **Python 3** — core engine
- **yara-python** — YARA rule compilation and matching
- **watchdog** — inotify filesystem event monitoring
- **click** — CLI interface
- **hashlib** — SHA256 file fingerprinting

---

## Roadmap

- [ ] ML classifier layer (Random Forest on entropy + YARA features)
- [ ] systemd unit file for daemon mode
- [ ] SQLite scan cache to skip unchanged files
- [ ] Web dashboard for scan reports
- [ ] ClamAV integration as secondary scanner

---

## Disclaimer

This tool is built for educational and defensive security purposes. The YARA rules and malware samples in this repo are synthetic signatures for detection testing only. Do not run the monitor with auto-quarantine on production systems without testing first.
