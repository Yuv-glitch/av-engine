import os
import shutil
import json
import hashlib
from datetime import datetime
from pathlib import Path

QUARANTINE_DIR = "quarantine"
QUARANTINE_LOG = "quarantine/quarantine_log.json"


def load_quarantine_log():
    if os.path.exists(QUARANTINE_LOG):
        with open(QUARANTINE_LOG, "r") as f:
            return json.load(f)
    return []


def save_quarantine_log(log):
    with open(QUARANTINE_LOG, "w") as f:
        json.dump(log, f, indent=2)


def quarantine_file(filepath, match_result):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)

    filepath = os.path.abspath(filepath)

    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return False

    # build a safe destination name using timestamp + original filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    original_name = os.path.basename(filepath)
    dest_name = f"{timestamp}__{original_name}"
    dest_path = os.path.join(QUARANTINE_DIR, dest_name)

    try:
        shutil.move(filepath, dest_path)
        os.chmod(dest_path, 0o000)  # strip all permissions
        print(f"[!] Quarantined: {filepath} -> {dest_path}")
    except PermissionError as e:
        print(f"[-] Permission error during quarantine: {e}")
        return False
    except Exception as e:
        print(f"[-] Failed to quarantine {filepath}: {e}")
        return False

    # log the quarantine entry
    log = load_quarantine_log()
    entry = {
        "original_path": filepath,
        "quarantine_path": dest_path,
        "timestamp": datetime.now().isoformat(),
        "sha256": match_result.get("sha256"),
        "matched_rules": [m["rules"] for m in match_result.get("matches", [])],
        "severity": [m["severity"] for m in match_result.get("matches", [])]
    }
    log.append(entry)
    save_quarantine_log(log)

    return True


def list_quarantined():
    log = load_quarantine_log()
    if not log:
        print("[*] Quarantine is empty.")
        return

    print(f"\n{'#':<4} {'Original Path':<40} {'Rules':<30} {'Timestamp'}")
    print("-" * 100)
    for i, entry in enumerate(log, 1):
        rules = ", ".join(entry.get("matched_rules", []))
        print(f"{i:<4} {entry['original_path']:<40} {rules:<30} {entry['timestamp']}")


def restore_file(index):
    log = load_quarantine_log()

    if index < 1 or index > len(log):
        print(f"[-] Invalid index: {index}")
        return False

    entry = log[index - 1]
    src = entry["quarantine_path"]
    dst = entry["original_path"]

    if not os.path.exists(src):
        print(f"[-] Quarantined file missing: {src}")
        return False

    try:
        os.chmod(src, 0o644)  # restore permissions before moving
        shutil.move(src, dst)
        print(f"[+] Restored: {src} -> {dst}")
        log.pop(index - 1)
        save_quarantine_log(log)
        return True
    except Exception as e:
        print(f"[-] Restore failed: {e}")
        return False
