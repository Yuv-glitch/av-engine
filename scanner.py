import math
from collections import Counter
import os
import yara
import hashlib
import json
from datetime import datetime
from pathlib import Path


RULES_DIR = "rules"
QUARANTINE_DIR = "quarantine"
LOGS_DIR = "logs"

def calculate_entropy(filepath):
	try:
		with open(filepath, "rb") as f:
			data = f.read()
		if not data:
			return 0.0

		byte_counts = Counter(data)
		total = len(data)
		entropy = 0.0

		for count in byte_counts.values():
			p = count /total
			entropy -= p * math.log2(p)
		
		return round(entropy, 4)
	except Exception:
		return None


def get_file_metadata(filepath):
	try:
		stat = os.stat(filepath)
		return {
			"size_bytes": stat.st_size,
			"extension": os.path.splitext(filepath)[1].lower(),
			"is_executable": os.access(filepath, os.X_OK),
			"entropy": calculate_entropy(filepath)
		}


	except Exception as e:
		print(f"[DEBUG] get_file_metadata error: {e}")
		return {}

def load_rules():
	rule_files = {}
	for f in Path(RULES_DIR).glob("*.yar"):
		rule_files[f.stem] = str(f)
	
	if not rule_files:
		raise FileNotFoundError("No .yar files found in rules/")
	
	rules = yara.compile(filepaths=rule_files)
	print(f"[+] Loaded {len(rule_files)} rule file(s): {list(rule_files.keys())}")
	return rules

def get_file_hash(filepath):
	sha256 = hashlib.sha256()
	try:
		with open(filepath, "rb") as f:
			for chunk in iter(lambda: f.read(8192), b""):
				sha256.update(chunk)
		return sha256.hexdigest()
	except Exception:
		return None

def scan_file(filepath, rules):
	result = {
		"file": str(filepath),
		"timestamp": datetime.now().isoformat(),
		"sha256": get_file_hash(filepath),
		"matches": [],
		"status": "clean",
		"metadata": get_file_metadata(filepath)
	}
	try: 
		matches = rules.match(str(filepath), timeout=10)
		if matches:
			result["status"] = "infected"
			result["matches"] = [
				{
				  "rules": m.rule,
				  "severity": m.meta.get("severity", "unknown"),
				  "description": m.meta.get("description", ""),
				  "strings": [str(s) for s in m.strings]
				}
				for m in matches
			]
	except yara.TimeoutError:
		result["status"] = "timeout"
	except yara.Error as e:
		result["status"] = "error"
		result["error"] = str(e)
	except PermissionError:
		result["status"] = "permission_denied"
	except Exception as e:
		result["status"] = "error"
		result["error"] = str(e)

	return result


def scan_directory(dipath, rules):
	results = []
	scanned = 0
	infected = 0

	print(f"[*] Scanning directory: {dipath}")
	
	for root, dirs, files in os.walk(dipath):
		dirs[:] = [d for d in dirs if os.path.join(root, d) != os.path.abspath(QUARANTINE_DIR)]
		
		for filename in files:
			filepath = os.path.join(root, filename)
			result = scan_file(filepath, rules)
			results.append(result)
			scanned += 1

		if result["status"] == "infected":
			infected += 1
			print(f" [!] INFECTED: {filepath}")
			for m in result["matches"]:
				print(f"   RULE      : {m['rules']}")
				print(f"   Severity  : {m['severity']}")
				print(f"   Desc      : {m['description']}")
		elif result["status"] == "clean":
			print(f"    [+] Clean 	: {filepath}")
		else:
			print(f"    [?] {result['status'].upper()}: {filepath}")
	print(f"\n[*] Scan complete. Scanned: {scanned} | Infected: {infected} | Clean: {scanned - infected}")
	return results

def save_report(results, output_path=None):
	os.makedirs(LOGS_DIR, exist_ok=True)
	if not output_path:
		timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
		output_path = os.path.join(LOGS_DIR, f"scan_{timestamp}.json")

	with open(output_path, "w") as f:
		json.dump(results, f, indent=2)
	
	print(f"[+] Report saved to: {output_path}")
	return output_path


		
