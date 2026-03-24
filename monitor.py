import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scanner import load_rules, scan_file
from quarantine import quarantine_file

WATCH_DIRS = ["/tmp", "/var/www/html", "/home"]
AUTO_QUARANTINE = True

class MalwareEventHandler(FileSystemEventHandler):
	def __init__(self, rules):
		self.rules = rules
		self.recently_scanned = {}

	def should_scan(self, filepath):
		if os.path.isdir(filepath):
			return False
		if "quarantine" in filepath:
			return False
		if filepath.endswith(".json"):
			return False


		last = self.recently_scanned.get(filepath, 0)
		if time.time() - last < 2:
			return False

		return True

	def handle_event(self, filepath):
		#print(f"[DEBUG] handle_event called: {filepath}")
		if not self.should_scan(filepath):
		#	print(f"[DEBUG] skipped by should_scan: {filepath}")
			return

		self.recently_scanned[filepath] = time.time()
		print(f"\n[*] Change detected: {filepath}")

		result = scan_file(filepath, self.rules)
		if result["status"] == "infected":
			print(f"[!!!] MALWARE DETECTED: {filepath}")
			for m in result["matches"]:
				print(f"	Rule      : {m['rules']}")
				print(f"	Severity  : {m['severity']}")
				print(f"	Desc	  : {m['description']}")
			if AUTO_QUARANTINE:
				quarantine_file(filepath, result)
		elif result['status'] == 'clean':
			print(f"[+] Clean: {filepath}")
		else:
			print(f"[?] {result['status'].upper()}: {filepath}")

	def on_created(self, event):
		if not event.is_directory:
			self.handle_event(event.src_path)
	
	def on_modified(self, event):
		if not event.is_directory:
			self.handle_event(event.src_path)
	def on_moved(self, event):
		if not event.is_directory:
			self.handle_event(event.dest_path)


def start_monitor(watch_dirs=None, auto_quarantine=True):
	global AUTO_QUARANTINE
	AUTO_QUARANTINE = auto_quarantine

	if watch_dirs is None:
		watch_dirs = WATCH_DIRS

	print("[*] Loading YARA rules...")
	rules = load_rules()

	observer = Observer()
	handler = MalwareEventHandler(rules)
	
	for directory in watch_dirs:
		if os.path.exists(directory):
			observer.schedule(handler, directory, recursive=True)
			print(f"[+] Watching: {directory}")
		else:
			print(f"[-] Skipping (not found): {directory}")
	
	observer.start()
	print("\n[*] Monitor running, Press Ctrl+C to stop. \n")

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		print("\n[*] Stopping monitor.....")
		observer.stop()

	observer.join()
	print("[*] Monitor stopped.")

if __name__ == "__main__":
	start_monitor()
