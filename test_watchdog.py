"""
test_watchdog.py — Test minimal pour vérifier que watchdog fonctionne.
Lance ce script SEUL dans un CMD, puis crée/modifie un fichier dans
Documents manuellement (ou laisse le script le faire automatiquement).
"""
import os, sys, time, threading

if sys.platform == "win32":
    from watchdog.observers.polling import PollingObserver as Observer
else:
    from watchdog.observers import Observer

from watchdog.events import FileSystemEventHandler

WATCH_DIR = os.path.join(os.path.expanduser("~"), "Documents")

class TestHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if not event.is_directory:
            print(f"  ✅ EVENT DETECTED: [{event.event_type}] {event.src_path}")

print(f"Watching: {WATCH_DIR}")
print("Waiting for file events... (Ctrl+C to stop)\n")

observer = Observer()
observer.schedule(TestHandler(), WATCH_DIR, recursive=True)
observer.start()

# Auto-create a test file after 3 seconds
def auto_test():
    time.sleep(3)
    test_file = os.path.join(WATCH_DIR, "_watchdog_test.txt")
    print(f"  [AUTO] Creating test file: {test_file}")
    with open(test_file, "w") as f:
        f.write("watchdog test")
    time.sleep(2)
    print(f"  [AUTO] Modifying test file...")
    with open(test_file, "a") as f:
        f.write("\nmodified")
    time.sleep(2)
    print(f"  [AUTO] Deleting test file...")
    os.remove(test_file)
    time.sleep(2)
    print("\n--- If no ✅ appeared above, watchdog cannot see events on this system ---")

t = threading.Thread(target=auto_test, daemon=True)
t.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
observer.join()
