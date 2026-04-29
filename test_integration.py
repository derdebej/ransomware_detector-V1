# test_rename_detection.py
import time, sys
sys.path.insert(0, '.')

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class RenameDebugHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return
        dest = getattr(event, 'dest_path', '')
        print(f"[{event.event_type:10}] {event.src_path}"
              + (f" -> {dest}" if dest else ""))

observer = Observer()
observer.schedule(RenameDebugHandler(),
                  r"C:\Users\nader\Documents",
                  recursive=True)
observer.start()

print("Ready — now run in another terminal:")
print("  python simulate_ransomware.py --mode suspicious_ext --no-cleanup")
print()

try:
    for i in range(60):
        time.sleep(1)
        sys.stdout.write(f"\r{i+1}/60s elapsed...")
        sys.stdout.flush()
finally:
    observer.stop()
    observer.join()

print("\nDone.")