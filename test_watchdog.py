# test_watchdog.py - run this standalone
import time, sys
sys.path.insert(0, '.')

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class DebugHandler(FileSystemEventHandler):
    def on_any_event(self, event):
        print(f"EVENT: {event.event_type} -> {event.src_path}")

observer = Observer()
observer.schedule(DebugHandler(), r"C:\Users\nader\Documents", recursive=True)
observer.start()

print("Watching Documents — create/edit/delete a file now...")
try:
    for _ in range(30):
        time.sleep(1)
        sys.stdout.write(".")
        sys.stdout.flush()
finally:
    observer.stop()
    observer.join()

print("\nDone.")