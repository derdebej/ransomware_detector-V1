"""
debug_monitor.py — Lance le monitor directement et affiche chaque event recu.
"""
import os, sys, time, queue, logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(message)s")

# Patch config pour pointer vers Documents
import config
config.WATCH_DIRS = [os.path.join(os.path.expanduser("~"), "Documents")]

from monitor import FileMonitor, DirectoryScanner

print("Starting direct scanner test...")
q = queue.Queue()
scanner = DirectoryScanner(config.WATCH_DIRS[0], q, interval=0.5)
scanner.start()
print(f"Scanner started on: {config.WATCH_DIRS[0]}")
print("Waiting for events (will create test files in 2s)...\n")

# Create test files after 2s
import threading
def make_files():
    time.sleep(2)
    test_dir = os.path.join(config.WATCH_DIRS[0], "rds_simulation")
    os.makedirs(test_dir, exist_ok=True)
    print("[TEST] Creating files now...")
    for i in range(5):
        path = os.path.join(test_dir, f"debug_test_{i}.txt")
        with open(path, "w") as f:
            f.write(f"test {i}")
        print(f"[TEST] Created: {path}")
        time.sleep(0.3)

t = threading.Thread(target=make_files, daemon=True)
t.start()

# Read queue for 15 seconds
deadline = time.time() + 15
count = 0
while time.time() < deadline:
    try:
        evt = q.get(timeout=0.5)
        count += 1
        print(f"  ✅ EVENT #{count}: [{evt.event_type}] {os.path.basename(evt.src_path)}")
    except queue.Empty:
        pass

print(f"\nTotal events received: {count}")
if count == 0:
    print("❌ No events — scanner thread may not be running")
    print(f"   Scanner thread alive: {scanner._thread.is_alive()}")
    print(f"   Snapshot size: {len(scanner._snapshot)}")
