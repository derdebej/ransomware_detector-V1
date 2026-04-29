import os, sys, time, queue
sys.path.insert(0, '.')
from monitor import DirectoryScanner

docs = os.path.join(os.path.expanduser("~"), "Documents")
q = queue.Queue()
s = DirectoryScanner(docs, q, interval=0.5)
s.start()

print("Thread alive:", s._thread.is_alive())
print("Snapshot size:", len(s._snapshot))

time.sleep(2)
print("Queue after 2s:", q.qsize())

# Create a file
test_dir = os.path.join(docs, "rds_simulation")
os.makedirs(test_dir, exist_ok=True)
test_file = os.path.join(test_dir, "_test123.txt")
with open(test_file, "w") as f:
    f.write("test")
print("Created:", test_file)

time.sleep(2)
print("Queue after file creation:", q.qsize())

if q.qsize() > 0:
    evt = q.get_nowait()
    print("EVENT:", evt.event_type, evt.src_path)
else:
    print("NO EVENT — checking thread...")
    print("Thread still alive:", s._thread.is_alive())
    # Check if _check() runs manually
    print("Running _check() manually...")
    before = len(s._snapshot)
    s._check()
    after = len(s._snapshot)
    print(f"Snapshot before: {before}, after: {after}")
    print("Queue after manual check:", q.qsize())
