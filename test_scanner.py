# Run this as a standalone script: python test_scanner.py
import queue, time, sys
sys.path.insert(0, '.')
from monitor import DirectoryScanner

q = queue.Queue()
s = DirectoryScanner(r"C:\Users\nader\Documents", q, interval=0.5)
s.start()
print("Scanner ready — manually create or edit a file in Documents now...")

for _ in range(20):
    time.sleep(1)
    while not q.empty():
        print("EVENT:", q.get())

print("Done.")