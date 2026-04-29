"""
test_direct.py — Teste la détection SANS watchdog, par scan direct du dossier.
Lance ce script seul. Il va créer des fichiers et vérifier s'il les voit.
"""
import os, sys, time, hashlib

WATCH_DIR = os.path.join(os.path.expanduser("~"), "Documents")
TEST_DIR  = os.path.join(WATCH_DIR, "rds_simulation")

print(f"Test directory: {TEST_DIR}")
print(f"OneDrive sync?  {os.path.exists(os.path.join(WATCH_DIR, 'desktop.ini'))}")
print()

# Snapshot function
def snapshot(path):
    result = {}
    try:
        for root, dirs, files in os.walk(path):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    result[fp] = os.path.getmtime(fp)
                except:
                    pass
    except:
        pass
    return result

os.makedirs(TEST_DIR, exist_ok=True)

print("Taking initial snapshot...")
before = snapshot(TEST_DIR)
print(f"Files found: {len(before)}")

print("\nCreating 5 test files...")
for i in range(5):
    with open(os.path.join(TEST_DIR, f"test_{i}.txt"), "w") as f:
        f.write(f"content {i}")

time.sleep(1)
after = snapshot(TEST_DIR)
new_files = set(after) - set(before)
print(f"New files detected by direct scan: {len(new_files)}")
for f in new_files:
    print(f"  ✅ {os.path.basename(f)}")

if not new_files:
    print("  ❌ Direct scan sees nothing — OneDrive or permissions issue")
else:
    print("\n✅ Direct scanning WORKS — switching monitor.py to use polling scan")

# Cleanup
import shutil
shutil.rmtree(TEST_DIR, ignore_errors=True)
print("\nTest complete.")
