#!/usr/bin/env python3
"""
sim_multiprocess.py — Multi-process distributed attack simulator

Spawns N independent worker subprocesses. Each worker autonomously encrypts
its own batch of files. Killing the coordinator does NOT stop the workers —
they run as separate python.exe processes.

This tests whether the detector can track and respond to multiple simultaneous
attack processes, each with their own PID.

Expected triggers (per worker): RAPID_FILE_ACTIVITY + SUSPICIOUS_EXTENSION + HIGH_ENTROPY
Severity: HIGH

Usage:
    python sim_multiprocess.py                    # 3 workers, 15 files each
    python sim_multiprocess.py --workers 5        # 5 workers
    python sim_multiprocess.py --files 10 --delay 0.2
    python sim_multiprocess.py --no-cleanup

Worker mode (called internally, not meant for direct use):
    python sim_multiprocess.py --worker-id 0 --files 15 --delay 0.3
"""

import os, sys, time, shutil, argparse, subprocess, pathlib

DOCS    = pathlib.Path.home() / "Documents"
SANDBOX = str(DOCS / "rds_sim_multiproc")

EXTS = [".enc", ".locked", ".crypt", ".ryuk", ".conti", ".lockbit"]


# ---------------------------------------------------------------------------
# Worker — runs in a subprocess, fully autonomous
# ---------------------------------------------------------------------------

def run_worker(worker_id: int, n_files: int, delay: float):
    my_dir = os.path.join(SANDBOX, f"worker_{worker_id:02d}")
    os.makedirs(my_dir, exist_ok=True)
    print(f"[W{worker_id:02d}] PID={os.getpid()}  dir={my_dir}  files={n_files}  delay={delay}s")

    try:
        for i in range(n_files):
            ext  = EXTS[(worker_id + i) % len(EXTS)]
            path = os.path.join(my_dir, f"file_{i:04d}{ext}")
            with open(path, "wb") as f:
                f.write(os.urandom(65536))
            print(f"[W{worker_id:02d}] [{i+1:2d}/{n_files}] {os.path.basename(path)}")
            time.sleep(delay)
    except KeyboardInterrupt:
        pass

    print(f"[W{worker_id:02d}] Finished.")


# ---------------------------------------------------------------------------
# Coordinator — spawns workers, waits for completion
# ---------------------------------------------------------------------------

def run_coordinator(n_workers: int, n_files: int, delay: float, no_cleanup: bool):
    os.makedirs(SANDBOX, exist_ok=True)
    print(f"[COORD] Sandbox  : {SANDBOX}")
    print(f"[COORD] Workers  : {n_workers}")
    print(f"[COORD] Files/w  : {n_files}")
    print(f"[COORD] Delay    : {delay}s")
    print()
    print(f"[COORD] Kill this process — workers keep running autonomously.")
    print(f"[COORD] Spawning workers...\n")

    procs = []
    for wid in range(n_workers):
        p = subprocess.Popen(
            [
                sys.executable, __file__,
                "--worker-id", str(wid),
                "--files",     str(n_files),
                "--delay",     str(delay),
            ],
            # Workers print to their own stdout independently
        )
        procs.append(p)
        print(f"[COORD] Worker {wid} spawned  PID={p.pid}")
        time.sleep(0.3)   # stagger starts so they don't all trigger simultaneously

    print(f"\n[COORD] All {n_workers} workers running. Coordinator waiting...\n")

    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        print("\n[COORD] Coordinator interrupted. Workers may still be running.")
        return

    print(f"\n[COORD] All workers done.")

    if not no_cleanup:
        time.sleep(2)
        shutil.rmtree(SANDBOX, ignore_errors=True)
        print("[COORD] Cleaned up.")
    else:
        print(f"[COORD] Files kept in: {SANDBOX}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    # Coordinator options
    ap.add_argument("--workers",    type=int,   default=3)
    ap.add_argument("--files",      type=int,   default=15)
    ap.add_argument("--delay",      type=float, default=0.3)
    ap.add_argument("--no-cleanup", action="store_true")
    # Worker mode (internal)
    ap.add_argument("--worker-id",  type=int,   default=None)
    args = ap.parse_args()

    if args.worker_id is not None:
        run_worker(args.worker_id, args.files, args.delay)
    else:
        run_coordinator(args.workers, args.files, args.delay, args.no_cleanup)


if __name__ == "__main__":
    main()
