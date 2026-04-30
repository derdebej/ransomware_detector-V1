#!/usr/bin/env python3
"""
sim_stealth.py — Slow, content-based attack simulator

Mimics ransomware that deliberately stays BELOW rate thresholds to avoid
detection by activity/rename counters. It relies on suspicious extensions
and encrypted content to eventually get caught.

Rate: 1 file per 4s  →  max ~1 file per 5s window, well below MOD_COUNT_THRESHOLD=5
Expected triggers:  SUSPICIOUS_EXTENSION  +  HIGH_ENTROPY  (no rate rules)
Severity:           HIGH  (2 rules)

Usage:
    python sim_stealth.py
    python sim_stealth.py --files 30 --delay 2.0
    python sim_stealth.py --no-cleanup
"""

import os, time, shutil, argparse, pathlib

DOCS    = pathlib.Path.home() / "Documents"
SANDBOX = str(DOCS / "rds_sim_stealth")

EXTS = [".enc", ".locked", ".vault", ".crypt", ".ryuk",
        ".conti", ".blackcat", ".lockbit", ".darkside"]


def make_encrypted_file(index: int, ext: str):
    path = os.path.join(SANDBOX, f"document_{index:04d}{ext}")
    with open(path, "wb") as f:
        f.write(os.urandom(65536))          # max-entropy — looks encrypted
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files",      type=int,   default=20)
    ap.add_argument("--delay",      type=float, default=4.0,
                    help="Seconds between files (keep below MOD_TIME_WINDOW/MOD_COUNT_THRESHOLD)")
    ap.add_argument("--no-cleanup", action="store_true")
    args = ap.parse_args()

    os.makedirs(SANDBOX, exist_ok=True)
    print(f"[STEALTH] Sandbox  : {SANDBOX}")
    print(f"[STEALTH] Rate     : 1 file / {args.delay}s  — below RAPID_FILE_ACTIVITY threshold")
    print(f"[STEALTH] Goal     : SUSPICIOUS_EXTENSION + HIGH_ENTROPY only")
    print()

    try:
        for i in range(args.files):
            ext  = EXTS[i % len(EXTS)]
            path = make_encrypted_file(i, ext)
            print(f"[STEALTH] [{i+1:2d}/{args.files}] {os.path.basename(path)}")
            time.sleep(args.delay)
    except KeyboardInterrupt:
        print("\n[STEALTH] Interrupted.")

    if not args.no_cleanup:
        print(f"\n[STEALTH] Waiting 3s so detector can catch the last events...")
        time.sleep(3)
        shutil.rmtree(SANDBOX, ignore_errors=True)
        print("[STEALTH] Cleaned up.")
    else:
        print(f"\n[STEALTH] Files kept in: {SANDBOX}")


if __name__ == "__main__":
    main()
