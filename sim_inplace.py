#!/usr/bin/env python3
"""
sim_inplace.py — Realistic in-place encryption simulator (WannaCry / LockBit style)

Most real ransomware works in two phases:
  Phase 1 — SCAN   : create/find "victim" documents (normal-looking files, no alert)
  Phase 2 — ATTACK : overwrite each file with encrypted content, rename to .enc

Phase 1 is invisible to the detector (no suspicious extension, low entropy content).
Phase 2 hits three rules simultaneously: RAPID_RENAMES + SUSPICIOUS_EXTENSION + HIGH_ENTROPY.

Expected triggers:  RAPID_RENAMES  +  SUSPICIOUS_EXTENSION  +  HIGH_ENTROPY
Severity:           HIGH  (3 rules)

Usage:
    python sim_inplace.py
    python sim_inplace.py --victims 30 --delay 0.1
    python sim_inplace.py --no-cleanup
"""

import os, time, random, shutil, argparse, pathlib

DOCS    = pathlib.Path.home() / "Documents"
SANDBOX = str(DOCS / "rds_sim_inplace")

VICTIM_EXTS = [".txt", ".docx", ".xlsx", ".pdf", ".jpg", ".png"]
ENC_EXT     = ".enc"


def _fake_doc_content(size: int = 8192) -> bytes:
    text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 200
    return text[:size].encode()


def phase1_create_victims(n: int, delay: float) -> list:
    print(f"\n[INPLACE] Phase 1 — Creating {n} victim documents (no alerts expected)...")
    print(f"[INPLACE]   Rate: 1 file / {delay}s — max {int(5/delay)} unique files per 5s window (threshold=5)")
    files = []
    for i in range(n):
        ext  = VICTIM_EXTS[i % len(VICTIM_EXTS)]
        path = os.path.join(SANDBOX, f"important_file_{i:03d}{ext}")
        with open(path, "wb") as f:
            f.write(_fake_doc_content(random.randint(4096, 32768)))
        files.append(path)
        print(f"\r[INPLACE]   Created {i+1}/{n}", end="", flush=True)
        time.sleep(delay)
    print(f"\n[INPLACE]   {n} victim files ready.")
    return files


def phase2_encrypt(files: list, delay: float):
    print(f"\n[INPLACE] Phase 2 — Encrypting in-place + renaming ({delay}s/file)...")
    print(f"[INPLACE]   Expected: RAPID_RENAMES + SUSPICIOUS_EXTENSION + HIGH_ENTROPY\n")
    for i, path in enumerate(files):
        # Overwrite with high-entropy (encrypted) content — triggers HIGH_ENTROPY
        with open(path, "wb") as f:
            f.write(os.urandom(65536))
        # Rename to .enc — triggers SUSPICIOUS_EXTENSION + RAPID_RENAMES
        enc_path = path + ENC_EXT
        os.rename(path, enc_path)
        print(f"\r[INPLACE]   Encrypted {i+1}/{len(files)} — {os.path.basename(enc_path)}", end="", flush=True)
        time.sleep(delay)
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--victims",     type=int,   default=10,
                    help="Number of victim files to create")
    ap.add_argument("--scan-delay",  type=float, default=1.5,
                    help="Seconds between victim file creations — must keep unique files "
                         "per MOD_TIME_WINDOW below MOD_COUNT_THRESHOLD; "
                         "safe minimum = MOD_TIME_WINDOW / (MOD_COUNT_THRESHOLD-1) > 1.25s")
    ap.add_argument("--delay",       type=float, default=0.2,
                    help="Seconds between each encrypt+rename operation in Phase 2")
    ap.add_argument("--no-cleanup",  action="store_true")
    args = ap.parse_args()

    os.makedirs(SANDBOX, exist_ok=True)
    print(f"[INPLACE] Sandbox: {SANDBOX}")

    try:
        victims = phase1_create_victims(args.victims, args.scan_delay)
        time.sleep(1.0)   # brief pause between phases — realistic behavior
        phase2_encrypt(victims, args.delay)
    except KeyboardInterrupt:
        print("\n[INPLACE] Interrupted.")

    if not args.no_cleanup:
        print(f"\n[INPLACE] Waiting 3s before cleanup...")
        time.sleep(3)
        shutil.rmtree(SANDBOX, ignore_errors=True)
        print("[INPLACE] Cleaned up.")
    else:
        print(f"\n[INPLACE] Files kept in: {SANDBOX}")


if __name__ == "__main__":
    main()
