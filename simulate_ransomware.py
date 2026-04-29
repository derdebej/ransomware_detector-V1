#!/usr/bin/env python3
# =============================================================================
# simulate_ransomware.py — Safe test script that mimics ransomware behaviour
#
# ⚠  This script only creates / renames / deletes files it creates itself.
#    It NEVER touches your real files.
#
# Modes:
#   python simulate_ransomware.py --mode rapid_mods    (trigger Rule 1)
#   python simulate_ransomware.py --mode suspicious_ext (trigger Rules 2+3)
#   python simulate_ransomware.py --mode encrypted      (trigger Rule 4)
#   python simulate_ransomware.py --mode full           (trigger all rules)
# =============================================================================

import os
import sys
import time
import random
import string
import shutil
import argparse
import tempfile

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# BUG FIX 1 (simulateur) : Le sandbox etait dans %TEMP% qui n'etait
# pas surveille par le detecteur -> aucun evenement jamais detecte.
# On cree le sandbox dans Documents (toujours surveille).
import pathlib
_DOCS = pathlib.Path.home() / "Documents"
SANDBOX_DIR = str(_DOCS / "rds_simulation")
SUSPICIOUS_EXTS = [".enc", ".locked", ".encrypted", ".crypt"]


def _setup():
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    print(f"[SIM] Sandbox directory: {SANDBOX_DIR}")


def _cleanup():
    print("[SIM] Waiting 2s before cleanup so detector can catch events...")
    time.sleep(2.0)   # ← add this
    if os.path.isdir(SANDBOX_DIR):
        shutil.rmtree(SANDBOX_DIR)
    print("[SIM] Sandbox cleaned up.")


def _random_name(length=8):
    return "".join(random.choices(string.ascii_lowercase, k=length))


def _make_file(name=None, content=None, subdir=None):
    base = os.path.join(SANDBOX_DIR, subdir) if subdir else SANDBOX_DIR
    os.makedirs(base, exist_ok=True)
    path = os.path.join(base, name or (_random_name() + ".txt"))
    with open(path, "wb") as fh:
        fh.write(content or b"Normal document content " * 50)
    return path


def _high_entropy_bytes(size=65536):
    """Return bytes that look like encrypted data (high Shannon entropy)."""
    return bytes([random.randint(0, 255) for _ in range(size)])


# ---------------------------------------------------------------------------
# Simulation scenarios
# ---------------------------------------------------------------------------

def simulate_rapid_modifications(n=30, delay=0.2):
    """Rapidly modify many files → triggers Rule 1."""
    print(f"\n[SIM] ── Rapid Modifications ({n} files in ~{n*delay:.1f}s) ──")
    files = [_make_file() for _ in range(n)]
    for i, path in enumerate(files):
        with open(path, "ab") as fh:
            fh.write(f"modified {i}\n".encode())
        sys.stdout.write(f"\r[SIM]  Modified {i+1}/{n}")
        sys.stdout.flush()
        time.sleep(delay)
    print(f"\n[SIM] Done — {n} files modified.")


def simulate_suspicious_extensions(n=10, delay=0.3):
    """Rename files to suspicious extensions → triggers Rules 2 & 3."""
    print(f"\n[SIM] ── Suspicious Extension Renames ({n} files) ──")
    files = [_make_file() for _ in range(n)]
    for i, path in enumerate(files):
        ext = random.choice(SUSPICIOUS_EXTS)
        new_path = os.path.splitext(path)[0] + ext
        os.rename(path, new_path)
        sys.stdout.write(f"\r[SIM]  Renamed {i+1}/{n} → {ext}")
        sys.stdout.flush()
        time.sleep(delay)
    print(f"\n[SIM] Done — {n} files renamed with suspicious extensions.")


def simulate_encrypted_files(n=5):
    """Write high-entropy content → triggers Rule 4."""
    print(f"\n[SIM] ── High-Entropy (Encrypted) Files ({n} files) ──")
    for i in range(n):
        content = _high_entropy_bytes()
        path = _make_file(name=_random_name() + ".enc", content=content)
        print(f"[SIM]  Created high-entropy file: {os.path.basename(path)}")
    print(f"[SIM] Done — {n} encrypted-looking files created.")


def simulate_full_attack(delay=0.1):
    """Combine all behaviours to trigger every rule."""
    print("\n[SIM] ══ FULL RANSOMWARE SIMULATION ══")
    simulate_rapid_modifications(n=25, delay=delay)
    simulate_suspicious_extensions(n=8, delay=0.1)
    simulate_encrypted_files(n=5)
    print("\n[SIM] Full simulation complete.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Simulate ransomware behaviour to test the detection system."
    )
    parser.add_argument(
        "--mode",
        choices=["rapid_mods", "suspicious_ext", "encrypted", "full"],
        default="full",
        help="Which simulation scenario to run (default: full)",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Keep the sandbox directory after the simulation",
    )
    args = parser.parse_args()

    _setup()

    try:
        if args.mode == "rapid_mods":
            simulate_rapid_modifications()
        elif args.mode == "suspicious_ext":
            simulate_suspicious_extensions()
        elif args.mode == "encrypted":
            simulate_encrypted_files()
        else:
            simulate_full_attack()
    finally:
        if not args.no_cleanup:
            _cleanup()
        else:
            print(f"[SIM] Files kept in: {SANDBOX_DIR}")


if __name__ == "__main__":
    main()
