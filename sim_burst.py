#!/usr/bin/env python3
"""
sim_burst.py — Burst-pattern attack simulator

Simulates ransomware that alternates between intense bursts of activity
and long quiet periods, trying to appear as normal background file I/O.
Each burst is designed to just cross the detection threshold.

Phase layout:
  1. Quiet Probe    — tiny activity, below all thresholds (no alert expected)
  2. Rename Sweep   — rapid renames only
  3. Encrypt Burst  — rapid high-entropy writes + suspicious extensions
  4. Silent Gap     — long pause (clears sliding windows)
  5. Final Wave     — combined rename + encrypt, highest intensity

Expected triggers: varies per phase — RAPID_RENAMES, SUSPICIOUS_EXTENSION, HIGH_ENTROPY
Severity: HIGH (phases 3 and 5 hit multiple rules)

Usage:
    python sim_burst.py
    python sim_burst.py --no-cleanup
"""

import os, time, shutil, pathlib, argparse

DOCS    = pathlib.Path.home() / "Documents"
SANDBOX = str(DOCS / "rds_sim_burst")

# Each phase: name, n_files, extension, high_entropy, delay_between_files, pause_after
PHASES = [
    # Phase 1 — innocent-looking probe: below every threshold, no alert
    dict(name="Quiet Probe",   n=3,  ext=".tmp",     entropy=False, delay=3.0,  pause=6.0,
         note="Below all thresholds — no alert expected"),

    # Phase 2 — rapid rename sweep: triggers RAPID_RENAMES + SUSPICIOUS_EXTENSION
    dict(name="Rename Sweep",  n=8,  ext=".enc",     entropy=False, delay=0.3,  pause=8.0,
         note="RAPID_RENAMES + SUSPICIOUS_EXTENSION"),

    # Phase 3 — encryption burst: triggers RAPID_FILE_ACTIVITY + SUSPICIOUS_EXTENSION + HIGH_ENTROPY
    dict(name="Encrypt Burst", n=12, ext=".locked",  entropy=True,  delay=0.2,  pause=10.0,
         note="RAPID_FILE_ACTIVITY + SUSPICIOUS_EXTENSION + HIGH_ENTROPY"),

    # Phase 4 — silent gap: activity windows cool down
    dict(name="Silent Gap",    n=2,  ext=".tmp",     entropy=False, delay=4.0,  pause=8.0,
         note="Sliding windows reset — detector resets state"),

    # Phase 5 — final wave: all-out attack, all rules fire
    dict(name="Final Wave",    n=20, ext=".ryuk",    entropy=True,  delay=0.15, pause=0.0,
         note="All rules — RAPID_FILE_ACTIVITY + RAPID_RENAMES + SUSPICIOUS_EXTENSION + HIGH_ENTROPY"),
]

_file_counter = 0


def run_phase(phase: dict) -> int:
    global _file_counter
    created = 0
    print(f"\n  ┌─ {phase['name']} ─────────────────────────────")
    print(f"  │  Files: {phase['n']}  Ext: {phase['ext']}  "
          f"Entropy: {'yes' if phase['entropy'] else 'no'}  "
          f"Delay: {phase['delay']}s")
    print(f"  │  Note: {phase['note']}")
    print(f"  └{'─' * 50}")

    subdir = os.path.join(SANDBOX, phase['name'].lower().replace(' ', '_'))
    os.makedirs(subdir, exist_ok=True)

    for i in range(phase['n']):
        path = os.path.join(subdir, f"file_{_file_counter:04d}{phase['ext']}")
        content = os.urandom(65536) if phase['entropy'] else b"normal content " * 64
        with open(path, "wb") as f:
            f.write(content)
        _file_counter += 1
        created += 1
        print(f"  [{i+1:2d}/{phase['n']}] {os.path.basename(path)}")
        time.sleep(phase['delay'])

    if phase['pause'] > 0:
        print(f"\n  ... quiet for {phase['pause']}s (windows cooling down) ...\n")
        time.sleep(phase['pause'])

    return created


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-cleanup", action="store_true")
    args = ap.parse_args()

    os.makedirs(SANDBOX, exist_ok=True)
    print(f"[BURST] Sandbox : {SANDBOX}")
    print(f"[BURST] Phases  : {len(PHASES)}")
    print(f"[BURST] Strategy: alternate between intense bursts and quiet gaps\n")

    total = 0
    try:
        for idx, phase in enumerate(PHASES):
            print(f"[BURST] ══ Phase {idx+1}/{len(PHASES)} ══", flush=True)
            total += run_phase(phase)
    except KeyboardInterrupt:
        print("\n[BURST] Interrupted.")

    print(f"\n[BURST] Total files created: {total}")

    if not args.no_cleanup:
        print("[BURST] Waiting 3s before cleanup...")
        time.sleep(3)
        shutil.rmtree(SANDBOX, ignore_errors=True)
        print("[BURST] Cleaned up.")
    else:
        print(f"[BURST] Files kept in: {SANDBOX}")


if __name__ == "__main__":
    main()
