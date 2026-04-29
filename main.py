#!/usr/bin/env python3
import sys, os, time, signal, logging, argparse, threading, datetime, queue as _queue
import config
from monitor import FileMonitor
from detector import Detector
from response import ResponseHandler, setup_logging

logger = logging.getLogger(__name__)

def run(auto_kill=True, quiet=False):
    config.AUTO_KILL_PROCESS = auto_kill
    response = ResponseHandler()
    detector = Detector(alert_callback=response.handle)
    monitor  = FileMonitor()

    print("\n" + "=" * 68)
    print("  🛡   Ransomware Detection System  —  Rule-Based Engine")
    print("=" * 68)
    print(f"  Watching : {', '.join(config.WATCH_DIRS)}")
    print(f"  Auto-kill: {'DISABLED' if not auto_kill else 'ENABLED'}")
    print(f"  Log file : {config.LOG_FILE}")
    print("=" * 68)
    print("  ⏳ Building initial snapshots — please wait...")

    monitor.start()   # blocks until ALL snapshots are ready

    print("  ✅ Ready — monitoring active.\n")
    logger.info("Ransomware Detection System running. Press Ctrl+C to stop.")

    stop_evt = threading.Event()

    # Stats display thread
    def stats_loop():
        CYAN="\033[96m"; GREEN="\033[92m"; YELLOW="\033[93m"; RESET="\033[0m"
        while not stop_evt.is_set():
            s   = detector.stats
            now = datetime.datetime.now().strftime("%H:%M:%S")
            ac  = s["alerts_raised"]
            acol= YELLOW if ac > 0 else GREEN
            line= (f"{CYAN}[{now}]{RESET} "
                   f"Events:{s['total_events']:>6}  │  "
                   f"Activity:{s['mod_rate']:>4}  │  "
                   f"Renames:{s['rename_rate']:>3}  │  "
                   f"Queue:{monitor.queue_size:>4}  │  "
                   f"{acol}Alerts:{ac}{RESET}")
            print(f"\r{' '*120}\r{line}", end="", flush=True)
            time.sleep(1.0)
        print()

    if not quiet:
        threading.Thread(target=stats_loop, daemon=True).start()

    def shutdown(sig=None, frame=None):
        stop_evt.set()

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Main event loop
    while not stop_evt.is_set():
        evt = monitor.get_event(timeout=0.5)
        if evt is not None:
            detector.process_event(evt)

    logger.info("Shutting down …")
    monitor.stop()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-kill", action="store_true")
    parser.add_argument("--quiet",   action="store_true")
    args = parser.parse_args()
    setup_logging()
    run(auto_kill=not args.no_kill, quiet=args.quiet)

if __name__ == "__main__":
    main()
