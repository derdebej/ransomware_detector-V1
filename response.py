# =============================================================================
# response.py — Automated response to ransomware detection alerts
#
# Actions (in order):
#   1. Log the alert to file (always)
#   2. Print a prominent console alert
#   3. Kill the offending process (if AUTO_KILL_PROCESS is True)
#   4. Optional: sound alert
# =============================================================================

import os
import sys
import signal
import logging
import datetime
import threading

import psutil

import config
from detector import DetectionAlert

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging setup — called once at startup
# ---------------------------------------------------------------------------

def setup_logging():
    """Configure root logger to write to both console and log file."""
    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Console handler (INFO and above)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(fmt, datefmt))
    root.addHandler(ch)

    # File handler (DEBUG and above — full audit trail)
    fh = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt, datefmt))
    root.addHandler(fh)

    logger.info("Logging initialised → %s", config.LOG_FILE)

# response.py — add this helper above the ResponseHandler class

# response.py — replace _find_pid_by_file_activity with this faster version

def _find_pid_by_file_activity(watch_dirs):
    """
    Find ransomware process — first try by name match,
    then fall back to open files scan.
    """
    watch_dirs_norm = [os.path.normpath(d).lower() for d in watch_dirs]

    # Known attacker names — add your exe name here
    SUSPECT_NAMES = {
        'ransomware_sim.exe',
        'simulate_ransomware.exe',
        'cryptor.exe',
        'encryptor.exe',
    }

    # Pass 1 — instant name match (works for demo with known exe)
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() in SUSPECT_NAMES:
                return proc.info['pid'], proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Pass 2 — find process with most watched-dir files open
    suspects = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if name in {'system', 'svchost.exe', 'explorer.exe',
                        'searchindexer.exe', 'registry', 'smss.exe',
                        'csrss.exe', 'wininit.exe', 'services.exe',
                        'lsass.exe', 'winlogon.exe'}:
                continue
            count = sum(
                1 for f in (proc.open_files() or [])
                if any(os.path.normpath(f.path).lower().startswith(d)
                       for d in watch_dirs_norm)
            )
            if count > 0:
                suspects[proc.info['pid']] = (proc.info['name'], count)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not suspects:
        return None, None

    best_pid = max(suspects, key=lambda p: suspects[p][1])
    return best_pid, suspects[best_pid][0]
# ---------------------------------------------------------------------------
# Response handler
# ---------------------------------------------------------------------------

class ResponseHandler:
    """
    Receives a DetectionAlert and executes the response playbook.
    All methods are intentionally defensive — a failure in one step must
    not prevent the others from running.
    """

    # response.py — update handle() method

    # response.py — update handle() to be non-blocking

    # response.py — replace handle() and _handle_async()

    def handle(self, alert: DetectionAlert):
        # Only log immediately, print after PID is found
        threading.Thread(
            target=self._handle_async,
            args=(alert,),
            daemon=True
        ).start()

    def _handle_async(self, alert: DetectionAlert):
        if alert.offending_pid is None:
            pid, name = _find_pid_by_file_activity(config.WATCH_DIRS)
            if pid:
                alert.offending_pid = pid
                alert.offending_process = name
        self._log_alert(alert)   # ← moved here
        self._print_alert(alert)
        if config.AUTO_KILL_PROCESS and alert.offending_pid is not None:
            self._kill_process(alert.offending_pid, alert.offending_process)
        if config.ALERT_SOUND:
            self._beep()
    # -----------------------------------------------------------------------

    @staticmethod
    def _log_alert(alert: DetectionAlert):
        ts = datetime.datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "=" * 70,
            f"  ⚠  RANSOMWARE DETECTED — {ts}  [{alert.severity}]",
            f"  Process : {alert.offending_process or 'unknown'}  (PID {alert.offending_pid})",
            f"  Rules   : {', '.join(alert.triggered_rules)}",
            "  Evidence:",
        ]
        for rule, detail in alert.evidence.items():
            lines.append(f"    [{rule}] {detail}")
        lines.append("=" * 70)
        block = "\n".join(lines)
        logger.warning("\n%s", block)

    @staticmethod
    def _print_alert(alert: DetectionAlert):
        RED   = "\033[91m"
        BOLD  = "\033[1m"
        RESET = "\033[0m"
        ts = datetime.datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")

        print(f"\n{RED}{BOLD}")
        print("╔══════════════════════════════════════════════════════════════════╗")
        print(f"║  🚨  RANSOMWARE DETECTED [{alert.severity}]  —  {ts}              ║")
        print("╠══════════════════════════════════════════════════════════════════╣")
        proc = alert.offending_process or "unknown"
        print(f"║  Process : {proc:<20}  PID : {str(alert.offending_pid):<10}        ║")
        print(f"║  Rules   : {', '.join(alert.triggered_rules):<54}  ║")
        print("╠══════════════════════════════════════════════════════════════════╣")
        for rule, detail in alert.evidence.items():
            # Truncate detail to fit console width
            short = detail[:58] if len(detail) > 58 else detail
            print(f"║  {rule:<20} {short:<44}  ║")
        print("╚══════════════════════════════════════════════════════════════════╝")
        print(f"{RESET}")

    @staticmethod
    def _kill_process(pid: int, name: str):
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()

            # Safety guard — never kill system-critical processes
            PROTECTED = {
                "systemd", "init", "kthreadd", "sshd", "bash",
                "python", "python3", "explorer.exe", "winlogon.exe",
                "services.exe", "lsass.exe",
            }
            if proc_name.lower() in PROTECTED:
                logger.warning(
                    "Refusing to kill protected process %s (PID %d)", proc_name, pid
                )
                return

            proc.terminate()          # SIGTERM first (graceful)
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()           # SIGKILL if still alive

            logger.warning("Killed process %s (PID %d)", proc_name, pid)
            print(f"  ✅  Process '{proc_name}' (PID {pid}) has been terminated.")

        except psutil.NoSuchProcess:
            logger.info("Process PID %d already gone.", pid)
        except psutil.AccessDenied:
            logger.error(
                "Access denied — cannot kill PID %d. "
                "Try running as root/Administrator.",
                pid,
            )
            print(f"  ❌  Cannot kill PID {pid}: permission denied (try sudo).")
        except Exception as exc:
            logger.error("Unexpected error killing PID %d: %s", pid, exc)

    @staticmethod
    def _beep():
        """Cross-platform beep."""
        try:
            if sys.platform == "win32":
                import winsound
                winsound.Beep(1000, 500)
            else:
                sys.stdout.write("\a")
                sys.stdout.flush()
        except Exception:
            pass
