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


# ---------------------------------------------------------------------------
# Response handler
# ---------------------------------------------------------------------------

class ResponseHandler:
    """
    Receives a DetectionAlert and executes the response playbook.
    All methods are intentionally defensive — a failure in one step must
    not prevent the others from running.
    """

    def handle(self, alert: DetectionAlert):
        self._log_alert(alert)
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
