# =============================================================================
# response.py — Automated response to ransomware detection alerts
# =============================================================================

import os
import sys
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
    fmt = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # File handler only — console output is handled by the pretty TUI.
    # A console StreamHandler would interleave with the stats bar.
    fh = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt, datefmt))
    root.addHandler(fh)


def _find_pid_by_file_activity(watch_dirs):
    """
    Find the ransomware process using three passes in order of speed:
      1. EXE name match       -- compiled simulators / known malware names
      2. Command-line match   -- Python-run scripts (files closed before open-file scan)
      3. Open-files heuristic -- unknown process with most watched-dir files open
    """
    watch_dirs_norm = [os.path.normpath(d).lower() for d in watch_dirs]

    # Pass 1 -- instant EXE name match
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() in config.SUSPECT_PROCESS_NAMES:
                return proc.info['pid'], proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Constants shared by Pass 2 and Pass 3.
    OWN_PID      = os.getpid()
    PYTHON_NAMES = {'python.exe', 'python3.exe', 'python', 'python3'}
    SAFE_SCRIPTS = {'main.py'}

    # Pass 2 -- generic Python-process detection.
    # Python scripts open and close files too fast for open-file scanning, but
    # the script name is always visible in the process argv. We flag any
    # python.exe that is not the detector's own process and is not running
    # main.py (the detector entry point). This works for any simulator script
    # without requiring its name to be hardcoded anywhere.
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['pid'] == OWN_PID:
                continue
            if proc.info['name'].lower() not in PYTHON_NAMES:
                continue
            cmdline = proc.info.get('cmdline') or []
            scripts = {os.path.basename(a).lower() for a in cmdline if a.endswith('.py')}
            if scripts and scripts.issubset(SAFE_SCRIPTS):
                continue
            if scripts:
                script_name  = next(iter(scripts))
                display_name = f"{proc.info['name']} [{script_name}]"
                return proc.info['pid'], display_name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Pass 3 -- unknown process: pick the one with most watched-dir files open.
    # Explicitly excludes the detector's own PID and all Python interpreters
    # (Python processes are handled by Pass 2; if Pass 2 didn't find one it
    # means no suspicious .py script is running, so don't kill python.exe here).
    SKIP = {'system', 'svchost.exe', 'explorer.exe', 'searchindexer.exe',
            'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'winlogon.exe'} | PYTHON_NAMES
    suspects = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['pid'] == OWN_PID:
                continue
            if proc.info['name'].lower() in SKIP:
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
    def handle(self, alert: DetectionAlert):
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
        self._log_alert(alert)
        if config.ALERT_SOUND:
            self._beep()

    @staticmethod
    def _log_alert(alert: DetectionAlert):
        ts = datetime.datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "=" * 70,
            f"  WARNING  RANSOMWARE DETECTED -- {ts}  [{alert.severity}]",
            f"  Process : {alert.offending_process or 'unknown'}  (PID {alert.offending_pid})",
            f"  Rules   : {', '.join(alert.triggered_rules)}",
            "  Evidence:",
        ]
        for rule, detail in alert.evidence.items():
            lines.append(f"    [{rule}] {detail}")
        lines.append("=" * 70)
        logger.warning("\n%s", "\n".join(lines))

    @staticmethod
    def _beep():
        try:
            if sys.platform == "win32":
                import winsound
                winsound.Beep(1000, 500)
            else:
                sys.stdout.write("\a")
                sys.stdout.flush()
        except Exception:
            pass
