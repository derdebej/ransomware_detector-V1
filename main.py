#!/usr/bin/env python3
import re, sys, os, time, signal, logging, argparse, threading, datetime
import ctypes
import config
from monitor import FileMonitor
from detector import Detector
from response import ResponseHandler, setup_logging

def enable_ansi():
    """Enable ANSI/VT100 color codes on Windows Terminal."""
    if os.name == 'nt':
        try:
            # Enable virtual terminal processing
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(
                kernel32.GetStdHandle(-11),  # STD_OUTPUT_HANDLE
                7  # ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            )
        except Exception:
            pass

logger = logging.getLogger(__name__)

_ANSI_ESCAPE = re.compile(r'\033\[[0-9;]*m')

# Single lock that all threads must hold before writing to stdout.
# Prevents alert boxes from interleaving with each other or the stats bar.
_print_lock = threading.Lock()

def _truncate_ansi(s: str, max_visible: int) -> str:
    """Truncate s to at most max_visible printable characters, keeping ANSI codes intact."""
    result = []
    visible = 0
    i = 0
    while i < len(s):
        if s[i] == '\033' and i + 1 < len(s) and s[i + 1] == '[':
            j = i + 2
            while j < len(s) and s[j] != 'm':
                j += 1
            result.append(s[i:j + 1])
            i = j + 1
        else:
            if visible >= max_visible:
                break
            result.append(s[i])
            visible += 1
            i += 1
    result.append('\033[0m')
    return ''.join(result)

# ---------------------------------------------------------------------------
# Terminal color/style constants (Windows Terminal / ANSI)
# ---------------------------------------------------------------------------
R  = "\033[0m"          # reset
BOLD = "\033[1m"
DIM  = "\033[2m"

# Colors
RED     = "\033[38;5;196m"
ORANGE  = "\033[38;5;208m"
YELLOW  = "\033[38;5;226m"
GREEN   = "\033[38;5;46m"
CYAN    = "\033[38;5;51m"
BLUE    = "\033[38;5;27m"
PURPLE  = "\033[38;5;135m"
WHITE   = "\033[38;5;255m"
GRAY    = "\033[38;5;240m"
LGRAY   = "\033[38;5;248m"

# Backgrounds
BG_RED    = "\033[48;5;196m"
BG_DARK   = "\033[48;5;234m"
BG_DARKER = "\033[48;5;232m"

def cls():
    os.system("cls" if os.name == "nt" else "clear")

def width():
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 100

# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------

BANNER = f"""
{RED}{BOLD}
  ██████╗ ██████╗  ███████╗
  ██╔══██╗██╔══██╗ ██╔════╝
  ██████╔╝██║  ██║ ███████╗
  ██╔══██╗██║  ██║ ╚════██║
  ██║  ██║██████╔╝ ███████║
  ╚═╝  ╚═╝╚═════╝  ╚══════╝{R}
{LGRAY}  Ransomware Detection System  —  Rule-Based Engine{R}
{GRAY}  ─────────────────────────────────────────────────{R}
"""

def print_banner():
    cls()
    print(BANNER)

# ---------------------------------------------------------------------------
# Startup info box
# ---------------------------------------------------------------------------

def print_info_box(dirs, auto_kill, log_file):
    w = min(width(), 72)
    bar = f"{GRAY}{'─' * w}{R}"
    print(bar)
    print(f"  {CYAN}◈ {WHITE}Watching{R}   {LGRAY}{', '.join(os.path.basename(d) for d in dirs)}{R}")
    kill_str = f"{GREEN}ENABLED{R}" if auto_kill else f"{YELLOW}DISABLED{R}"
    print(f"  {CYAN}◈ {WHITE}Auto-kill{R}  {kill_str}")
    print(f"  {CYAN}◈ {WHITE}Log file{R}   {LGRAY}{log_file}{R}")
    print(f"  {CYAN}◈ {WHITE}Engine{R}     {LGRAY}5 rules  ·  no AI  ·  no signatures{R}")
    print(bar)
    print()

# ---------------------------------------------------------------------------
# Stats bar (single line, refreshes in place)
# ---------------------------------------------------------------------------

_last_alert_count = 0

def format_stats_bar(stats, queue_sz, start_time):
    global _last_alert_count
    elapsed = int(time.time() - start_time)
    h, m, s = elapsed // 3600, (elapsed % 3600) // 60, elapsed % 60
    uptime = f"{h:02d}:{m:02d}:{s:02d}"

    ac = stats["alerts_raised"]
    alert_col = RED + BOLD if ac > _last_alert_count else (YELLOW if ac > 0 else GREEN)
    _last_alert_count = ac

    q_col = ORANGE if queue_sz > 50 else (YELLOW if queue_sz > 10 else GRAY)

    now = datetime.datetime.now().strftime("%H:%M:%S")

    bar = (
        f"{GRAY}[{WHITE}{now}{GRAY}]{R}  "
        f"{DIM}up {uptime}{R}    "
        f"{CYAN}events {WHITE}{stats['total_events']:>5}{R}    "
        f"{CYAN}activity {WHITE}{stats['mod_rate']:>4}{R}    "
        f"{CYAN}renames {WHITE}{stats['rename_rate']:>3}{R}    "
        f"{q_col}queue {queue_sz:>4}{R}    "
        f"{alert_col}🚨 alerts {ac}{R}"
    )
    return bar

# ---------------------------------------------------------------------------
# Alert box (printed when alert fires)
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {
    "HIGH":   RED + BOLD,
    "MEDIUM": ORANGE + BOLD,
    "LOW":    YELLOW,
}

RULE_ICONS = {
    "RAPID_FILE_ACTIVITY":  "⚡",
    "RAPID_RENAMES":        "🔄",
    "SUSPICIOUS_EXTENSION": "🎯",
    "HIGH_ENTROPY":         "🔐",
    "SUSPECT_PROCESS":      "🦠",
}

def print_alert_box(alert):
    sc  = SEVERITY_COLOR.get(alert.severity, WHITE + BOLD)
    ts  = datetime.datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
    w   = min(width() - 2, 74)
    pad = w - 2

    def row(content=""):
        visible = _ANSI_ESCAPE.sub('', content)
        spaces = pad - len(visible)
        return f"{GRAY}║{R}{content}{' ' * max(0, spaces)}{GRAY}║{R}"

    sep_top = f"{GRAY}╔{'═' * pad}╗{R}"
    sep_mid = f"{GRAY}╠{'═' * pad}╣{R}"
    sep_bot = f"{GRAY}╚{'═' * pad}╝{R}"

    proc  = alert.offending_process or "unknown"
    pid   = str(alert.offending_pid) if alert.offending_pid else "—"
    rules = ", ".join(alert.triggered_rules)

    print(f"\n{sep_top}")
    print(row(f"  {sc}🚨  RANSOMWARE DETECTED  [{alert.severity}]{R}  {GRAY}─{R}  {WHITE}{ts}{R}"))
    print(sep_mid)
    print(row(f"  {LGRAY}Process :{R}  {CYAN}{BOLD}{proc:<24}{R}  {LGRAY}PID :{R}  {WHITE}{pid}{R}"))
    print(row(f"  {LGRAY}Rules   :{R}  {YELLOW}{rules}{R}"))
    print(sep_mid)
    for rule, detail in alert.evidence.items():
        icon  = RULE_ICONS.get(rule, "•")
        short = detail[:pad - 8] if len(detail) > pad - 8 else detail
        print(row(f"  {icon}  {LGRAY}{rule:<22}{R}  {WHITE}{short}{R}"))
    print(sep_bot)

# ---------------------------------------------------------------------------
# Kill confirmation line
# ---------------------------------------------------------------------------

def print_kill_line(proc_name, pid, success):
    if success:
        print(f"  {GREEN}{BOLD}✅  Process '{proc_name}' (PID {pid}) terminated.{R}\n")
    else:
        print(f"  {YELLOW}⚠   Process '{proc_name}' (PID {pid}) already exited.{R}\n")

# ---------------------------------------------------------------------------
# Patch ResponseHandler to use our pretty UI
# ---------------------------------------------------------------------------

from response import ResponseHandler as _RH, _find_pid_by_file_activity

class PrettyResponseHandler(_RH):
    def handle(self, alert):
        threading.Thread(
            target=self._handle_async, args=(alert,), daemon=True
        ).start()

    def _handle_async(self, alert):
        import psutil

        if alert.offending_pid is None:
            pid, name = _find_pid_by_file_activity(config.WATCH_DIRS)
            if pid:
                alert.offending_pid     = pid
                alert.offending_process = name

        self._log_alert(alert)
        with _print_lock:
            sys.stdout.write("\n")   # step off the stats bar line before the box
            print_alert_box(alert)

        if not (config.AUTO_KILL_PROCESS and alert.offending_pid is not None):
            return

        # Hunt loop — kill the triggering process, then immediately look for any
        # remaining co-workers (handles multi-process attacks where killing the
        # coordinator leaves workers still running).
        killed_pids = set()
        target_pid  = alert.offending_pid

        for _ in range(10):           # cap at 10 kills per alert to avoid infinite loops
            if target_pid in killed_pids:
                break
            try:
                proc      = psutil.Process(target_pid)
                proc_name = proc.name()
                if proc_name.lower() in config.PROTECTED_PROCESSES:
                    break
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                logger.warning("Killed process %s (PID %d)", proc_name, target_pid)
                with _print_lock:
                    print_kill_line(proc_name, target_pid, True)
                killed_pids.add(target_pid)
            except psutil.NoSuchProcess:
                with _print_lock:
                    print_kill_line(alert.offending_process or "?", target_pid, False)
                killed_pids.add(target_pid)
            except psutil.AccessDenied:
                with _print_lock:
                    print(f"  {RED}❌  Cannot kill PID {target_pid}: permission denied.{R}\n")
                break
            except Exception as exc:
                logger.error("Kill error: %s", exc)
                break

            # Look for remaining suspects (co-workers) immediately after each kill
            time.sleep(0.3)
            next_pid, next_name = _find_pid_by_file_activity(config.WATCH_DIRS)
            if next_pid is None or next_pid in killed_pids:
                break
            target_pid = next_pid

# ---------------------------------------------------------------------------
# Main run loop
# ---------------------------------------------------------------------------

def run(auto_kill=True, quiet=False):
    enable_ansi()
    config.AUTO_KILL_PROCESS = auto_kill

    print_banner()
    print_info_box(config.WATCH_DIRS, auto_kill, config.LOG_FILE)

    print(f"  {YELLOW}⏳  Building file index — please wait…{R}")

    response = PrettyResponseHandler()
    detector = Detector(alert_callback=response.handle)
    monitor  = FileMonitor()

    # Immediate-kill path for known-bad EXEs — fires from WMI thread,
    # bypasses queue so kills work even when backlog is hundreds of events.
    def _immediate_suspect_kill(pid: int, name: str):
        import time as _time
        from detector import DetectionAlert as _DA
        alert = _DA(
            timestamp=_time.time(),
            triggered_rules=["SUSPECT_PROCESS"],
            offending_pid=pid,
            offending_process=name,
            evidence={"SUSPECT_PROCESS": f"Known malware EXE: {name}"},
            severity="HIGH",
        )
        response.handle(alert)

    monitor.immediate_alert_cb = _immediate_suspect_kill
    monitor.start()

    print(f"  {GREEN}{BOLD}✅  Ready — monitoring active.{R}\n")
    print(f"  {GRAY}Press Ctrl+C to stop.{R}\n")
    print(f"{GRAY}{'─' * min(width(), 72)}{R}")

    logger.info("Ransomware Detection System running.")

    stop_evt   = threading.Event()
    start_time = time.time()

    # Stats bar refresh thread
    def stats_loop():
        while not stop_evt.is_set():
            detector.refresh_stats()   # keep rate counters fresh even when queue is empty
            bar = format_stats_bar(detector.stats, monitor.queue_size, start_time)
            term_w = width()
            visible_len = len(_ANSI_ESCAPE.sub('', bar))
            if visible_len > term_w:
                bar = _truncate_ansi(bar, term_w)
                visible_len = term_w
            with _print_lock:
                sys.stdout.write(f"\r{bar}{' ' * (term_w - visible_len)}")
                sys.stdout.flush()
            time.sleep(1.0)
        sys.stdout.write("\n")
        sys.stdout.flush()

    if not quiet:
        threading.Thread(target=stats_loop, daemon=True).start()

    def shutdown(sig=None, frame=None):
        stop_evt.set()

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Main event loop — batch drain
    while not stop_evt.is_set():
        processed = 0
        while processed < 500:
            evt = monitor.get_event(timeout=0.01)
            if evt is None:
                break
            detector.process_event(evt)
            processed += 1
        if processed == 0:
            time.sleep(0.01)

    print(f"\n\n  {GRAY}Shutting down…{R}")
    logger.info("Shutting down …")
    monitor.stop()
    print(f"  {GREEN}Goodbye.{R}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-kill", action="store_true")
    parser.add_argument("--quiet",   action="store_true")
    args = parser.parse_args()
    setup_logging()
    run(auto_kill=not args.no_kill, quiet=args.quiet)

if __name__ == "__main__":
    main()