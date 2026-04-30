import os, time, queue, logging, threading, collections
from dataclasses import dataclass, field
from typing import Optional

import psutil
import wmi
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import config

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# FileEvent — unchanged so detector.py / response.py stay compatible
# ---------------------------------------------------------------------------

@dataclass
class FileEvent:
    event_type:   str
    src_path:     str
    dest_path:    Optional[str]  = None
    timestamp:    float          = field(default_factory=time.time)
    pid:          Optional[int]  = None
    process_name: Optional[str]  = None
    file_size:    Optional[int]  = None


def _safe_size(path: str) -> Optional[int]:
    try:
        return os.path.getsize(path)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# ProcessTracker — watches for new processes via WMI and tracks which ones
# are writing to watched directories using psutil open files
# ---------------------------------------------------------------------------

class ProcessTracker:
    """
    Maintains a live registry of suspicious processes:
      - Watches for new process creation via WMI
      - For each new process, checks if it has files open in watched dirs
      - Provides fast PID lookup by file path
    """

    def __init__(self, watch_dirs):
        self._watch_dirs  = [os.path.normpath(d).lower() for d in watch_dirs]
        # path (lower) -> (pid, name)
        self._path_to_proc: dict = {}
        self._lock        = threading.Lock()
        self._stop_evt    = threading.Event()
        self._on_suspect  = None   # optional callback(pid, name) for known-bad EXEs
        self._wmi_thread  = threading.Thread(
            target=self._wmi_loop, daemon=True, name="wmi-tracker"
        )
        self._scan_thread = threading.Thread(
            target=self._scan_loop, daemon=True, name="proc-scanner"
        )

    def start(self):
        # Initial scan of all running processes
        self._full_scan()
        self._wmi_thread.start()
        self._scan_thread.start()
        logger.info("ProcessTracker started.")

    def stop(self):
        self._stop_evt.set()

    def get_pid_for_path(self, path: str):
        """Fast O(1) lookup — returns (pid, name) or (None, None)."""
        key = os.path.normpath(path).lower()
        with self._lock:
            return self._path_to_proc.get(key, (None, None))

    def _is_watched(self, path: str) -> bool:
        p = os.path.normpath(path).lower()
        return any(p.startswith(d) for d in self._watch_dirs)

    def _register_process(self, proc):
        """Scan a single process's open files and register watched ones."""
        try:
            pid  = proc.pid
            name = proc.name()
            for f in (proc.open_files() or []):
                if self._is_watched(f.path):
                    key = os.path.normpath(f.path).lower()
                    with self._lock:
                        self._path_to_proc[key] = (pid, name)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception as e:
            logger.debug("ProcessTracker._register_process error: %s", e)

    def _full_scan(self):
        """Scan all running processes — called once at startup."""
        for proc in psutil.process_iter(['pid', 'name']):
            self._register_process(proc)
        logger.debug("ProcessTracker full scan complete (%d entries).",
                     len(self._path_to_proc))

    def _scan_loop(self):
        """Re-scan all processes every 2s to catch any we missed."""
        while not self._stop_evt.is_set():
            self._full_scan()
            self._stop_evt.wait(timeout=2.0)

    def _quick_register(self, pid: int):
        """2 rapid re-registrations for every new process (100 ms apart).
        Ensures _path_to_proc is populated within 200 ms for any EXE that
        opens watched-dir files, regardless of whether it is a known suspect."""
        for _ in range(2):
            if self._stop_evt.is_set():
                break
            time.sleep(0.15)
            try:
                self._register_process(psutil.Process(pid))
            except psutil.NoSuchProcess:
                break

    def _aggressive_register(self, pid: int):
        """10 re-registrations for confirmed-suspect processes (100 ms apart, 1 s total)."""
        for _ in range(10):
            if self._stop_evt.is_set():
                break
            time.sleep(0.1)
            try:
                self._register_process(psutil.Process(pid))
            except psutil.NoSuchProcess:
                break

    def _wmi_loop(self):
        try:
            import pythoncom
            pythoncom.CoInitialize()
            w = wmi.WMI()
            watcher = w.Win32_ProcessStartTrace.watch_for()
            while not self._stop_evt.is_set():
                try:
                    event = watcher(timeout_ms=1000)
                    if event:
                        pid = event.ProcessID
                        time.sleep(0.05)
                        try:
                            proc = psutil.Process(pid)
                            name = proc.name()
                            self._register_process(proc)
                            logger.debug("WMI: new process %s (PID %d) registered.", name, pid)

                            # Quick re-registration for ALL new processes so that
                            # _path_to_proc is populated even for EXEs not in
                            # SUSPECT_PROCESS_NAMES.
                            threading.Thread(
                                target=self._quick_register,
                                args=(pid,),
                                daemon=True
                            ).start()

                            if name.lower() in config.SUSPECT_PROCESS_NAMES:
                                logger.info("WMI: SUSPECT EXE — %s (PID %d)", name, pid)
                                if self._on_suspect:
                                    self._on_suspect(pid, name)
                                threading.Thread(
                                    target=self._aggressive_register,
                                    args=(pid,),
                                    daemon=True
                                ).start()
                        except psutil.NoSuchProcess:
                            pass
                except wmi.x_wmi_timed_out:
                    pass
                except Exception as e:
                    logger.debug("WMI watcher error: %s", e)
        except Exception as e:
            logger.warning("WMI loop failed: %s", e)
        finally:
            try:
                pythoncom.CoUninitialize()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Watchdog handler — zero blocking on the watchdog thread
# ---------------------------------------------------------------------------

class _Handler(FileSystemEventHandler):
    def __init__(self, event_queue: queue.Queue, tracker: ProcessTracker):
        super().__init__()
        self._queue   = event_queue
        self._tracker = tracker

    def _push(self, evt: FileEvent):
        # Ignore events from excluded directories (e.g. the project folder itself)
        if evt.src_path:
            path = os.path.normpath(evt.src_path)
            for excl in config.EXCLUDE_DIRS:
                if path.startswith(excl):
                    return
        try:
            self._queue.put_nowait(evt)
        except queue.Full:
            logger.warning("Event queue full — event dropped.")

    def _make_event(self, event_type, src_path, dest_path=None):
        """Build a FileEvent with PID looked up from tracker (O(1), no blocking)."""
        path_for_lookup = dest_path or src_path
        pid, pname = self._tracker.get_pid_for_path(path_for_lookup)
        return FileEvent(
            event_type=event_type,
            src_path=src_path,
            dest_path=dest_path,
            file_size=_safe_size(path_for_lookup),
            pid=pid,
            process_name=pname,
        )

    def on_created(self, event):
        if event.is_directory:
            return
        self._push(self._make_event("created", event.src_path))

    def on_modified(self, event):
        if event.is_directory:
            return
        self._push(self._make_event("modified", event.src_path))

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._push(FileEvent(event_type="deleted", src_path=event.src_path))

    def on_moved(self, event):
        if event.is_directory:
            return
        dest = event.dest_path
        self._push(self._make_event("renamed", event.src_path, dest_path=dest))
        # Synthetic modified so entropy/extension rules fire on .enc/.locked
        self._push(self._make_event("modified", dest))


# ---------------------------------------------------------------------------
# FileMonitor — same public API, drop-in replacement
# ---------------------------------------------------------------------------

class FileMonitor:
    def __init__(self):
        self._queue    = queue.Queue(maxsize=50_000)
        self._tracker  = ProcessTracker(config.WATCH_DIRS)
        self._tracker._on_suspect = self._on_suspect_process
        self._observer = Observer()
        self._running  = False
        # Set by main.py — called directly from WMI thread, bypasses queue backlog
        self.immediate_alert_cb = None

    def _on_suspect_process(self, pid: int, name: str):
        """Called from WMI thread when a known-bad EXE is detected.

        Always injects a synthetic event for the detector pipeline.
        Also fires immediate_alert_cb directly so kills happen even when
        the queue is saturated (queue-bypass path).
        """
        evt = FileEvent(
            event_type="process_detected",
            src_path="",
            pid=pid,
            process_name=name,
        )
        try:
            self._queue.put_nowait(evt)
        except queue.Full:
            pass

        if self.immediate_alert_cb:
            threading.Thread(
                target=self.immediate_alert_cb,
                args=(pid, name),
                daemon=True,
            ).start()

    def start(self):
        if self._running:
            return

        # Start process tracker first so PID data is ready before events arrive
        self._tracker.start()

        handler = _Handler(self._queue, self._tracker)
        for directory in config.WATCH_DIRS:
            self._observer.schedule(handler, directory, recursive=True)
            logger.info("Monitoring: %s", directory)

        self._observer.start()
        self._running = True
        logger.info("FileMonitor started (%d directories)", len(config.WATCH_DIRS))

    def stop(self):
        self._tracker.stop()
        self._observer.stop()
        self._observer.join(timeout=3)
        self._running = False
        logger.info("FileMonitor stopped.")

    def get_event(self, timeout=0.5) -> Optional[FileEvent]:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def is_running(self):
        return self._running

    @property
    def queue_size(self):
        return self._queue.qsize()