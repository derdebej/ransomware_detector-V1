import os, sys, time, queue, logging, threading
from dataclasses import dataclass, field
from typing import Optional, Dict
import config

logger = logging.getLogger(__name__)

@dataclass
class FileEvent:
    event_type: str
    src_path: str
    dest_path: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    pid: Optional[int] = None
    process_name: Optional[str] = None
    file_size: Optional[int] = None

class DirectoryScanner:
    def __init__(self, path: str, event_queue: queue.Queue, interval: float = 0.5):
        # BUG FIX 4 : Intervalle reduit de 1.0s a 0.5s.
        # A 1s, les 30 fichiers du simulateur arrivaient en 1-2 gros cycles,
        # tous avec des timestamps quasi-identiques. La fenetre glissante les
        # comptait en une seule impulsion puis retombait a 0 -> seuil jamais atteint.
        self._path      = path
        self._queue     = event_queue
        self._interval  = interval
        # BUG FIX 5 : Le snapshot ne stockait que mtime, pas la taille.
        # Les renommages (doc.txt -> doc.locked) generaient "deleted"+"created"
        # mais jamais "renamed" -> RAPID_RENAMES ne se declenchait jamais.
        # On stocke maintenant (mtime, size) et on detecte les renommages.
        self._snapshot: Dict[str, tuple] = {}   # path -> (mtime, size)
        self._ready     = threading.Event()
        self._stop_evt  = threading.Event()
        self._thread    = threading.Thread(
            target=self._run, daemon=True,
            name=f"scanner-{os.path.basename(path)}"
        )

    def start(self):
        self._thread.start()
        self._ready.wait(timeout=30)

    def stop(self):
        self._stop_evt.set()

    def _take_snapshot(self) -> Dict[str, tuple]:
        result = {}
        try:
            for root, dirs, files in os.walk(self._path):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for fname in files:
                    fp = os.path.join(root, fname)
                    try:
                        st = os.stat(fp)
                        result[fp] = (st.st_mtime, st.st_size)
                    except OSError:
                        pass
        except OSError:
            pass
        return result

    def _push(self, evt: FileEvent):
        try:
            self._queue.put_nowait(evt)
        except queue.Full:
            pass

    def _run(self):
        self._snapshot = self._take_snapshot()
        logger.debug("Scanner ready: %s (%d files)", self._path, len(self._snapshot))
        self._ready.set()

        while not self._stop_evt.is_set():
            time.sleep(self._interval)
            try:
                self._check()
            except Exception as exc:
                logger.debug("Scanner error: %s", exc)

    def _check(self):
        current  = self._take_snapshot()
        prev_set = set(self._snapshot)
        cur_set  = set(current)

        new_paths     = set(cur_set - prev_set)
        removed_paths = set(prev_set - cur_set)

        # Detecter les renommages (fichier disparu + fichier de meme taille apparu)
        removed_by_size = {}
        for rp in removed_paths:
            sz = self._snapshot[rp][1]
            rdir = os.path.dirname(rp)
            removed_by_size[(rdir, sz)] = rp

        rename_pairs = {}
        for np in list(new_paths):
            sz = current[np][1]
            ndir = os.path.dirname(np)
            key = (ndir, sz)
            if key in removed_by_size and sz > 0:
                old = removed_by_size[key]
                rename_pairs[old] = np
                new_paths.discard(np)
                removed_paths.discard(old)

        for old_path, new_path in rename_pairs.items():
            self._push(FileEvent(
                event_type="renamed",
                src_path=old_path,
                dest_path=new_path,
                file_size=current[new_path][1],
            ))

        for path in new_paths:
            self._push(FileEvent(event_type="created", src_path=path,
                                 file_size=self._safe_size(path)))

        for path in removed_paths:
            self._push(FileEvent(event_type="deleted", src_path=path))

        for path in cur_set & prev_set:
            if current[path][0] != self._snapshot[path][0]:
                self._push(FileEvent(event_type="modified", src_path=path,
                                     file_size=self._safe_size(path)))

        self._snapshot = current

    @staticmethod
    def _safe_size(path):
        try:
            return os.path.getsize(path)
        except OSError:
            return None

class FileMonitor:
    def __init__(self):
        self._queue    = queue.Queue(maxsize=50_000)
        self._scanners = []
        self._running  = False

    def start(self):
        if self._running:
            return
        for directory in config.WATCH_DIRS:
            s = DirectoryScanner(directory, self._queue, interval=0.5)
            s.start()
            self._scanners.append(s)
            logger.info("Monitoring: %s (%d files)", directory, len(s._snapshot))
        self._running = True
        logger.info("FileMonitor started (%d directories)", len(self._scanners))

    def stop(self):
        for s in self._scanners:
            s.stop()
        self._running = False
        logger.info("FileMonitor stopped.")

    def get_event(self, timeout=0.5):
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def is_running(self): return self._running

    @property
    def queue_size(self): return self._queue.qsize()
