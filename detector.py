# =============================================================================
# detector.py — Rule-based ransomware detection engine (NO AI / NO ML)
# =============================================================================

import os
import math
import time
import logging
import collections
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import config
from monitor import FileEvent

logger = logging.getLogger(__name__)


@dataclass
class DetectionAlert:
    timestamp: float
    triggered_rules: List[str]
    offending_pid: Optional[int]
    offending_process: Optional[str]
    evidence: Dict
    severity: str = "HIGH"


class EventWindow:
    def __init__(self, window_seconds: float):
        self._window = window_seconds
        self._items: collections.deque = collections.deque()

    def add(self, value):
        self._items.append((time.time(), value))
        self._expire()

    def _expire(self):
        cutoff = time.time() - self._window
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()

    def values(self):
        self._expire()
        return [v for _, v in self._items]

    def count(self):
        self._expire()
        return len(self._items)

    def clear(self):
        self._items.clear()


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path: str, sample_bytes: int = config.ENTROPY_SAMPLE_BYTES) -> float:
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_bytes)
        return _shannon_entropy(data)
    except OSError:
        return 0.0


class Detector:
    def __init__(self, alert_callback=None):
        self._alert_cb = alert_callback
        self._global_mod_window    = EventWindow(config.MOD_TIME_WINDOW)
        self._global_rename_window = EventWindow(config.RENAME_TIME_WINDOW)
        self._alerted_pids: Dict   = {}
        self._alert_cooldown       = 5.0    # BUG FIX 6 : reduit de 30s a 5s

        self.stats = {
            "total_events":  0,
            "mod_rate":      0,
            "rename_rate":   0,
            "alerts_raised": 0,
            "last_alert":    None,
        }

    def process_event(self, evt: FileEvent):
        self.stats["total_events"] += 1

        # All file activity counts as a modification for rate tracking
        if evt.event_type in ("created", "modified", "deleted"):
            self._global_mod_window.add(evt.src_path)
        elif evt.event_type == "renamed":
            self._global_rename_window.add(evt.src_path)

        self.stats["mod_rate"]    = self._global_mod_window.count()
        self.stats["rename_rate"] = self._global_rename_window.count()

        triggered, evidence = self._evaluate_rules(evt)

        if triggered:
            logger.debug("Rules triggered: %s for %s", triggered, evt.src_path)

        if len(triggered) >= config.MIN_RULES_FOR_ALERT:
            self._maybe_raise_alert(evt, triggered, evidence)

    def _evaluate_rules(self, evt: FileEvent) -> Tuple[List[str], Dict]:
        triggered = []
        evidence  = {}

        # Rule 1 — Rapid file activity (create + modify + delete all count)
        gmod = self._global_mod_window.count()
        if gmod >= config.MOD_COUNT_THRESHOLD:
            triggered.append("RAPID_FILE_ACTIVITY")
            evidence["RAPID_FILE_ACTIVITY"] = (
                f"{gmod} file operations in {config.MOD_TIME_WINDOW}s window"
            )

        # Rule 2 — Rapid renames
        gren = self._global_rename_window.count()
        if gren >= config.RENAME_COUNT_THRESHOLD:
            triggered.append("RAPID_RENAMES")
            evidence["RAPID_RENAMES"] = (
                f"{gren} renames in {config.RENAME_TIME_WINDOW}s window"
            )

        # Rule 3 — Suspicious extension (check both src and dest)
        for check_path in [evt.src_path, evt.dest_path]:
            if check_path:
                ext = os.path.splitext(check_path)[1].lower()
                if ext in config.SUSPICIOUS_EXTENSIONS:
                    triggered.append("SUSPICIOUS_EXTENSION")
                    evidence["SUSPICIOUS_EXTENSION"] = (
                        f"Suspicious extension '{ext}' → {os.path.basename(check_path)}"
                    )
                    break

        # Rule 4 — High entropy (encrypted content)
        target = evt.dest_path or evt.src_path
        if evt.event_type in ("created", "modified") and target:
            ext = os.path.splitext(target)[1].lower()
            # Only check files likely to be data files, skip tiny files
            size = evt.file_size or 0
            if size > 512 or ext in config.SUSPICIOUS_EXTENSIONS:
                entropy = file_entropy(target)
                if entropy >= config.ENTROPY_THRESHOLD:
                    triggered.append("HIGH_ENTROPY")
                    evidence["HIGH_ENTROPY"] = (
                        f"Entropy {entropy:.3f} >= {config.ENTROPY_THRESHOLD} "
                        f"in {os.path.basename(target)}"
                    )

        return triggered, evidence

    def _maybe_raise_alert(self, evt: FileEvent, triggered: List[str], evidence: Dict):
        # BUG FIX 6 : La cle de cooldown etait les 50 premiers chars du chemin.
        # Chaque fichier ayant un chemin unique, le cooldown ne bloquait jamais.
        # On utilise desormais les regles declenchees comme cle (meme attaque
        # = memes regles) avec un cooldown court de 5s pour eviter le spam
        # sans masquer les vraies attaques consecutives.
        now = time.time()
        key = tuple(sorted(triggered))
        last = self._alerted_pids.get(key, 0)
        if now - last < self._alert_cooldown:
            return
        self._alerted_pids[key] = now

        alert = DetectionAlert(
            timestamp=now,
            triggered_rules=triggered,
            offending_pid=evt.pid,
            offending_process=evt.process_name or "unknown",
            evidence=evidence,
            severity="HIGH" if len(triggered) >= 2 else "MEDIUM",
        )

        self.stats["alerts_raised"] += 1
        self.stats["last_alert"] = alert

        logger.warning(
            "ALERT — Rules: %s | File: %s",
            ", ".join(triggered), os.path.basename(evt.src_path)
        )

        if self._alert_cb:
            self._alert_cb(alert)
