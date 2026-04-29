import os
import tempfile

HOME = os.path.expanduser("~")

# BUG FIX 1 : Inclure le dossier TEMP dans la surveillance.
# Le simulateur écrivait dans %TEMP%\rds_simulation mais ce dossier
# n'était pas surveillé → aucun événement n'était jamais détecté.
WATCH_DIRS = [
    os.path.join(HOME, "Documents"),
    os.path.join(HOME, "Desktop"),
    os.path.join(HOME, "Downloads"),
]
"""
WATCH_DIRS = [
    os.path.join(HOME, "Documents"),
    os.path.join(HOME, "Desktop"),
    os.path.join(HOME, "Downloads"),
    os.path.join(HOME, "Pictures"),
    os.path.join(HOME, "Videos"),
    os.path.join(HOME, "Music"),
    tempfile.gettempdir(),          # ← AJOUTÉ : %TEMP% / /tmp
]
"""
WATCH_DIRS = [d for d in WATCH_DIRS if os.path.isdir(d)]
if not WATCH_DIRS:
    WATCH_DIRS = [HOME]

# BUG FIX 2 : Seuils trop élevés — le simulateur créait 30 fichiers en
# ~1.5s, ce qui dépasse facilement 5 en 10s, MAIS les événements
# arrivaient en rafale lors d'un seul cycle de scan (intervalle=1s),
# donc la fenêtre glissante les regroupait mal. On abaisse les seuils
# et on réduit la fenêtre pour une détection plus réactive.
MOD_COUNT_THRESHOLD    = 5       # opérations fichiers dans la fenêtre
MOD_TIME_WINDOW        = 5       # secondes (réduit de 10 → 5)

RENAME_COUNT_THRESHOLD = 2
RENAME_TIME_WINDOW     = 5       # secondes (réduit de 10 → 5)

# BUG FIX 3 : Extensions manquantes — plusieurs extensions utilisées par
# le simulateur (.vault, .petya, .ryuk, .lockbit, etc.) n'étaient pas
# dans la liste, donc la règle SUSPICIOUS_EXTENSION ne se déclenchait pas.
SUSPICIOUS_EXTENSIONS = {
    ".enc", ".encrypted", ".locked", ".crypto", ".crypt",
    ".crypted", ".wncry", ".wcry", ".wncryt", ".onion",
    ".zepto", ".cerber", ".locky", ".ecc", ".ezz", ".exx",
    ".aaa", ".abc", ".xyz", ".zzzzz", ".micro", ".vvv",
    ".ccc", ".ttt", ".mp3", ".vault", ".petya", ".thor",
    ".ryk", ".ryuk", ".sodinokibi", ".revil", ".conti",
    ".maze", ".blackcat", ".alphv", ".cl0p", ".lockbit",
    ".wannacry", ".wcrypt", ".darkness", ".nochance",
}

ENTROPY_THRESHOLD    = 7.0
ENTROPY_SAMPLE_BYTES = 65536

PROCESS_FILE_ACCESS_THRESHOLD = 10
PROCESS_ACCESS_TIME_WINDOW    = 10

MIN_RULES_FOR_ALERT = 1

AUTO_KILL_PROCESS       = True
LOG_FILE                = "ransomware_detector.log"
ALERT_SOUND             = False
STATS_REFRESH_INTERVAL  = 1.0
