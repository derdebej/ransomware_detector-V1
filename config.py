import os

HOME        = os.path.expanduser("~")
_SCRIPT_DIR = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))

WATCH_DIRS = [
    os.path.join(HOME, "Documents"),
    os.path.join(HOME, "Desktop"),
    os.path.join(HOME, "Downloads"),
]
WATCH_DIRS = [d for d in WATCH_DIRS if os.path.isdir(d)]
if not WATCH_DIRS:
    WATCH_DIRS = [HOME]

# Events from these directories are silently ignored (the project folder contains
# the rotating log file and __pycache__ writes which would cause false positives).
EXCLUDE_DIRS = [_SCRIPT_DIR]

MOD_COUNT_THRESHOLD    = 5
MOD_TIME_WINDOW        = 5

RENAME_COUNT_THRESHOLD = 2
RENAME_TIME_WINDOW     = 5

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

MIN_RULES_FOR_ALERT = 1

AUTO_KILL_PROCESS      = True
LOG_FILE               = "ransomware_detector.log"
ALERT_SOUND            = False
STATS_REFRESH_INTERVAL = 1.0

# Processes that must never be killed regardless of suspicion.
PROTECTED_PROCESSES = {
    "systemd", "init", "kthreadd", "sshd", "bash",
    "python", "python3", "explorer.exe", "winlogon.exe",
    "services.exe", "lsass.exe",
}

# Process EXE names that are immediately flagged as suspect (compiled simulators).
SUSPECT_PROCESS_NAMES = {
    "ransomware_sim.exe", "simulate_ransomware.exe",
    "sim_stealth.exe", "sim_inplace.exe",
    "sim_multiprocess.exe", "sim_burst.exe",
    "cryptor.exe", "encryptor.exe",
}