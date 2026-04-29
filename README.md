# 🛡 Ransomware Detection System (Rule-Based, No AI)

A lightweight, real-time ransomware detection and prevention tool written in Python.
It uses **behavioural rules** — no machine learning or AI — to identify and stop ransomware attacks.

---

## 📁 Project Structure

```
ransomware_detector/
├── config.py               ← All thresholds & settings (edit me!)
├── monitor.py              ← Real-time filesystem watcher (watchdog)
├── detector.py             ← Rule-based detection engine (5 rules)
├── response.py             ← Alert, kill process, write logs
├── main.py                 ← Entry point + live CLI dashboard
├── simulate_ransomware.py  ← Safe test script (no real files touched)
├── requirements.txt
└── README.md
```

---

## ⚙ Requirements

- Python 3.8+
- pip packages: `watchdog`, `psutil`

---

## 🚀 Installation & First Run

```bash
# 1. Navigate to the project folder
cd ransomware_detector

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the detector (Ctrl+C to stop)
python main.py
```

### Command-line options

| Flag | Description |
|------|-------------|
| `--no-kill` | Detect only, do NOT kill suspicious processes |
| `--quiet` | Suppress the live stats dashboard |

```bash
python main.py --no-kill          # safe test mode
python main.py --no-kill --quiet  # minimal output
```

---

## 🧪 Testing with the Simulator

**Open two terminals.**

**Terminal 1** — start the detector:
```bash
python main.py --no-kill
```

**Terminal 2** — run one of the simulations:

```bash
# Trigger Rule 1: rapid file modifications
python simulate_ransomware.py --mode rapid_mods

# Trigger Rules 2 + 3: suspicious extension renames
python simulate_ransomware.py --mode suspicious_ext

# Trigger Rule 4: high-entropy (encrypted) files
python simulate_ransomware.py --mode encrypted

# Trigger ALL rules simultaneously
python simulate_ransomware.py --mode full
```

The detector should print a red alert box in Terminal 1 within seconds.

---

## 🔍 The 5 Detection Rules

| # | Rule | Threshold |
|---|------|-----------|
| 1 | Rapid global modifications | > 20 files modified in 5 s |
| 2 | Rapid global renames | > 5 renames in 5 s |
| 3 | Suspicious file extension | `.enc`, `.locked`, `.encrypted`, … (40+ patterns) |
| 4 | High file entropy | Shannon entropy ≥ 7.2 (encrypted content) |
| 5 | Process mass file access | 1 process touches > 30 files in 10 s |

An alert is raised when **≥ 2 rules** trigger simultaneously (configurable).

---

## 🎛 Tuning Thresholds

Open `config.py` and adjust any value:

```python
MOD_COUNT_THRESHOLD   = 20    # ← lower = more sensitive
MOD_TIME_WINDOW       = 5
RENAME_COUNT_THRESHOLD = 5
ENTROPY_THRESHOLD     = 7.2
MIN_RULES_FOR_ALERT   = 2     # ← raise to reduce false positives
AUTO_KILL_PROCESS     = True  # ← set False for passive monitoring
```

---

## 📄 Log File

All events are written to `ransomware_detector.log` in the current directory.
The log contains full timestamps, rule names, process info, and evidence strings.

---

## 🔒 Response Playbook (on detection)

1. **Log** the alert with full evidence to console + log file
2. **Print** a red alert box in the terminal
3. **Kill** the offending process (`SIGTERM` → `SIGKILL` after 3 s)
4. *(optional)* Sound a beep (set `ALERT_SOUND = True` in config.py)

> Protected system processes (`systemd`, `bash`, `sshd`, etc.) are never killed.

---

## 💡 Suggestions for Improvement

- **Shadow copies**: automatically create a VSS snapshot before any reaction
- **Network isolation**: call `iptables` or Windows Firewall API to block the PID
- **Email / webhook alerts**: integrate SMTP or Slack webhook for remote notification
- **Whitelist trusted processes**: skip rules for known-good processes (e.g., backup software)
- **Journalling**: track which files were encrypted so they can be restored from backup
- **GUI dashboard**: replace the CLI with a Tkinter or web-based interface
- **Scheduled integrity checks**: hourly hash scan of critical directories
