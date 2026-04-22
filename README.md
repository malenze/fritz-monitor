# FRITZ!Box Network Activity Monitor for macOS

Polls your FRITZ!Box router logs via TR-064 SOAP, detects suspicious network events, and delivers native macOS notifications.

---

## Prerequisites

### 1. Install Miniconda

Download and install Miniconda for macOS from [conda.io](https://docs.conda.io/en/latest/miniconda.html), or via Homebrew:

```bash
brew install --cask miniconda
```

Initialize the shell integration:

```bash
conda init zsh   # or: conda init bash
```

Restart your terminal, then create and activate a dedicated environment:

```bash
conda activate base
```

### 2. Install Python Dependencies

```bash
pip install requests schedule defusedxml
```

| Package | Purpose |
|---|---|
| `requests` | HTTP/SOAP calls to the FRITZ!Box TR-064 interface |
| `schedule` | Periodic polling loop |
| `defusedxml` | Safe XML parsing (guards against XML bomb attacks) |

---

## Setup

### Run the interactive setup wizard

```bash
python3 macos_setup.py
```

The wizard walks through four steps:

1. **Prerequisites check** — verifies Python and required packages, creates `~/fritz-monitor/` as the working directory.
2. **FRITZ!Box configuration** — prompts for the router's hostname/IP and admin credentials. The hostname and username are saved to `~/fritz-monitor/fritz_config.json`; the password is stored securely in the **macOS Keychain** (service `fritz-monitor`, account `fritz_password`) and never written to disk in plain text.
3. **Knowledge base initialisation** — creates `~/fritz-monitor/network_knowledge_base.json` with default whitelisted IPs (Google/Cloudflare DNS, FRITZ!Box gateway) and optionally lets you register your known devices interactively.
4. **LaunchAgent** — writes and loads `~/Library/LaunchAgents/com.fritz-monitor.plist` so the monitor starts automatically at login and restarts if it exits unexpectedly.

---

## LaunchAgent Management

The plist is located at:

```
~/Library/LaunchAgents/com.fritz-monitor.plist
```

### Load (start the monitor)

```bash
launchctl load ~/Library/LaunchAgents/com.fritz-monitor.plist
```

### Unload (stop the monitor)

```bash
launchctl unload ~/Library/LaunchAgents/com.fritz-monitor.plist
```

### Check whether it is running

```bash
launchctl list | grep fritz-monitor
```

A running agent shows a PID in the first column:

```
1234  0  com.fritz-monitor     ← running (PID 1234)
-     0  com.fritz-monitor     ← loaded but not running
```

You can also watch the live log:

```bash
tail -f ~/fritz-monitor/fritz_monitor.log
```

---

## Knowledge Base

The knowledge base (`~/fritz-monitor/network_knowledge_base.json`) stores:

| Key | Purpose |
|---|---|
| `known_devices` | MAC → IP/hostname mapping; unknown MACs trigger an alert |
| `whitelisted_ips` | IPs that never trigger unknown-device alerts |
| `suspicious_ips` | IPs manually flagged for reference |
| `baseline_traffic` | Source→destination traffic patterns (reserved for future use) |

### Option A — Interactive manager

```bash
python3 kb_manager.py
```

Menu options:

```
1. Add known device
2. List known devices
3. Add baseline traffic pattern
4. List baseline traffic
5. Whitelist IP address
6. List whitelisted IPs
7. View suspicious IPs
8. Flag IP as suspicious
9. Auto-populate from current network (ARP scan)
0. Exit
```

### Option B — Edit the JSON file directly

Open `~/fritz-monitor/network_knowledge_base.json` in any text editor. Example structure:

```json
{
  "known_devices": {
    "aa:bb:cc:dd:ee:ff": {
      "mac": "AA:BB:CC:DD:EE:FF",
      "ip": "192.168.178.20",
      "hostname": "My MacBook Pro",
      "type": "laptop",
      "first_seen": "2026-04-22T10:00:00",
      "last_seen": "2026-04-22T10:00:00"
    },
    "11:22:33:44:55:66": {
      "mac": "11:22:33:44:55:66",
      "ip": "192.168.178.21",
      "hostname": "iPhone 15",
      "type": "smartphone",
      "first_seen": "2026-04-22T10:00:00",
      "last_seen": "2026-04-22T10:00:00"
    }
  },
  "whitelisted_ips": [
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "192.168.178.1",
    "224.0.0.1",
    "255.255.255.255"
  ],
  "suspicious_ips": [],
  "baseline_traffic": {},
  "metadata": {
    "created": "2026-04-22T10:00:00",
    "last_updated": "2026-04-22T10:00:00"
  }
}
```

**Notes:**
- `known_devices` keys must be lowercase MAC addresses (colons as separators).
- `whitelisted_ips` accepts both IPv4 and IPv6 addresses.
- After editing the file manually, no restart is needed — the knowledge base is re-read on each monitoring cycle.

---

## Extending the Log Analyser Filters

The keyword lists live in `fritz_monitor_macos.py` inside the `LogAnalyzer` class (around line 552). There are two lists, checked in order:

1. **`CRITICAL_KEYWORDS`** — match triggers a modal dialog that the user must dismiss.
2. **`SUSPICIOUS_KEYWORDS`** — match triggers a standard macOS notification with an Alarm sound. Within this category, messages containing `gescheitert` or `verweigert` are graded `high`; everything else is `medium`.

The check is a simple case-insensitive substring match against the full log message, so multi-word phrases (e.g. `'falsches kennwort'`) work as exact-phrase filters.

To add a new keyword, open `fritz_monitor_macos.py` and append to the relevant list:

```python
SUSPICIOUS_KEYWORDS = [
    'gescheitert',
    ...
    'mein-neues-keyword',   # ← add here
]
```

To remove a keyword, simply delete its line.

### Current keyword tables

All keywords are sourced from the official FRITZ!Box 6670 Cable event message list.

#### Suspicious keywords

| Keyword | Matches |
|---|---|
| `gescheitert` | Any failed login / connection / delivery |
| `fehlgeschlagen` | Protocol / service / firmware failures (PPP, IPv6, Powerline, update) |
| `störquelle` | WLAN interference source detected (possible jamming) |
| `wlan-autokanal` | WLAN auto-channel change (causes device reconnections) |
| `dns-störung` | DNS disturbance / possible DNS hijacking indicator |
| `loopback gefunden` | PPP routing loop detected |
| `schwerwiegender fehler` | Severe system error (e.g. factory reset triggered on bad import) |
| `verweigert` | Access or login denied by remote system |

#### Critical keywords

| Keyword | Matches |
|---|---|
| `falsches kennwort` | Brute-force attempt on admin UI or FTP |
| `kennwort falsch` | Brute-force attempt on SMB share (alternate phrasing) |
| `ungültige sitzungskennung` | Session token attack / session hijacking attempt |
| `ungültiger wlan-schlüssel` | WiFi WPA key brute force |
| `authentifizierungsfehler` | Authentication failure at FRITZ! mesh product |
| `kennwort abgelehnt` | Internet access password attempt rejected |
| `untypisch` | Anomalous call usage / toll fraud indicator |
| `netzwerkschleife` | Network loop detected (possible DoS) |

---

## Running Manually

```bash
# Run the monitor directly (foreground, logs to stdout)
python3 fritz_monitor_macos.py

# Interactive setup wizard
python3 macos_setup.py

# Interactive knowledge base manager
python3 kb_manager.py

# Validate configuration
python3 config.py

# Syntax check
python3 -c "import py_compile; py_compile.compile('fritz_monitor_macos.py', doraise=True)"
```

## Runtime Files

| File | Location | Purpose |
|---|---|---|
| `fritz_config.json` | `~/fritz-monitor/` | FRITZ!Box hostname + username (no password) |
| `network_knowledge_base.json` | `~/fritz-monitor/` | Device registry and IP lists |
| `fritz_monitor.log` | `~/fritz-monitor/` | Application log |
| `fritz_monitor.error.log` | `~/fritz-monitor/` | stderr from the LaunchAgent |
| `com.fritz-monitor.plist` | `~/Library/LaunchAgents/` | macOS auto-start configuration |

---

## License & Maintenance

This project is released under the [MIT License](LICENSE).

This is a personal tool released as-is. Maintenance will be minimal — issues and pull requests may not be actively monitored. That said, everyone is welcome to fork the repository and adapt it freely to their own needs. The MIT license gives you full permission to use, modify, and redistribute the code, with or without attribution.

