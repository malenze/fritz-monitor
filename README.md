# FRITZ!Box Network Activity Monitor for macOS

Polls your FRITZ!Box router logs via TR-064 SOAP, detects suspicious network events, and delivers native macOS notifications.

---

## Prerequisites

### 1. Install Python 3.10 or newer

macOS ships an older Python, so install a current one with Homebrew:

```bash
brew install python
```

The project runs in its own virtual environment (`venv/` inside the project folder), so no other Python tooling is needed.

### 2. Python dependencies

The setup wizard installs these into the virtual environment for you (see below). The pinned versions are declared in `pyproject.toml`, and `requirements.txt` carries the SHA256 hash of every package.

| Package | Purpose |
| --- | --- |
| `requests` | HTTP and SOAP calls to the FRITZ!Box TR-064 interface |
| `schedule` | Periodic polling loop |
| `defusedxml` | Safe XML parsing (guards against XML bomb attacks) |

To create the environment by hand instead of using the wizard:

```bash
python3.14 -m venv venv
venv/bin/pip install --require-hashes -r requirements.txt
```

The `--require-hashes` flag makes pip refuse any package whose hash does not match `requirements.txt`. After changing a dependency in `pyproject.toml`, regenerate the lock file with:

```bash
uv pip compile pyproject.toml --generate-hashes --python-version 3.10 -o requirements.txt
```

---

## Setup

### Run the interactive setup wizard

Run everything from the folder you checked the project out to:

```bash
python3 macos_setup.py
```

Nothing is copied anywhere else. The wizard uses only the Python standard library, so it runs before any packages are installed. If `venv/` already exists, it restarts itself under that interpreter. Otherwise it creates the venv in step 2 and then restarts itself under the new interpreter for the remaining steps. It walks through seven steps:

1. **Prerequisites check**: confirms the project files are present and finds a Python 3.10 or newer. It uses the running interpreter if suitable, otherwise the newest `python3.x` on your `PATH`.
2. **Python environment**: creates `venv/` in the project folder and installs the dependencies with `pip install --require-hashes`. The wizard stops if the install fails.
3. **FRITZ!Box configuration**: prompts for the router's hostname or IP and the admin username, tests the connection, and saves both to `fritz_config.json` (no password).
4. **FRITZ!Box password**: checks whether the **macOS Keychain** already holds the password (service `fritz-monitor`, account `fritz_password`). If it does, the wizard asks before overwriting. Otherwise `security` prompts for the password with hidden input, so it never appears in the process list or on disk.
5. **Log directory**: asks where to write log files. The default is `logs/` in the project folder (ignored by git). Any other directory works, and the choice is saved as `log_dir` in `fritz_config.json`.
6. **Knowledge base**: creates `network_knowledge_base.json` with default whitelisted IPs if it does not exist yet (an existing one is never overwritten), then starts `kb_manager.py` so you can register your known devices. Choose option 0 to return to the wizard.
7. **LaunchAgent**: checks for an existing `com.fritzbox.monitor` agent (and the older `com.fritz-monitor`), removes it with `launchctl bootout`, clears launchd's disabled override, writes `~/Library/LaunchAgents/com.fritzbox.monitor.plist`, loads it with `launchctl bootstrap`, and checks that the monitor is running. The agent runs `venv/bin/python fritz_monitor_macos.py` from the project folder.

### Log directory

All log files go to one directory: `fritz_monitor.log`, `fritz_monitor_alert.log`, `fritz_monitor.error.log`, `fritz_monitor.out.log`, and the gzipped monthly archives. The directory comes from `LOGGING_CONFIG['dir']` in `config.py` (default `logs`). Relative paths start at the project folder, absolute paths are used as is. To change it, set `log_dir` in `fritz_config.json`, for example:

```json
{
  "fritz_hostname": "192.168.178.1",
  "fritz_username": "admin",
  "log_dir": "/Users/me/Library/Logs/fritz-monitor"
}
```

`config.py` also applies `fritz_hostname` and `fritz_username` from this file. Rerun the wizard or restart the agent after a change (see below). Because the LaunchAgent writes `fritz_monitor.out.log` and `fritz_monitor.error.log` to the log directory, rerun the wizard when you move it.

---

## LaunchAgent Management

The plist is located at:

```text
~/Library/LaunchAgents/com.fritzbox.monitor.plist
```

The commands use the modern `launchctl` syntax with the per user domain `gui/$(id -u)`.

### Restart the monitor after a configuration change

The monitor reads `config.py`, `fritz_config.json` and the knowledge base only at startup. After running `kb_manager.py` or editing any of these, restart it:

```bash
launchctl kickstart -k gui/$(id -u)/com.fritzbox.monitor
```

`kb_manager.py` prints this command when you leave it.

### Stop the monitor

```bash
launchctl bootout gui/$(id -u)/com.fritzbox.monitor
```

### Start the monitor

```bash
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.fritzbox.monitor.plist
```

If `bootstrap` fails with `Input/output error`, launchd holds a disabled override for the label. Clear it and try again:

```bash
launchctl enable gui/$(id -u)/com.fritzbox.monitor
```

### Check whether it is running

```bash
launchctl print gui/$(id -u)/com.fritzbox.monitor | grep -E "state|pid"
```

A running agent shows `state = running` and a `pid`. You can also watch the live log:

```bash
tail -f logs/fritz_monitor.log
```

---

## Knowledge Base

The knowledge base (`network_knowledge_base.json` in the project folder) stores:

| Key | Purpose |
| --- | --- |
| `known_devices` | MAC → IP/hostname mapping; unknown MACs trigger an alert |
| `whitelisted_ips` | IPs that never trigger unknown-device alerts |
| `suspicious_ips` | IPs manually flagged for reference |
| `suspicious_keywords` | Substring patterns that trigger a high/medium notification |
| `critical_keywords` | Substring patterns that trigger a modal alert dialog |
| `baseline_traffic` | Source→destination traffic patterns (reserved for future use) |

### Option A — Interactive manager

```bash
venv/bin/python kb_manager.py
```

Menu options:

```text
1. Add known device
2. List known devices
3. Add baseline traffic pattern
4. List baseline traffic
5. Whitelist IP address
6. List whitelisted IPs
7. View suspicious IPs
8. Flag IP as suspicious
9. Auto-populate from current network (ARP scan)
k. Manage keywords (suspicious / critical)
0. Exit
```

### Option B — Edit the JSON file directly

Open `network_knowledge_base.json` in any text editor. Example structure:

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
- The monitor loads the knowledge base at startup only. After editing the file manually or running `kb_manager.py`, restart the agent with `launchctl kickstart -k gui/$(id -u)/com.fritzbox.monitor`.

---

## Extending the Log Analyzer Filters

Keywords are stored in `network_knowledge_base.json` under two keys and are loaded at monitor startup. There are two lists, checked in order per log message:

1. **`critical_keywords`** — match triggers a modal alert dialog that the user must dismiss.
2. **`suspicious_keywords`** — match triggers a standard macOS notification with an Alarm sound. Within this category, messages containing `gescheitert` or `verweigert` are graded `high`; everything else is `medium`.

The check is a simple case-insensitive substring match against the full log message, so multi-word phrases (e.g. `'falsches kennwort'`) work as exact-phrase filters.

### Managing keywords interactively

Use `kb_manager.py` and choose option `k`:

```bash
python3 kb_manager.py
# → k. Manage keywords (suspicious / critical)
```

The keyword submenu lets you list, add, and delete entries for both lists. Changes are saved immediately to `network_knowledge_base.json`. **A monitor restart is required for keyword changes to take effect**, as the lists are read once at startup.

### Editing the JSON file directly

Open `~/fritz-monitor/network_knowledge_base.json` and edit the arrays directly:

```json
{
  "suspicious_keywords": [
    "gescheitert",
    "mein-neues-keyword"
  ],
  "critical_keywords": [
    "falsches kennwort"
  ]
}
```

Restart the monitor after saving.

### Current keyword tables

All keywords are sourced from the official FRITZ!Box 6670 Cable event message list.

#### Suspicious keywords

| Keyword | Matches |
| --- | --- |
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
| --- | --- |
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

Run these from the project folder with the virtual environment's interpreter (or activate it first with `source venv/bin/activate`).

```bash
# Run the monitor directly in the foreground (logs to logs/fritz_monitor.log)
venv/bin/python fritz_monitor_macos.py

# Interactive setup wizard
python3 macos_setup.py

# Interactive knowledge base manager
venv/bin/python kb_manager.py

# Validate configuration
venv/bin/python config.py

# Syntax check
venv/bin/python -c "import py_compile; py_compile.compile('fritz_monitor_macos.py', doraise=True)"
```

## Runtime Files

Paths are relative to the project folder unless noted. The log directory can be changed (see above).

| File | Location | Purpose |
| --- | --- | --- |
| `fritz_config.json` | project folder | FRITZ!Box hostname, username and `log_dir` (no password) |
| `network_knowledge_base.json` | project folder | Device registry and IP lists |
| `fritz_monitor.log` | `logs/` | Application log |
| `fritz_monitor_alert.log` | `logs/` | Every alert that was raised |
| `fritz_monitor.error.log` | `logs/` | stderr from the LaunchAgent |
| `fritz_monitor.out.log` | `logs/` | stdout from the LaunchAgent |
| `venv/` | project folder | Virtual environment used by the LaunchAgent |
| `com.fritzbox.monitor.plist` | `~/Library/LaunchAgents/` | macOS auto-start configuration |

---

## License & Maintenance

This project is released under the [MIT License](LICENSE).

This is a personal tool released as-is. Maintenance will be minimal — issues and pull requests may not be actively monitored. That said, everyone is welcome to fork the repository and adapt it freely to their own needs. The MIT license gives you full permission to use, modify, and redistribute the code, with or without attribution.
