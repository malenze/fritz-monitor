#!/usr/bin/env python3
"""
macOS FRITZ!Box Monitor Setup Assistant
Runs from the project checkout: creates the virtual environment, stores the
configuration, and installs the LaunchAgent. No files are copied elsewhere.
"""

from __future__ import annotations

import ipaddress
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

import config

MIN_PYTHON = (3, 10)
PYTHON_CANDIDATES = ['python3.14', 'python3.13', 'python3.12', 'python3.11', 'python3.10']
RESUME_FLAG = '--resume'  # set after the re-exec into the venv; skips the bootstrap steps
LEGACY_LABELS = ['com.fritz-monitor']  # earlier LaunchAgent labels, removed during setup


class MacOSSetupAssistant:
    """Interactive setup for macOS."""

    def __init__(self):
        self.root = config.PROJECT_ROOT
        self.launchagent_dir = Path.home() / 'Library' / 'LaunchAgents'
        self.label = config.LAUNCHAGENT_LABEL
        self.plist_path = self.launchagent_dir / f'{self.label}.plist'
        self.venv_dir = self.root / 'venv'
        self.venv_python = self.venv_dir / 'bin' / 'python'
        self.base_python = sys.executable
        self.config_path = config.LOCAL_CONFIG_FILE
        self.log_dir = self._resolve_log_dir(config.LOGGING_CONFIG['dir'])
        self.uid = os.getuid()
        self.domain = f'gui/{self.uid}'
        self.username = os.getenv('USER', os.getenv('LOGNAME'))

    # ------------------------------------------------------------------ helpers

    def in_venv(self) -> bool:
        """True when this process already runs the project virtual environment."""
        return Path(sys.prefix).resolve() == self.venv_dir.resolve()

    def reexec_in_venv(self, extra_args: list[str] | None = None):
        """Replace this process with the same script running under the venv python."""
        script = str(Path(__file__).resolve())
        args = [str(self.venv_python), script, *sys.argv[1:], *(extra_args or [])]
        sys.stdout.flush()
        try:
            os.execv(str(self.venv_python), args)
        except OSError as e:
            print(f"⚠️  Could not switch to {self.venv_python}: {e}")
            print("  Continuing with the current Python.")

    def clear(self):
        """Clear screen."""
        subprocess.run(['clear'], check=False)

    def header(self, title: str):
        """Print header."""
        print("\n" + "="*70)
        print(f"  {title}")
        print("="*70)

    def section(self, title: str):
        """Print section."""
        print(f"\n→ {title}\n")

    def ask_yes_no(self, prompt: str, default: bool = False) -> bool:
        """Ask a yes/no question. Enter selects the default."""
        answer = input(f"{prompt} ({'Y/n' if default else 'y/N'}): ").strip().lower()
        return default if not answer else answer.startswith('y')

    def _resolve_log_dir(self, value: str) -> Path:
        """Resolve a log directory setting against the project root."""
        path = Path(value).expanduser()
        return path if path.is_absolute() else self.root / path

    def _load_local_config(self) -> dict:
        """Read fritz_config.json, or an empty dict if missing or broken."""
        try:
            with open(self.config_path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save_local_config(self, updates: dict):
        """Merge updates into fritz_config.json, keeping other keys."""
        data = self._load_local_config()
        data.update(updates)
        with open(self.config_path, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')

    def _tail(self, path: Path, lines: int = 15) -> str:
        """Return the last lines of a text file, or an empty string."""
        try:
            return '\n'.join(path.read_text(errors='replace').splitlines()[-lines:])
        except OSError:
            return ''

    # ------------------------------------------------------------------ wizard

    def run(self):
        """Run setup wizard."""
        self.clear()
        self.header("FRITZ!Box Monitor for macOS - Setup")

        print("Welcome! This wizard will set up automatic network monitoring")
        print("with native macOS notifications.\n")
        print(f"📁 Project directory: {self.root}")
        print(f"👤 Username: {self.username}\n")

        # The bootstrap steps need no packages and create the venv;
        # afterwards the wizard re-runs itself under the venv python.
        try:
            if RESUME_FLAG not in sys.argv:
                self.step_welcome()
                self.step_prerequisites()
                self.step_venv()
                if not self.in_venv():
                    self.reexec_in_venv([RESUME_FLAG])
            self.step_fritz_config()
            self.step_keychain()
            self.step_log_dir()
            self.step_knowledge_base()
            self.step_launchagent()
            self.step_final()
        except KeyboardInterrupt:
            print("\n\n⚠️  Setup cancelled.")
            sys.exit(1)

    def step_welcome(self):
        """Welcome and overview."""
        self.header("About This Monitor")

        print("""
✅ What you'll have after setup:
  • A Python virtual environment inside the project folder
  • Automatic monitoring of FRITZ!Box logs
  • macOS Notification Center alerts for suspicious activity
  • Log files in a log directory of your choice (default: logs/)
  • Knowledge base of your known devices
  • Automatic startup when you log in (LaunchAgent)

Everything runs from this checkout. No files are copied elsewhere.

Let's get started!
        """)
        input("Press Enter to continue...")

    def step_prerequisites(self):
        """Check the project files and the Python interpreter."""
        self.clear()
        self.header("Step 1: Checking Prerequisites")

        self.section("Project files")
        required = ['requirements.txt', 'config.py', 'fritz_monitor_macos.py', 'kb_manager.py']
        missing = [name for name in required if not (self.root / name).exists()]
        if missing:
            print(f"✗ Missing in {self.root}: {', '.join(missing)}")
            sys.exit(1)
        print(f"✓ Project files found in {self.root}")

        self.section("Checking Python...")
        python_path = self._find_python()
        if not python_path:
            print(f"✗ Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer not found!")
            print("\nInstall Python via Homebrew:")
            print("  brew install python")
            sys.exit(1)
        self.base_python = python_path
        result = subprocess.run([python_path, '--version'],
                                capture_output=True, text=True, check=False)
        print(f"✓ {result.stdout.strip()} ({python_path})")

        input("\nPress Enter to continue...")

    def _find_python(self) -> str | None:
        """Return a Python interpreter that meets MIN_PYTHON, or None."""
        if sys.version_info >= MIN_PYTHON and sys.prefix == sys.base_prefix:
            return sys.executable
        for name in PYTHON_CANDIDATES:
            path = shutil.which(name)
            if path:
                return path
        return None

    def step_venv(self):
        """Create the project virtual environment and install hashed dependencies."""
        self.clear()
        self.header("Step 2: Python Environment")

        requirements = self.root / 'requirements.txt'

        self.section(f"Virtual environment: {self.venv_dir}")
        if self.venv_python.exists():
            print("✓ Virtual environment already exists")
        else:
            result = subprocess.run([self.base_python, '-m', 'venv', str(self.venv_dir)],
                                    capture_output=True, text=True, check=False)
            if result.returncode != 0:
                print(f"✗ Could not create virtual environment: {result.stderr.strip()}")
                sys.exit(1)
            print("✓ Virtual environment created")

        self.section("Installing packages (hash verified)")
        result = subprocess.run(
            [str(self.venv_python), '-m', 'pip', 'install', '--require-hashes',
             '-r', str(requirements)],
            cwd=self.root, check=False
        )
        if result.returncode != 0:
            print("✗ Package installation failed.")
            sys.exit(1)
        print("✓ Packages installed")

        input("\nPress Enter to continue...")

    def _test_connection(self, hostname: str) -> bool:
        """Check that the TR-064 description is reachable. HTTP 401 also counts as reachable."""
        print(f"\nTesting connection to {hostname}...")
        try:
            try:
                with urllib.request.urlopen(f'http://{hostname}:49000/tr64desc.xml', timeout=5) as response:
                    status = response.status
            except urllib.error.HTTPError as http_err:
                status = http_err.code
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            print("Make sure FRITZ!Box is online and IP is correct.")
            return False
        if status in (200, 401):
            print("✓ Connected successfully!")
            return True
        print(f"⚠️  Unexpected status: {status}")
        return False

    def step_fritz_config(self):
        """Configure FRITZ!Box access."""
        self.clear()
        self.header("Step 3: FRITZ!Box Configuration")

        local = self._load_local_config()
        default_host = local.get('fritz_hostname') or '192.168.178.1'
        default_user = local.get('fritz_username') or 'admin'

        self.section("Testing FRITZ!Box connection")
        while True:
            hostname = input(
                f"FRITZ!Box hostname/IP (press Enter for {default_host}): "
            ).strip() or default_host
            if self._test_connection(hostname):
                break
            if not self.ask_yes_no("Try different IP?", default=True):
                print("⚠️  Continuing with an unverified hostname.")
                break
            default_host = hostname

        self.section("FRITZ!Box user")
        username = input(
            f"Admin username (press Enter for '{default_user}'): "
        ).strip() or default_user

        self._save_local_config({'fritz_hostname': hostname, 'fritz_username': username})
        print(f"\n✓ Config saved to {self.config_path} (no password)")

        input("\nPress Enter to continue...")

    def _keychain_has_password(self) -> bool:
        """True if the FRITZ!Box password item exists. The password itself is never read."""
        result = subprocess.run(
            ['security', 'find-generic-password', '-s', config.KEYCHAIN_SERVICE,
             '-a', config.KEYCHAIN_ACCOUNT],
            capture_output=True, check=False
        )
        return result.returncode == 0

    def step_keychain(self):
        """Store the FRITZ!Box password in the macOS Keychain, asking before overwriting."""
        self.clear()
        self.header("Step 4: FRITZ!Box Password")

        if self._keychain_has_password():
            print("✓ A FRITZ!Box password is already stored in the macOS Keychain")
            print(f"  (service '{config.KEYCHAIN_SERVICE}', account '{config.KEYCHAIN_ACCOUNT}')\n")
            if not self.ask_yes_no("Overwrite it?"):
                print("\n✓ Keeping the stored password")
                input("\nPress Enter to continue...")
                return
        else:
            print("No FRITZ!Box password is stored in the macOS Keychain yet.")

        # security prompts for the password itself (hidden input, asked twice),
        # so it never appears in the process list. -U updates an existing item in place.
        print("\nmacOS will now ask for the admin password. Input is hidden.\n")
        result = subprocess.run(
            ['security', 'add-generic-password', '-U',
             '-s', config.KEYCHAIN_SERVICE, '-a', config.KEYCHAIN_ACCOUNT, '-w'],
            check=False
        )
        if result.returncode == 0:
            print("\n✓ Password stored in macOS Keychain")
        else:
            print("\n⚠️  Keychain storage failed or was cancelled.")
            print("  Password can be set via FRITZ_PASSWORD environment variable instead.")

        input("\nPress Enter to continue...")

    def step_log_dir(self):
        """Choose the log directory and save it for config.py."""
        self.clear()
        self.header("Step 5: Log Directory")

        print("Log files (monitor log, alert log, error log and monthly archives)")
        print("are written to one directory. Relative paths start at the project folder.\n")

        while True:
            entry = input(f"Log directory (press Enter for {self.log_dir}): ").strip()
            candidate = self._resolve_log_dir(entry) if entry else self.log_dir
            try:
                candidate.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryFile(dir=candidate):
                    pass  # proves the directory is writable
            except OSError as e:
                print(f"✗ Cannot use {candidate}: {e}")
                continue
            break

        self.log_dir = candidate.resolve()
        try:
            stored = str(self.log_dir.relative_to(self.root))
        except ValueError:
            stored = str(self.log_dir)
        self._save_local_config({'log_dir': stored})
        print(f"\n✓ Log directory: {self.log_dir}")
        print(f"✓ Saved as 'log_dir' in {self.config_path}")

        input("\nPress Enter to continue...")

    def step_knowledge_base(self):
        """Create the baseline knowledge base if missing, then run kb_manager.py."""
        self.clear()
        self.header("Step 6: Knowledge Base")

        kb_path = config.get_kb_path()
        if kb_path.exists():
            print(f"✓ Knowledge base already exists and is kept: {kb_path}")
        else:
            self.section("Creating baseline knowledge base")
            self._create_knowledge_base(kb_path)
            print(f"✓ Knowledge base created: {kb_path}")

        self.section("Knowledge base manager")
        print("Register your known devices now. At minimum add:")
        print("  • Your MacBook (MAC address)")
        print("  • Your iPhone/iPad (MAC address)")
        print("  • Any other frequently used devices")
        print("\nChoose option 0 in the manager to return to the setup.\n")
        input("Press Enter to start kb_manager.py...")

        result = subprocess.run([str(self.venv_python), str(self.root / 'kb_manager.py')],
                                cwd=self.root, check=False)
        if result.returncode != 0:
            print(f"\n⚠️  kb_manager.py exited with code {result.returncode}")
            print(f"  Run it again later: {self.venv_python} {self.root / 'kb_manager.py'}")

        input("\nPress Enter to continue...")

    def _create_knowledge_base(self, kb_path: Path):
        """Write the default knowledge base with whitelisted DNS servers and the router."""
        whitelist = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '192.168.178.1', '224.0.0.1', '255.255.255.255']
        hostname = self._load_local_config().get('fritz_hostname', '')
        try:
            ipaddress.ip_address(hostname)
            if hostname not in whitelist:
                whitelist.append(hostname)
        except ValueError:
            pass  # a name like fritz.box is not an IP address

        now = datetime.now().isoformat()
        kb_data = {
            'known_devices': {},
            'baseline_traffic': {},
            'suspicious_keywords': [
                'gescheitert',            # Any failed login / connection / delivery
                'fehlgeschlagen',         # Protocol / service / firmware failures
                'störquelle',             # WLAN interference source detected (possible jamming)
                'wlan-autokanal',         # WLAN auto-channel change (causes reconnections)
                'dns-störung',            # DNS disturbance / hijacking indicator
                'loopback gefunden',      # PPP routing loop detected
                'schwerwiegender fehler', # Severe system error (e.g. factory-reset on import)
                'verweigert',             # Access/login denied by remote system
            ],
            'critical_keywords': [
                'falsches kennwort',         # Brute force on admin UI / FTP
                'kennwort falsch',           # Brute force on SMB (alternate phrasing)
                'ungültige sitzungskennung', # Session token attack / session hijacking
                'ungültiger wlan-schlüssel', # WiFi WPA key brute force
                'authentifizierungsfehler',  # FRITZ! mesh product auth failure
                'kennwort abgelehnt',        # Internet access password attempt rejected
                'untypisch',                 # Anomalous call usage / toll fraud indicator
                'netzwerkschleife',          # Network loop / possible DoS attack
            ],
            'whitelisted_ips': whitelist,
            'suspicious_ips': [],
            'metadata': {'created': now, 'last_updated': now}
        }
        with open(kb_path, 'w') as f:
            json.dump(kb_data, f, indent=2)

    # ------------------------------------------------------------------ launchd

    def _launchctl(self, *args: str) -> subprocess.CompletedProcess:
        """Run launchctl and capture its output."""
        return subprocess.run(['launchctl', *args], capture_output=True, text=True, check=False)

    def _service_loaded(self, label: str) -> bool:
        """True if launchd currently knows the service in the user's GUI domain."""
        return self._launchctl('print', f'{self.domain}/{label}').returncode == 0

    def _service_disabled(self, label: str) -> bool:
        """True if launchd keeps a persistent 'disabled' override for the label."""
        out = self._launchctl('print-disabled', self.domain).stdout
        return f'"{label}" => disabled' in out

    def _remove_agent(self, label: str):
        """Boot out a LaunchAgent, clear launchd's disabled override and delete its plist."""
        target = f'{self.domain}/{label}'
        plist = self.launchagent_dir / f'{label}.plist'
        loaded = self._service_loaded(label)
        disabled = self._service_disabled(label)
        exists = plist.exists()

        if not (loaded or disabled or exists):
            print(f"  {label}: no configuration found")
            return

        state = [name for name, flag in (('plist present', exists), ('loaded', loaded),
                                         ('disabled', disabled)) if flag]
        print(f"  {label}: {', '.join(state)}")

        if loaded:
            result = self._launchctl('bootout', target)
            if result.returncode != 0:
                print(f"    ⚠️  bootout: {result.stderr.strip() or result.stdout.strip()}")
            # bootout returns before the job is fully gone, so wait for it
            for _ in range(10):
                if not self._service_loaded(label):
                    break
                time.sleep(0.5)
            else:
                print("    ⚠️  Service is still registered after 5 seconds")
            print("    ✓ booted out")

        if disabled:
            # A disabled label makes bootstrap fail with "Input/output error"
            self._launchctl('enable', target)
            print("    ✓ disabled override cleared")

        if exists:
            plist.unlink()
            print("    ✓ plist removed")

    def _write_plist(self):
        """Write the LaunchAgent plist for this checkout."""
        agent = {
            'Label': self.label,
            'ProgramArguments': [str(self.venv_python), str(self.root / 'fritz_monitor_macos.py')],
            'WorkingDirectory': str(self.root),
            'RunAtLoad': True,
            'KeepAlive': {'SuccessfulExit': False},
            'ThrottleInterval': 60,
            'StandardOutPath': str(self.log_dir / 'fritz_monitor.out.log'),
            'StandardErrorPath': str(self.log_dir / 'fritz_monitor.error.log'),
            'EnvironmentVariables': {
                'ALERT_METHOD': 'desktop',
                'PATH': f'{self.venv_dir / "bin"}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
            },
        }
        self.launchagent_dir.mkdir(parents=True, exist_ok=True)
        with open(self.plist_path, 'wb') as f:
            plistlib.dump(agent, f)
        os.chmod(self.plist_path, 0o644)

    def _wait_until_running(self, timeout: float = 15.0) -> tuple[bool, dict]:
        """Poll launchctl until the service runs stably. Returns (running, last seen info)."""
        target = f'{self.domain}/{self.label}'
        info: dict = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self._launchctl('print', target)
            if result.returncode == 0:
                info = {key: m.group(1).strip() for key, pattern in (
                    ('state', r'^\tstate = (.+)$'),
                    ('pid', r'^\tpid = (\d+)$'),
                    ('exit', r'^\tlast exit code = (.+)$'),
                ) if (m := re.search(pattern, result.stdout, re.MULTILINE))}
                if info.get('state') == 'running' and 'pid' in info:
                    # a crash on startup shows up as a changed or missing pid
                    time.sleep(3)
                    again = self._launchctl('print', target).stdout
                    if re.search(rf'^\tpid = {info["pid"]}$', again, re.MULTILINE):
                        return True, info
            time.sleep(1)
        return False, info

    def step_launchagent(self):
        """Replace the LaunchAgent: bootout, clean launchd state, bootstrap, verify."""
        self.clear()
        self.header("Step 7: Configure Automatic Startup")

        self.section("Existing LaunchAgent configuration")
        for label in (self.label, *LEGACY_LABELS):
            self._remove_agent(label)

        self.section("Creating LaunchAgent configuration")
        self._write_plist()
        lint = subprocess.run(['plutil', '-lint', str(self.plist_path)],
                              capture_output=True, text=True, check=False)
        if lint.returncode != 0:
            print(f"✗ Invalid plist: {lint.stdout.strip()} {lint.stderr.strip()}")
            sys.exit(1)
        print(f"✓ LaunchAgent created: {self.plist_path}")

        self.section("Loading LaunchAgent")
        result = self._launchctl('bootstrap', self.domain, str(self.plist_path))
        if result.returncode != 0:
            print(f"✗ bootstrap failed: {result.stderr.strip() or result.stdout.strip()}")
            if 'Input/output error' in result.stderr:
                print("  launchd may still hold a disabled override for this label.")
                print(f"  Try: launchctl enable {self.domain}/{self.label}")
            input("\nPress Enter to continue...")
            return
        print("✓ bootstrap succeeded, waiting for the monitor to start...")

        running, info = self._wait_until_running()
        if running:
            print(f"✓ Monitor is running (PID {info['pid']})")
        else:
            print(f"✗ Monitor did not stay running (state: {info.get('state', 'unknown')}, "
                  f"last exit code: {info.get('exit', 'n/a')})")
            error_tail = self._tail(self.log_dir / 'fritz_monitor.error.log')
            if error_tail:
                print(f"\nLast lines of {self.log_dir / 'fritz_monitor.error.log'}:\n{error_tail}")
            print(f"\nCheck {self.log_dir / 'fritz_monitor.log'} for details.")

        print("\nNote: macOS may show a 'Background item added' notification. You can review it in")
        print("System Settings > General > Login Items & Extensions.")

        input("\nPress Enter to continue...")

    def step_final(self):
        """Summary and management commands."""
        self.clear()
        self.header("Setup Complete! ✓")

        target = f'gui/$(id -u)/{self.label}'
        print(f"""
Your FRITZ!Box monitor is configured.

📍 Project:   {self.root}
📊 Logs:      {self.log_dir}/fritz_monitor.log
🚀 LaunchAgent: {self.plist_path}

Restart the monitor after any configuration change, for example after
running kb_manager.py or editing fritz_config.json or config.py:

   launchctl kickstart -k {target}

Other commands:
• Status:  launchctl print {target} | grep -E "state|pid"
• Stop:    launchctl bootout gui/$(id -u)/{self.label}
• Start:   launchctl bootstrap gui/$(id -u) {self.plist_path}
• Logs:    tail -f {self.log_dir}/fritz_monitor.log
• Devices: {self.venv_python} {self.root / 'kb_manager.py'}

Manage or check notifications:
System Settings → Notifications → Terminal
        """)

        if self.ask_yes_no("View logs now?"):
            print("\nWatching logs (Ctrl+C to stop)...\n")
            subprocess.run(['tail', '-f', str(self.log_dir / 'fritz_monitor.log')], check=False)


def main():
    """Main entry."""
    try:
        assistant = MacOSSetupAssistant()
        if assistant.venv_python.exists() and not assistant.in_venv():
            assistant.reexec_in_venv()
        assistant.run()
    except KeyboardInterrupt:
        print("\n\nSetup interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
