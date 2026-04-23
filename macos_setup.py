#!/usr/bin/env python3
"""
macOS FRITZ!Box Monitor Setup Assistant
Automatically configures LaunchAgent and all settings.
"""

import os
import shutil
import sys
import json
import subprocess
from pathlib import Path


class MacOSSetupAssistant:
    """Interactive setup for macOS."""
    
    def __init__(self):
        self.home = Path.home()
        self.monitor_dir = self.home / 'fritz-monitor'
        self.launchagent_dir = self.home / 'Library/LaunchAgents'
        self.plist_path = self.launchagent_dir / 'com.fritz-monitor.plist'
        self.username = os.getenv('USER', os.getenv('LOGNAME'))
    
    def clear(self):
        """Clear screen."""
        subprocess.run(['clear'])
    
    def header(self, title: str):
        """Print header."""
        print("\n" + "="*70)
        print(f"  {title}")
        print("="*70)
    
    def section(self, title: str):
        """Print section."""
        print(f"\n→ {title}\n")
    
    def run(self):
        """Run setup wizard."""
        self.clear()
        self.header("FRITZ!Box Monitor for macOS - Setup")
        
        print("Welcome! This wizard will set up automatic network monitoring")
        print("with native macOS notifications.\n")
        print(f"📁 Working directory: {self.monitor_dir}")
        print(f"👤 Username: {self.username}\n")
        
        # Run steps
        try:
            self.step_welcome()
            self.step_prerequisites()
            self.step_deploy()
            self.step_fritz_config()
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
  • Automatic monitoring of FRITZ!Box logs every 5 minutes
  • macOS Notification Center alerts for suspicious activity
  • Automatic startup when you log in
  • Knowledge base of your known devices
  • Full log history for troubleshooting

⏱️  Time required: ~10 minutes

Let's get started!
        """)
        input("Press Enter to continue...")
    
    def step_prerequisites(self):
        """Check and install prerequisites."""
        self.clear()
        self.header("Step 1: Checking Prerequisites")
        
        # Check Miniconda
        self.section("Checking Miniconda...")
        conda_path = shutil.which('conda')
        if not conda_path:
            # Fall back to common install locations
            candidates = [
                Path.home() / 'miniconda3' / 'bin' / 'conda',
                Path.home() / 'opt' / 'miniconda3' / 'bin' / 'conda',
                Path('/usr/local/opt/miniconda3/bin/conda'),
                Path('/opt/homebrew/Caskroom/miniconda/base/bin/conda'),
            ]
            for candidate in candidates:
                if candidate.exists():
                    conda_path = str(candidate)
                    break

        if not conda_path:
            print("✗ Miniconda is not installed!")
            print("\n  Install it with Homebrew and then restart your terminal:")
            print("    brew install --cask miniconda")
            print("    conda init zsh   # or: conda init bash")
            sys.exit(1)

        # Verify the base environment is accessible
        result = subprocess.run(
            [conda_path, 'run', '-n', 'base', 'python', '--version'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"✓ Miniconda found: {conda_path}")
            print(f"✓ Base environment active: {result.stdout.strip() or result.stderr.strip()}")
        else:
            print(f"✓ Miniconda found: {conda_path}")
            print("⚠️  Could not activate base environment — continuing anyway.")

        # Create directories
        self.section("Creating directories...")
        self.monitor_dir.mkdir(parents=True, exist_ok=True)
        print(f"✓ Directory created: {self.monitor_dir}")
        
        self.launchagent_dir.mkdir(parents=True, exist_ok=True)
        
        # Check Python
        self.section("Checking Python...")
        try:
            result = subprocess.run(['python3', '--version'], 
                                   capture_output=True, text=True)
            print(f"✓ {result.stdout.strip()}")
        except FileNotFoundError:
            print("✗ Python3 not found!")
            print("\nInstall Python via Homebrew:")
            print("  brew install python3")
            sys.exit(1)
        
        # Check dependencies
        self.section("Checking Python packages...")
        
        required = ['requests', 'schedule', 'defusedxml']
        missing = []
        
        for pkg in required:
            try:
                __import__(pkg)
                print(f"✓ {pkg} is installed")
            except ImportError:
                missing.append(pkg)
                print(f"✗ {pkg} not found")
        
        if missing:
            print(f"\nInstalling: {', '.join(missing)}")
            subprocess.run([sys.executable, '-m', 'pip3', 'install'] + missing)
        
        input("\nPress Enter to continue...")
    
    def step_deploy(self):
        """Copy project *.py files into the monitor directory."""
        self.clear()
        self.header("Step 2: Deploy Monitor Scripts")

        src_dir = Path(__file__).parent
        py_files = sorted(src_dir.glob('*.py'))

        self.section(f"Copying scripts to {self.monitor_dir}")

        copied = []
        for src in py_files:
            dest = self.monitor_dir / src.name
            shutil.copy2(src, dest)
            copied.append(src.name)
            print(f"✓ {src.name}")

        print(f"\n✓ {len(copied)} file(s) copied to {self.monitor_dir}")
        input("\nPress Enter to continue...")

    def step_fritz_config(self):
        """Configure FRITZ!Box access."""
        self.clear()
        self.header("Step 3: FRITZ!Box Configuration")
        
        self.section("Testing FRITZ!Box connection")
        
        hostname = input(
            "FRITZ!Box hostname/IP (press Enter for 192.168.178.1): "
        ).strip() or '192.168.178.1'
        
        print(f"\nTesting connection to {hostname}...")
        try:
            import requests
            response = requests.get(f'http://{hostname}:49000/tr64desc.xml', timeout=5)
            if response.status_code in [200, 401]:
                print(f"✓ Connected successfully!")
            else:
                print(f"⚠️  Unexpected status: {response.status_code}")
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            print("Make sure FRITZ!Box is online and IP is correct.")
            retry = input("Try different IP? (y/n): ").strip().lower()
            if retry == 'y':
                return self.step_fritz_config()
            return
        
        self.section("FRITZ!Box credentials")
        
        username = input(
            "Admin username (press Enter for 'admin'): "
        ).strip() or 'admin'
        
        print("\nYour password will be stored securely in the macOS Keychain.\n")

        password = input(
            "Enter admin password (stored in macOS Keychain): "
        ).strip()

        # Save config (no password)
        config = {
            'fritz_hostname': hostname,
            'fritz_username': username
        }

        config_path = self.monitor_dir / 'fritz_config.json'
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"\n✓ Config saved to {config_path}")

        # Store password in macOS Keychain
        try:
            # Delete existing entry if present
            subprocess.run(
                ['security', 'delete-generic-password', '-s', 'fritz-monitor',
                 '-a', 'fritz_password'],
                capture_output=True
            )
            # Add new entry
            result = subprocess.run(
                ['security', 'add-generic-password', '-s', 'fritz-monitor',
                 '-a', 'fritz_password', '-w', password],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                print("✓ Password stored in macOS Keychain")
            else:
                print(f"⚠️  Keychain storage failed: {result.stderr}")
                print("  Password can be set via FRITZ_PASSWORD environment variable instead.")
        except Exception as e:
            print(f"⚠️  Could not store in Keychain: {e}")
            print("  Password can be set via FRITZ_PASSWORD environment variable instead.")

        input("Press Enter to continue...")
    
    def step_knowledge_base(self):
        """Initialize knowledge base."""
        self.clear()
        self.header("Step 4: Initialize Knowledge Base")
        
        kb_path = self.monitor_dir / 'network_knowledge_base.json'
        
        if kb_path.exists():
            print("✓ Knowledge base already exists")
            update = input("  Update it? (y/n): ").strip().lower()
            if update != 'y':
                return
        
        self.section("Creating baseline knowledge base")
        
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
            'whitelisted_ips': [
                '8.8.8.8',           # Google DNS
                '8.8.4.4',           # Google DNS
                '1.1.1.1',           # Cloudflare DNS
                '192.168.178.1',     # FRITZ!Box
                '224.0.0.1',         # mDNS
                '255.255.255.255',   # Broadcast
            ],
            'suspicious_ips': [],
            'metadata': {'created': str(Path(__file__).name)}
        }
        
        with open(kb_path, 'w') as f:
            json.dump(kb_data, f, indent=2)
        
        print(f"✓ Knowledge base created: {kb_path}")
        
        # Ask to add devices
        self.section("Add your devices?")
        
        print("You can manually add your devices to the knowledge base.")
        print("At minimum, add:")
        print("  • Your MacBook (MAC address)")
        print("  • Your iPhone/iPad (MAC address)")
        print("  • Any other frequently used devices\n")
        
        add_devices = input("Add devices now? (y/n): ").strip().lower()
        
        if add_devices == 'y':
            self._add_devices_interactive(kb_path)
        else:
            print("\n✓ You can add devices later using:")
            print("  cd ~/fritz-monitor && python3 kb_manager.py")
        
        input("\nPress Enter to continue...")
    
    def _add_devices_interactive(self, kb_path: Path):
        """Interactively add devices to knowledge base."""
        print("\n--- Add Known Devices ---\n")
        
        with open(kb_path, 'r') as f:
            kb = json.load(f)
        
        while True:
            mac = input("Device MAC address (or 'done'): ").strip()
            if mac.lower() == 'done':
                break
            
            ip = input(f"  IP address for {mac}: ").strip()
            hostname = input(f"  Device name (e.g., 'My MacBook'): ").strip()
            
            kb['known_devices'][mac.lower()] = {
                'mac': mac,
                'ip': ip,
                'hostname': hostname,
                'type': 'device',
                'first_seen': str(Path(__file__).name)
            }
            
            print(f"✓ Added {hostname or mac}\n")
        
        with open(kb_path, 'w') as f:
            json.dump(kb, f, indent=2)
        
        print(f"\n✓ Devices saved to {kb_path}")
    
    def step_launchagent(self):
        """Create and load LaunchAgent."""
        self.clear()
        self.header("Step 5: Configure Automatic Startup")
        
        self.section("Creating LaunchAgent configuration")
        
        # Resolve the active python3 interpreter and its directory so the
        # LaunchAgent runs with the same Python (e.g. a conda environment).
        python3_path = shutil.which('python3') or sys.executable
        python3_dir = str(Path(python3_path).parent)

        # Create plist content
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fritz-monitor</string>

    <key>ProgramArguments</key>
    <array>
        <string>{python3_path}</string>
        <string>{self.monitor_dir}/fritz_monitor_macos.py</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    
    <key>ThrottleInterval</key>
    <integer>60</integer>
    
    <key>StandardOutPath</key>
    <string>{self.monitor_dir}/fritz_monitor.log</string>
    
    <key>StandardErrorPath</key>
    <string>{self.monitor_dir}/fritz_monitor.error.log</string>
    
    <key>WorkingDirectory</key>
    <string>{self.monitor_dir}</string>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>ALERT_METHOD</key>
        <string>desktop</string>
        <key>PATH</key>
        <string>{python3_dir}:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
"""
        
        # Write plist file
        with open(self.plist_path, 'w') as f:
            f.write(plist_content)
        
        # Set permissions
        os.chmod(self.plist_path, 0o600)
        
        print(f"✓ LaunchAgent created: {self.plist_path}")
        
        # Load it
        self.section("Loading LaunchAgent")
        
        try:
            # Unload if already loaded
            subprocess.run(['launchctl', 'unload', str(self.plist_path)],
                          capture_output=True)
        except Exception:
            pass
        
        # Load the agent
        result = subprocess.run(['launchctl', 'load', str(self.plist_path)],
                               capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ LaunchAgent loaded successfully")
            print("  Monitor will start automatically at next login")
            print("  (Or now if you reload the system)\n")
        else:
            print(f"✗ Failed to load: {result.stderr}")
        
        # Verify
        result = subprocess.run(['launchctl', 'list'],
                               capture_output=True, text=True)
        if 'fritz-monitor' in result.stdout:
            print("✓ LaunchAgent is active")
        
        input("\nPress Enter to continue...")
    
    def step_final(self):
        """Final configuration and testing."""
        self.clear()
        self.header("Setup Complete! ✓")
        
        print(f"""
Your FRITZ!Box monitor is now configured!

📍 Location: {self.monitor_dir}
📊 Logs: {self.monitor_dir}/fritz_monitor.log
🚀 Status: Automatic startup enabled

Next steps:

1️⃣  Wait a few seconds for the monitor to start, then check the logs:
   tail -f ~/fritz-monitor/fritz_monitor.log

2️⃣  Add your devices to the knowledge base:
   python3 ~/fritz-monitor/kb_manager.py

3️⃣  Manage or check notifications:
   System Settings → Notifications → Terminal

Need help?
• View logs: tail -f ~/fritz-monitor/fritz_monitor.log
• Manage monitor: launchctl list | grep fritz
• Pause: launchctl unload ~/Library/LaunchAgents/com.fritz-monitor.plist
• Resume: launchctl load ~/Library/LaunchAgents/com.fritz-monitor.plist

🎉 You're all set!
        """)
        
        # Offer to view logs
        view_logs = input("\nView logs now? (y/n): ").strip().lower()
        if view_logs == 'y':
            print("\nWatching logs (Ctrl+C to stop)...\n")
            subprocess.run(['tail', '-f', str(self.monitor_dir / 'fritz_monitor.log')])


def main():
    """Main entry."""
    try:
        assistant = MacOSSetupAssistant()
        assistant.run()
    except KeyboardInterrupt:
        print("\n\nSetup interrupted.")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
