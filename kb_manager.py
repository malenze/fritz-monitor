#!/usr/bin/env python3
"""
Network Knowledge Base Manager
Interactive tool to register known devices and baseline traffic patterns.
"""

import ipaddress
import json
import re
import sys
from pathlib import Path
from datetime import datetime
from fritz_monitor_macos import KnowledgeBase

MAC_PATTERN = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def _validate_mac(mac: str) -> bool:
    """Validate MAC address format (AA:BB:CC:DD:EE:FF)."""
    return bool(MAC_PATTERN.match(mac))


def _validate_ip(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class KnowledgeBaseManager:
    """Interactive manager for the knowledge base."""
    
    def __init__(self):
        self.kb = KnowledgeBase()
    
    def interactive_menu(self):
        """Show interactive menu."""
        while True:
            print("\n" + "="*50)
            print("FRITZ!Box Network Knowledge Base Manager")
            print("="*50)
            print("\n1. Add known device")
            print("2. List known devices")
            print("3. Add baseline traffic pattern")
            print("4. List baseline traffic")
            print("5. Whitelist IP address")
            print("6. List whitelisted IPs")
            print("7. View suspicious IPs")
            print("8. Flag IP as suspicious")
            print("9. Auto-populate from current network (requires access)")
            print("k. Manage keywords (suspicious / critical)")
            print("0. Exit")

            choice = input("\nSelect option (0-9, k): ").strip()

            if choice == '1':
                self.add_device_interactive()
            elif choice == '2':
                self.list_devices()
            elif choice == '3':
                self.add_traffic_interactive()
            elif choice == '4':
                self.list_traffic()
            elif choice == '5':
                self.whitelist_ip_interactive()
            elif choice == '6':
                self.list_whitelist()
            elif choice == '7':
                self.list_suspicious()
            elif choice == '8':
                self.flag_suspicious_interactive()
            elif choice == '9':
                self.auto_populate()
            elif choice == 'k':
                self.manage_keywords_menu()
            elif choice == '0':
                print("Exiting...")
                break
            else:
                print("Invalid option")
    
    def add_device_interactive(self):
        """Interactively add a device."""
        print("\n--- Add Known Device ---")
        mac = input("MAC address (e.g., AA:BB:CC:DD:EE:FF): ").strip().upper()
        if not _validate_mac(mac):
            print("✗ Invalid MAC address format. Expected AA:BB:CC:DD:EE:FF")
            return
        ip = input("IP address (e.g., 192.168.1.100): ").strip()
        if not _validate_ip(ip):
            print("✗ Invalid IP address format.")
            return
        hostname = input("Device hostname/name (optional): ").strip()

        device_types = ['smartphone', 'laptop', 'desktop', 'smart_home', 'printer',
                       'router', 'nas', 'camera', 'iot', 'other']
        print("\nDevice types:")
        for i, dt in enumerate(device_types, 1):
            print(f"  {i}. {dt}")

        type_choice = input("Select type (number or custom): ").strip()
        if type_choice.isdigit() and 1 <= int(type_choice) <= len(device_types):
            device_type = device_types[int(type_choice) - 1]
        else:
            device_type = type_choice or 'other'

        self.kb.add_device(mac, ip, hostname, device_type)
        print(f"✓ Device added: {hostname or mac}")
    
    def list_devices(self):
        """List all known devices."""
        devices = self.kb.data.get('known_devices', {})
        
        if not devices:
            print("\nNo devices registered yet.")
            return
        
        print(f"\n--- Known Devices ({len(devices)}) ---")
        print(f"{'MAC Address':<20} {'IP Address':<15} {'Hostname':<20} {'Type':<12}")
        print("-" * 70)
        
        for mac, info in sorted(devices.items()):
            mac_display = mac.upper()
            ip = info.get('ip', '?')
            hostname = info.get('hostname', '(none)')[:19]
            dtype = info.get('type', 'unknown')
            print(f"{mac_display:<20} {ip:<15} {hostname:<20} {dtype:<12}")
    
    def add_traffic_interactive(self):
        """Interactively add baseline traffic pattern."""
        print("\n--- Add Baseline Traffic Pattern ---")
        source_ip = input("Source IP (local device): ").strip()
        if not _validate_ip(source_ip):
            print("✗ Invalid source IP address format.")
            return
        dest_ip = input("Destination IP (external server): ").strip()
        if not _validate_ip(dest_ip):
            print("✗ Invalid destination IP address format.")
            return
        protocol = input("Protocol (TCP/UDP): ").strip().upper()
        if protocol not in ('TCP', 'UDP'):
            print("✗ Protocol must be TCP or UDP.")
            return
        port = input("Port number: ").strip()

        try:
            port = int(port)
            if not (1 <= port <= 65535):
                raise ValueError("Port must be between 1 and 65535")
            self.kb.add_baseline_traffic(source_ip, dest_ip, protocol, port)
            print(f"✓ Traffic pattern added: {source_ip} -> {dest_ip}:{port}/{protocol}")
        except ValueError:
            print("✗ Invalid port number")
    
    def list_traffic(self):
        """List baseline traffic patterns."""
        traffic = self.kb.data.get('baseline_traffic', {})
        
        if not traffic:
            print("\nNo baseline traffic patterns recorded yet.")
            return
        
        print(f"\n--- Baseline Traffic Patterns ({len(traffic)}) ---")
        print(f"{'Source -> Destination:Port/Protocol':<40} {'Count':<8}")
        print("-" * 50)
        
        for key, info in sorted(traffic.items()):
            count = info.get('count', 0)
            print(f"{key:<40} {count:<8}")
    
    def whitelist_ip_interactive(self):
        """Interactively whitelist an IP."""
        print("\n--- Whitelist IP Address ---")
        ip = input("IP address to whitelist: ").strip()
        if not _validate_ip(ip):
            print("✗ Invalid IP address format.")
            return
        reason = input("Reason (e.g., 'ISP gateway', 'trusted service'): ").strip()

        self.kb.whitelist_ip(ip)
        print(f"✓ IP whitelisted: {ip}")
    
    def list_whitelist(self):
        """List whitelisted IPs."""
        whitelist = self.kb.data.get('whitelisted_ips', set())
        
        if isinstance(whitelist, list):
            whitelist = set(whitelist)
        
        if not whitelist:
            print("\nNo whitelisted IPs yet.")
            return
        
        print(f"\n--- Whitelisted IPs ({len(whitelist)}) ---")
        for ip in sorted(whitelist):
            print(f"  • {ip}")
    
    def list_suspicious(self):
        """List flagged suspicious IPs."""
        suspicious = self.kb.data.get('suspicious_ips', set())
        
        if isinstance(suspicious, list):
            suspicious = set(suspicious)
        
        if not suspicious:
            print("\nNo suspicious IPs flagged yet.")
            return
        
        print(f"\n--- Suspicious IPs ({len(suspicious)}) ---")
        for ip in sorted(suspicious):
            print(f"  ⚠ {ip}")
    
    def flag_suspicious_interactive(self):
        """Interactively flag an IP as suspicious."""
        print("\n--- Flag Suspicious IP ---")
        ip = input("IP address: ").strip()
        if not _validate_ip(ip):
            print("✗ Invalid IP address format.")
            return
        reason = input("Reason (e.g., 'brute force attempt'): ").strip()

        self.kb.flag_suspicious(ip)
        print(f"✓ IP flagged: {ip}")

    def manage_keywords_menu(self):
        """Submenu for managing detection keywords."""
        while True:
            print("\n" + "="*50)
            print("Keyword Management")
            print("="*50)
            print("\n1. List suspicious keywords")
            print("2. Add suspicious keyword")
            print("3. Delete suspicious keyword")
            print("4. List critical keywords")
            print("5. Add critical keyword")
            print("6. Delete critical keyword")
            print("0. Back")

            choice = input("\nSelect option (0-6): ").strip()

            if choice == '1':
                self.list_keywords('suspicious_keywords')
            elif choice == '2':
                self.add_keyword_interactive('suspicious_keywords')
            elif choice == '3':
                self.delete_keyword_interactive('suspicious_keywords')
            elif choice == '4':
                self.list_keywords('critical_keywords')
            elif choice == '5':
                self.add_keyword_interactive('critical_keywords')
            elif choice == '6':
                self.delete_keyword_interactive('critical_keywords')
            elif choice == '0':
                break
            else:
                print("Invalid option")

    def list_keywords(self, key: str):
        """List keywords for the given category."""
        label = 'Suspicious' if key == 'suspicious_keywords' else 'Critical'
        keywords = self.kb.data.get(key, [])
        if not keywords:
            print(f"\nNo {label.lower()} keywords defined.")
            return
        print(f"\n--- {label} Keywords ({len(keywords)}) ---")
        for i, kw in enumerate(keywords, 1):
            print(f"  {i:2}. {kw}")

    def add_keyword_interactive(self, key: str):
        """Interactively add a keyword."""
        label = 'suspicious' if key == 'suspicious_keywords' else 'critical'
        print(f"\n--- Add {label.capitalize()} Keyword ---")
        kw = input("Keyword (case-insensitive substring): ").strip().lower()
        if not kw:
            print("✗ Keyword cannot be empty.")
            return
        keywords = self.kb.data.setdefault(key, [])
        if kw in keywords:
            print(f"✗ '{kw}' is already in the {label} keyword list.")
            return
        keywords.append(kw)
        self.kb.save()
        print(f"✓ Added '{kw}' to {label} keywords.")

    def delete_keyword_interactive(self, key: str):
        """Interactively delete a keyword."""
        label = 'suspicious' if key == 'suspicious_keywords' else 'critical'
        keywords = self.kb.data.get(key, [])
        if not keywords:
            print(f"\nNo {label} keywords to delete.")
            return
        print(f"\n--- Delete {label.capitalize()} Keyword ---")
        self.list_keywords(key)
        choice = input("\nEnter number to delete (or keyword text, 0 to cancel): ").strip()
        if choice == '0':
            return
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(keywords):
                removed = keywords.pop(idx)
                self.kb.save()
                print(f"✓ Removed '{removed}' from {label} keywords.")
            else:
                print("✗ Invalid number.")
        else:
            kw = choice.lower()
            if kw in keywords:
                keywords.remove(kw)
                self.kb.save()
                print(f"✓ Removed '{kw}' from {label} keywords.")
            else:
                print(f"✗ '{kw}' not found in {label} keywords.")

    def auto_populate(self):
        """Attempt to auto-populate knowledge base from network."""
        print("\n--- Auto-Populate from Network ---")
        print("This will scan your network for devices...")
        
        try:
            import subprocess
            import re
            
            # Try to get ARP table
            try:
                if sys.platform == 'darwin':
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                    devices = self._parse_arp_macos(result.stdout)
                elif sys.platform == 'win32':
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                    devices = self._parse_arp_windows(result.stdout)
                else:  # Linux
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                    devices = self._parse_arp_linux(result.stdout)
                
                if devices:
                    print(f"\nFound {len(devices)} devices on network:")
                    for device in devices:
                        print(f"  • {device['ip']} ({device['mac']})")
                    
                    add_all = input("\nAdd all discovered devices? (y/n): ").strip().lower()
                    if add_all == 'y':
                        for device in devices:
                            self.kb.add_device(
                                device['mac'],
                                device['ip'],
                                device.get('hostname', ''),
                                'discovered'
                            )
                        print(f"✓ Added {len(devices)} devices")
                else:
                    print("No devices found on network.")
            
            except Exception as e:
                print(f"Error scanning network: {e}")
                print("Make sure you have the required network tools installed (arp, etc.)")
        
        except ImportError:
            print("Network scanning requires additional packages.")
    
    def _parse_arp_macos(self, output: str) -> list:
        """Parse arp output on macOS."""
        devices = []
        for line in output.strip().split('\n'):
            if ' at ' in line:
                parts = line.split()
                if len(parts) >= 3:
                    devices.append({
                        'ip': parts[1].strip('()'),
                        'mac': parts[3]
                    })
        return devices
    
    def _parse_arp_windows(self, output: str) -> list:
        """Parse arp output on Windows."""
        devices = []
        lines = output.strip().split('\n')
        for line in lines:
            if '.' in line and '-' in line:  # Likely an IP address
                parts = line.split()
                if len(parts) >= 2:
                    devices.append({
                        'ip': parts[0],
                        'mac': parts[1].replace('-', ':').upper()
                    })
        return devices
    
    def _parse_arp_linux(self, output: str) -> list:
        """Parse arp output on Linux."""
        devices = []
        for line in output.strip().split('\n'):
            if '(' in line and ')' in line:
                parts = line.split()
                if len(parts) >= 5:
                    devices.append({
                        'ip': parts[1].strip('()'),
                        'mac': parts[3]
                    })
        return devices


def main():
    """Main entry point."""
    manager = KnowledgeBaseManager()
    manager.interactive_menu()


if __name__ == '__main__':
    main()
