#!/usr/bin/env python3
"""
FRITZ!Box Network Activity Monitor - macOS Edition
Optimized for macOS with native notifications and sleep detection.
"""

import json
import os
import sys
import time
import logging
import subprocess
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import requests
import schedule
import defusedxml.ElementTree as ET

# Import configuration
try:
    import config
except ImportError:
    print("Error: config.py not found. Please ensure config.py is in the same directory.")
    sys.exit(1)

# Configure logging - will be updated based on config.py settings in main()
logging_config = {
    'level': logging.INFO,
    'format': '%(asctime)s - %(levelname)s - %(message)s',
    'file': 'fritz_monitor.log'
}

logging.basicConfig(
    level=logging_config['level'],
    format=logging_config['format'],
    handlers=[
        logging.FileHandler(logging_config['file']),
#        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Dedicated alert log — receives every alert processed by AlertHandler
_alert_file_handler = logging.FileHandler('fritz_monitor_alert.log')
_alert_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
alert_logger = logging.getLogger('fritz_monitor.alerts')
alert_logger.setLevel(logging.INFO)
alert_logger.addHandler(_alert_file_handler)
alert_logger.propagate = False  # keep alert log separate from the main log


class MacOSNotificationManager:
    """Handle macOS-native notifications via osascript."""

    SOUNDS = {
        'alert': 'Submarine',
        'warning': 'Alarm',
        'error': 'Sosumi',
        'info': 'Bell'
    }

    @staticmethod
    def _sanitize_for_applescript(text: str) -> str:
        """Sanitize a string for safe inclusion in AppleScript double-quoted strings.

        Strips control characters (newlines, tabs, etc.) and escapes backslashes,
        double quotes, and single quotes to prevent AppleScript injection.
        """
        # Strip control characters that could break out of string context
        sanitized = re.sub(r'[\x00-\x1f\x7f]', ' ', text)
        # Escape backslashes first, then quotes
        sanitized = sanitized.replace('\\', '\\\\')
        sanitized = sanitized.replace('"', '\\"')
        sanitized = sanitized.replace("'", "\\'")
        return sanitized

    @staticmethod
    def notify(title: str, message: str, sound: str = 'alert',
               action_btn: str = None, reply_btn: str = None) -> Optional[str]:
        """
        Send native macOS notification.

        Args:
            title: Notification title
            message: Notification body
            sound: Sound name (alert, warning, error, info)
            action_btn: Optional action button text
            reply_btn: Optional reply button text

        Returns:
            User's response if clickable buttons included
        """
        try:
            sound_file = MacOSNotificationManager.SOUNDS.get(sound, 'Submarine')

            safe_message = MacOSNotificationManager._sanitize_for_applescript(message)
            safe_title = MacOSNotificationManager._sanitize_for_applescript(title)

            # Build AppleScript
            script = f'''
            display notification "{safe_message}" with title "{safe_title}" sound name "{sound_file}"
            '''

            result = subprocess.run(
                ['osascript', '-e', script],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                logger.info(f"macOS notification sent: {title}")
                return True
            else:
                logger.error(f"Notification failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"macOS notification error: {e}")
            return False

    @staticmethod
    def send_alert_dialog(title: str, message: str, alert_style: str = 'warning') -> bool:
        """
        Send a more prominent alert dialog (user must dismiss).

        Args:
            title: Dialog title
            message: Dialog message
            alert_style: 'warning', 'critical', or 'informational'
        """
        try:
            safe_title = MacOSNotificationManager._sanitize_for_applescript(title)
            safe_message = MacOSNotificationManager._sanitize_for_applescript(message)
            # Validate alert_style to prevent injection via the unquoted parameter
            if alert_style not in ('warning', 'critical', 'informational'):
                alert_style = 'warning'
            logger.debug(f"Sending alert dialog: {title} - {message}")

            script = f'''
            tell app "System Events"
                activate
                display alert "{safe_title}" message "{safe_message}" as {alert_style}
            end tell
            '''

            subprocess.run(
                ['osascript', '-e', script],
                capture_output=True,
                timeout=10
            )
            return True

        except Exception as e:
            logger.error(f"Alert dialog failed: {e}")
            return False


class MacOSPowerManager:
    """Detect macOS sleep state and system wake/sleep events."""
    
    @staticmethod
    def is_system_awake() -> bool:
        """Check if system is awake (not in sleep mode)."""
        try:
            # Use pmset to check current system state
            result = subprocess.run(
                ['pmset', '-g', 'systemstate'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Parse the output to find "Current Power State: X"
            # State 4 = Awake, State 0 = Sleep
            output = result.stdout.strip()
            
            # Look for the power state line
            for line in output.split('\n'):
                if 'Current Power State:' in line:
                    # Extract the state number
                    try:
                        state = int(line.split(':')[1].strip())
                        # State 4 = Awake, State 0 = Sleep
                        is_awake = state > 0
                        logger.debug(f"System power state: {state} ({'awake' if is_awake else 'sleeping'})")
                        return is_awake
                    except (ValueError, IndexError):
                        logger.debug(f"Could not parse power state from: {line}")
                        return True  # Default to awake if parsing fails
            
            # If we didn't find the power state line, default to awake
            logger.debug(f"Could not find 'Current Power State' in pmset output: {output}")
            return True
                
        except Exception as e:
            logger.warning(f"Could not determine power state: {e}")
            # Default to awake if command fails
            return True
    


class FRITZBoxMonitor:
    """Handle FRITZ!Box communication."""
    
    def __init__(self, hostname: str = '192.168.0.1', username: str = 'logger', password: str = ''):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.base_url = f'http://{hostname}:49000'
        self.session = requests.Session()
        self.last_successful_connect = None
        self.last_log_timestamp = datetime(1970, 1, 1)  # Initialize to epoch to read all events on first run
        
    def test_connection(self) -> bool:
        """Test if FRITZ!Box is accessible."""
        try:
            response = self.session.get(
                f'http://{self.hostname}:49000/tr64desc.xml',
                timeout=5
            )
            
            if response.status_code in [200, 401]:
                logger.info(f"✓ Connected to FRITZ!Box at {self.hostname}")
                self.last_successful_connect = datetime.now()
                return True
            else:
                logger.warning(f"FRITZ!Box returned status {response.status_code}")
                return False
                
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot reach FRITZ!Box at {self.hostname}")
            return False
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    def get_logs(self) -> List[Dict]:
        """
        Retrieve device logs from FRITZ!Box in two steps:
        1. Get device log path via SOAP X_AVM-DE_GetDeviceLogPath
        2. Fetch XML log file from that path with filter=all
        
        Returns list of log events as dictionaries.
        """
        try:
            from requests.auth import HTTPDigestAuth
            
            # Step 1: Get the device log path
            log_path = self._get_device_log_path()
            if not log_path:
                logger.warning("Could not retrieve device log path")
                return []
            
            # Step 2: Fetch the actual log XML file
            logs = self._fetch_log_xml(log_path)
            
            logger.debug(f"Retrieved {len(logs)} log entries")
            return logs
            
        except Exception as e:
            logger.error(f"Error retrieving logs: {e}")
            return []
    
    def _get_device_log_path(self) -> Optional[str]:
        """
        Step 1: Get the device log path via SOAP.
        Returns the log path URL (e.g., /devicelog.lua?sid=...)
        """
        try:
            from requests.auth import HTTPDigestAuth
            
            url = f'http://{self.hostname}:49000/upnp/control/deviceinfo'
            
            # SOAP request for X_AVM-DE_GetDeviceLogPath
            soap_body = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:X_AVM-DE_GetDeviceLogPath xmlns:u="urn:dslforum-org:service:DeviceInfo:1">
    </u:X_AVM-DE_GetDeviceLogPath>
  </s:Body>
</s:Envelope>"""
            
            headers = {
                'Content-Type': 'text/xml; charset="utf-8"',
                'SOAPAction': 'urn:dslforum-org:service:DeviceInfo:1#X_AVM-DE_GetDeviceLogPath'
            }
            
            auth = HTTPDigestAuth(self.username, self.password)
            response = self.session.post(
                url,
                data=soap_body,
                headers=headers,
                auth=auth,
                timeout=10
            )
            
            if response.status_code == 200:
                # Parse SOAP response to extract log path
                log_path = self._parse_log_path_response(response.text)
                logger.debug(f"Got device log path: {log_path}")
                return log_path
            elif response.status_code == 401:
                logger.error(f"FRITZ!Box authentication failed (401). Check username/password.")
                return None
            else:
                logger.warning(f"FRITZ!Box returned status {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting device log path: {e}")
            return None
    
    def _parse_log_path_response(self, xml_response: str) -> Optional[str]:
        """Extract device log path from SOAP response."""
        try:
            root = ET.fromstring(xml_response)
            ns = {
                'u': 'urn:dslforum-org:service:DeviceInfo:1',
                's': 'http://schemas.xmlsoap.org/soap/envelope/'
            }
            
            # Extract NewDeviceLogPath element
            log_path = root.findtext('.//NewDeviceLogPath', None, ns)
            return log_path
        except Exception as e:
            logger.debug(f"Error parsing log path response: {e}")
            return None
    
    def _fetch_log_xml(self, log_path: str) -> List[Dict]:
        """
        Step 2: Fetch the actual log XML file.
        The log_path should be something like: /devicelog.lua?sid=...
        We append &filter=all to get all log entries.
        
        Returns list of event dictionaries.
        """
        try:
            # Validate log_path from SOAP response before using in URL
            if not log_path.startswith('/') or '..' in log_path or '\n' in log_path:
                logger.warning(f"Suspicious log path rejected: {log_path!r}")
                return []

            # Construct full URL
            full_url = f'http://{self.hostname}:49000{log_path}&filter=all'
            logger.debug(f"Fetching log XML from: {full_url}")
            
            # No authentication needed for this GET request
            response = self.session.get(full_url, timeout=10)
            
            if response.status_code == 200:
                events = self._parse_log_xml(response.text)
                return events
            else:
                logger.warning(f"Failed to fetch log XML: HTTP {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error fetching log XML: {e}")
            return []
    
    def _parse_log_xml(self, xml_content: str) -> List[Dict]:
        """
        Parse XML log file and extract events.
        Filters events newer than last_log_timestamp to avoid duplicates.
        Events are sorted from newest to oldest in the XML.

        Returns list of event dictionaries with structure:
        {
            'id': event_id,
            'group': event_group,
            'date': date_string,
            'time': time_string,
            'timestamp': datetime object,
            'msg': message
        }
        """
        try:
            root = ET.fromstring(xml_content)
            events = []
            newest_event_timestamp = None

            # Parse all Event elements
            for event_elem in root.findall('Event'):
                try:
                    event = {
                        'id': event_elem.findtext('id', ''),
                        'group': event_elem.findtext('group', ''),
                        'date': event_elem.findtext('date', ''),
                        'time': event_elem.findtext('time', ''),
                        'msg': event_elem.findtext('msg', '')
                    }

                    # Parse timestamp for filtering duplicates
                    # Date format: DD.MM.YY, Time format: HH:MM:SS
                    try:
                        date_str = event['date']
                        time_str = event['time']
                        # Parse date DD.MM.YY format
                        date_parts = date_str.split('.')
                        if len(date_parts) == 3:
                            day, month, year = int(date_parts[0]), int(date_parts[1]), int(date_parts[2])
                            # Convert YY to YYYY (assume 20xx)
                            if year < 50:
                                year += 2000
                            else:
                                year += 1900

                            # Parse time HH:MM:SS
                            time_parts = time_str.split(':')
                            if len(time_parts) == 3:
                                hour, minute, second = int(time_parts[0]), int(time_parts[1]), int(time_parts[2])
                                event['timestamp'] = datetime(year, month, day, hour, minute, second)
                            else:
                                event['timestamp'] = None
                        else:
                            event['timestamp'] = None
                    except (ValueError, IndexError):
                        event['timestamp'] = None

                    # Only include events newer than last_log_timestamp
                    if event['timestamp'] is not None and event['timestamp'] > self.last_log_timestamp:
                        events.append(event)
                        logger.info(f"Parsed log event: {event['date']} {event['time']} - {event['msg']}")

                        # Track the newest event timestamp (first event in XML since sorted newest-first)
                        if newest_event_timestamp is None:
                            newest_event_timestamp = event['timestamp']

                except Exception as e:
                    logger.debug(f"Error parsing individual event: {e}")
                    continue

            # Update last_log_timestamp to the newest event after processing all events
            if newest_event_timestamp is not None:
                self.last_log_timestamp = newest_event_timestamp

            return events

        except Exception as e:
            logger.error(f"Error parsing log XML: {e}")
            return []
    


class KnowledgeBase:
    """Knowledge base management."""
    
    def __init__(self, db_path: str = 'network_knowledge_base.json'):
        self.db_path = Path(db_path)
        self.data = self._load_or_create()
    
    def _load_or_create(self) -> Dict:
        """Load existing or create new knowledge base."""
        # FRITZ!Box log patterns (German, sourced from official event message list)
        _default_suspicious_keywords = [
            'gescheitert',            # Any failed login / connection / delivery
            'fehlgeschlagen',         # Protocol / service / firmware failures
            'störquelle',             # WLAN interference source detected (possible jamming)
            'wlan-autokanal',         # WLAN auto-channel change (causes reconnections)
            'dns-störung',            # DNS disturbance / hijacking indicator
            'loopback gefunden',      # PPP routing loop detected
            'schwerwiegender fehler', # Severe system error (e.g. factory-reset on import)
            'verweigert',             # Access/login denied by remote system
        ]
        _default_critical_keywords = [
            'falsches kennwort',         # Brute force on admin UI / FTP
            'kennwort falsch',           # Brute force on SMB (alternate phrasing)
            'ungültige sitzungskennung', # Session token attack / session hijacking
            'ungültiger wlan-schlüssel', # WiFi WPA key brute force
            'authentifizierungsfehler',  # FRITZ! mesh product auth failure
            'kennwort abgelehnt',        # Internet access password attempt rejected
            'untypisch',                 # Anomalous call usage / toll fraud indicator
            'netzwerkschleife',          # Network loop / possible DoS attack
        ]

        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    data = json.load(f)
                # Migrate: backfill keyword arrays added in later versions
                if 'suspicious_keywords' not in data:
                    data['suspicious_keywords'] = _default_suspicious_keywords
                if 'critical_keywords' not in data:
                    data['critical_keywords'] = _default_critical_keywords
                return data
            except Exception as e:
                logger.error(f"Error loading KB: {e}")

        # Create new
        return {
            'known_devices': {},
            'baseline_traffic': {},
            'suspicious_keywords': _default_suspicious_keywords,
            'critical_keywords':   _default_critical_keywords,
            'whitelisted_ips': set(),
            'suspicious_ips': set(),
            'metadata': {
                'created': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }
        }
    
    def save(self):
        """Persist to disk."""
        try:
            output = self.data.copy()
            output['whitelisted_ips'] = list(self.data.get('whitelisted_ips', set()))
            output['suspicious_ips'] = list(self.data.get('suspicious_ips', set()))
            output['metadata']['last_updated'] = datetime.now().isoformat()
            
            with open(self.db_path, 'w') as f:
                json.dump(output, f, indent=2)
            logger.debug("Knowledge base saved")
        except Exception as e:
            logger.error(f"Error saving KB: {e}")
    
    def add_baseline_traffic(self, source_ip: str, dest_ip: str, protocol: str, port: int):
        """Add a baseline traffic pattern."""
        key = f"{source_ip} -> {dest_ip}:{port}/{protocol}"
        self.data['baseline_traffic'][key] = {
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'protocol': protocol,
            'port': port,
            'count': self.data['baseline_traffic'].get(key, {}).get('count', 0) + 1,
            'first_seen': self.data['baseline_traffic'].get(key, {}).get('first_seen', datetime.now().isoformat()),
            'last_seen': datetime.now().isoformat()
        }
        self.save()
        logger.info(f"Added baseline traffic: {key}")

    def add_device(self, mac: str, ip: str, hostname: str = '', device_type: str = 'unknown'):
        """Register a known device."""
        device_id = mac.lower()
        self.data['known_devices'][device_id] = {
            'mac': mac,
            'ip': ip,
            'hostname': hostname,
            'type': device_type,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }
        self.save()
        logger.info(f"Added device: {hostname or mac}")
    
    def whitelist_ip(self, ip: str):
        """Add IP to whitelist."""
        if not isinstance(self.data.get('whitelisted_ips'), set):
            self.data['whitelisted_ips'] = set()
        self.data['whitelisted_ips'].add(ip)
        self.save()
        logger.info(f"Whitelisted: {ip}")
    
    def is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted."""
        whitelist = self.data.get('whitelisted_ips', set())
        if isinstance(whitelist, list):
            whitelist = set(whitelist)
        return ip in whitelist

    def is_known_ip(self, ip: str) -> bool:
        """Check if a device with this IP is known."""
        return any(
            d.get('ip', '') == ip
            for d in self.data['known_devices'].values()
        )

    def is_known_mac(self, mac: str) -> bool:
        """Check if a device with this MAC address is known."""
        return any(
            d.get('mac', '').lower() == mac.lower()
            for d in self.data['known_devices'].values()
        )

    def flag_suspicious(self, ip: str):
        """Mark IP as suspicious."""
        if not isinstance(self.data.get('suspicious_ips'), set):
            self.data['suspicious_ips'] = set()
        self.data['suspicious_ips'].add(ip)
        self.save()
        logger.warning(f"Flagged suspicious: {ip}")


class LogAnalyzer:
    """Analyze logs for suspicious patterns."""
    
    DEDUP_WINDOW_SECONDS = 300  # Suppress duplicate alerts within 5 minutes

    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self.critical_keywords   = kb.data.get('critical_keywords',   [])
        self.suspicious_keywords = kb.data.get('suspicious_keywords', [])
        self.last_analysis_time = None
        self._recent_alerts: Dict[str, datetime] = {}

    def _extract_device_info(self, message: str) -> Optional[Dict]:
        """Extract hostname and IP from WLAN connect/disconnect messages."""
        # Strip optional repeater prefix
        msg = re.sub(r'^\[fritz\.repeater\]\s*', '', message)
        # Match: ..., <hostname>, IP <ip>, ...
        match = re.search(r',\s+([^,]+),\s+IP\s+((?:\d{1,3}\.){3}\d{1,3}),\s+MAC\s+([0-9A-Fa-f:]+)', msg)
        if match:
            return {'hostname': match.group(1).strip(), 'ip': match.group(2), 'mac': match.group(3)}
        # Fallback: IP address only
        ip_match = re.search(r'\bIP\s+((?:\d{1,3}\.){3}\d{1,3}),\s+MAC\s+([0-9A-Fa-f:]+)', msg)
        if ip_match:
            return {'hostname': None, 'ip': ip_match.group(1), 'mac': ip_match.group(2)}
        return None

    def analyze(self, logs: List[Dict]) -> List[Dict]:
        """Analyze log events and return alerts.
        
        Args:
            logs: List of log event dictionaries from FRITZ!Box XML
            
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        for event in logs:
            # Extract message from event
            msg = event.get('msg', '')
            if not msg or len(msg) < 5:
                continue
            
            alert = self._check_log_message(msg, event)
            if alert and not self._is_duplicate(alert):
                alerts.append(alert)
        
        self.last_analysis_time = datetime.now()
        return alerts
    
    def _check_log_message(self, message: str, event: Dict) -> Optional[Dict]:
        """Check single log message for suspicious patterns."""
        lower_msg = message.lower()
        
        # Check for critical security issues
        for keyword in self.critical_keywords:
            if keyword in lower_msg:
                return {
                    'type': 'critical_security_event',
                    'severity': 'critical',
                    'message': message,
                    'event_id': event.get('id'),
                    'group': event.get('group'),
                    'timestamp': event.get('timestamp', datetime.now()).isoformat()
                }
        
        # Check for general suspicious activity
        for keyword in self.suspicious_keywords:
            if keyword in lower_msg:
                return {
                    'type': 'suspicious_activity',
                    'severity': 'high' if 'gescheitert' in lower_msg or 'verweigert' in lower_msg else 'medium',
                    'message': message,
                    'event_id': event.get('id'),
                    'group': event.get('group'),
                    'timestamp': event.get('timestamp', datetime.now()).isoformat()
                }

        # Check for unknown devices in WLAN connect messages
        if 'WLAN-Gerät angemeldet' in message or 'WLAN-Gerät wurde angemeldet' in message or 'angemeldet' in lower_msg:
            device_info = self._extract_device_info(message)
            if device_info:
                ip = device_info.get('ip')
                hostname = device_info.get('hostname')
                mac = device_info.get('mac')
                # Skip if IP is whitelisted
                if ip and self.kb.is_whitelisted(ip):
                    return None
                # Check if device is known by MAC or IP
                mac_known = mac and self.kb.is_known_mac(mac)
                ip_known = ip and self.kb.is_known_ip(ip)
                if not mac_known and not ip_known:
                    label = hostname or mac or ip or 'Unknown'
                    return {
                        'type': 'unknown_device',
                        'severity': 'high',
                        'message': f"Unknown device connected: {label} (MAC: {mac}, IP: {ip})",
                        'event_id': event.get('id'),
                        'group': event.get('group'),
                        'timestamp': event.get('timestamp', datetime.now()).isoformat(),
                        'ip': ip or '',
                        'mac': mac or '',
                        'hostname': hostname or ''
                    }

        return None
    
    def _is_duplicate(self, alert: Dict) -> bool:
        """Check if we've seen this alert recently (within DEDUP_WINDOW_SECONDS)."""
        key = f"{alert.get('type')}:{alert.get('message', '')}"
        now = datetime.now()

        # Purge expired entries
        self._recent_alerts = {
            k: t for k, t in self._recent_alerts.items()
            if (now - t).total_seconds() < self.DEDUP_WINDOW_SECONDS
        }

        if key in self._recent_alerts:
            return True

        self._recent_alerts[key] = now
        return False


class AlertHandler:
    """Handle alert delivery via notifications."""
    
    def __init__(self, kb: KnowledgeBase):
        self.kb = kb
        self.alert_history = []
        self.notifications = MacOSNotificationManager()
    
    def process_alert(self, alert: Dict) -> bool:
        """
        Process and deliver alert.
        
        Args:
            alert: Alert dictionary with type, severity, message
            
        Returns:
            True if alert was delivered
        """
        try:
            # Skip if IP is whitelisted
            if 'ip' in alert and self.kb.is_whitelisted(alert['ip']):
                logger.debug(f"Skipping whitelisted IP: {alert['ip']}")
                return False
            
            # Log locally
            self._log_alert(alert)
            self.alert_history.append({
                'alert': alert,
                'timestamp': datetime.now().isoformat()
            })
            
            # Send notification based on severity
            return self._send_notification(alert)
            
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
            return False
    
    def _log_alert(self, alert: Dict):
        """Log alert to main log and dedicated alert log."""
        level = logging.WARNING if alert['severity'] in ['high', 'critical'] else logging.INFO
        msg = f"[{alert['severity'].upper()}] {alert['type']}: {alert['message']}"
        logger.log(level, msg)
        alert_logger.log(level, msg)
    
    def _send_notification(self, alert: Dict) -> bool:
        """Send macOS notification based on severity."""
        severity = alert['severity']
        alert_type = alert['type']
        message = alert['message'][:100]  # Truncate for notification
        
        if severity == 'critical':
            # Use alert dialog for critical issues
            return self.notifications.send_alert_dialog(
                f"🚨 CRITICAL",
                message,
                alert_style='critical'
            )
        
        elif severity == 'high':
            # High priority notification with warning sound
            return self.notifications.notify(
                f"⚠️  SECURITY ALERT",
                f"{message}",
                sound='warning'
            )
        
        else:
            # Medium severity - regular notification
            return self.notifications.notify(
                f"ℹ️  Network Activity",
                f"{message}",
                sound='alert'
            )


class MonitoringEngine:
    """Main monitoring orchestration."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.fritz = FRITZBoxMonitor(
            config.get('fritz_hostname', '192.168.178.1'),
            config.get('fritz_username', 'logger'),
            config.get('fritz_password', '')
        )
        self.kb = KnowledgeBase()
        self.analyzer = LogAnalyzer(self.kb)
        self.alerts = AlertHandler(self.kb)
        self.power = MacOSPowerManager()
        
        self.running = False
        self.last_cycle_time = None
        self.cycle_count = 0
    
    def start(self, interval_minutes: int = 5):
        """Start monitoring loop."""
        self.running = True
        logger.info(f"🚀 FRITZ!Box Monitor started (interval: {interval_minutes}m)")
        logger.info(f"📍 Monitoring {self.config.get('fritz_hostname', '192.168.178.1')}")
        
        # Schedule monitoring
        schedule.every(interval_minutes).minutes.do(self._run_cycle)
        
        # Initial test
        if not self.fritz.test_connection():
            logger.warning("⚠️  Initial connection test failed - will retry")
        
        # Run scheduler loop
        try:
            while self.running:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop monitoring gracefully."""
        self.running = False
        logger.info("🛑 Monitoring stopped")
    
    def _run_cycle(self):
        """Single monitoring cycle."""
        self.cycle_count += 1
        self.last_cycle_time = datetime.now()
        
        logger.info(f"[Cycle #{self.cycle_count}] Starting at {self.last_cycle_time.strftime('%H:%M:%S')}")
        
        # Check if system is awake
        if not self.power.is_system_awake():
            logger.info("💤 System is sleeping, skipping cycle")
            return
        
        # Test connection to FRITZ!Box
        if not self.fritz.test_connection():
            logger.error("❌ Cannot reach FRITZ!Box, will retry next cycle")
            return
        
        # Retrieve logs
        logs = self.fritz.get_logs()
        if not logs:
            logger.info("✓ No logs available (normal)")
            return
        
        logger.info(f"📊 Retrieved {len(logs)} log entries")
        
        # Analyze logs
        alerts = self.analyzer.analyze(logs)
        
        if alerts:
            logger.warning(f"⚠️  Found {len(alerts)} suspicious activities")
            for alert in alerts:
                self.alerts.process_alert(alert)
        else:
            logger.info("✓ No suspicious activities detected")
        
        logger.debug(f"Cycle completed in {(datetime.now() - self.last_cycle_time).total_seconds():.1f}s")


def main():
    """Main entry point."""
    # Load configuration from config.py
    fritz_config = config.get_config('fritz')
    monitoring_config = config.get_config('monitoring')
    logging_config = config.get_config('logging')
    
    # Override with environment variables (for security - passwords shouldn't be in config files)
    hostname = os.getenv('FRITZ_HOSTNAME', fritz_config.get('hostname', '192.168.0.1'))
    username = os.getenv('FRITZ_USERNAME', fritz_config.get('username', 'logger'))
    password = os.getenv('FRITZ_PASSWORD', '')

    # Try macOS Keychain if no env var password is set
    if not password:
        try:
            result = subprocess.run(
                ['security', 'find-generic-password', '-s', 'fritz-monitor',
                 '-a', 'fritz_password', '-w'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                password = result.stdout.strip()
                logger.info("Password loaded from macOS Keychain")
        except Exception as e:
            logger.debug(f"Could not read from Keychain: {e}")

    if not password:
        password = fritz_config.get('password', '')
    
    # Set logging level from config
    log_level = getattr(logging, logging_config.get('level', 'INFO'))
    logger.setLevel(log_level)
    
    # Build final configuration
    runtime_config = {
        'fritz_hostname': hostname,
        'fritz_username': username,
        'fritz_password': password,
        'monitoring_interval': monitoring_config.get('interval_minutes', 5),
        'respect_sleep': monitoring_config.get('respect_sleep_state', True),
    }
    
    logger.info("="*70)
    logger.info("FRITZ!Box Network Monitor - macOS Edition")
    logger.info("="*70)
    logger.info(f"Configuration loaded from config.py")
    logger.info(f"  FRITZ!Box: {runtime_config['fritz_hostname']}")
    logger.info(f"  Username: {runtime_config['fritz_username']}")
    logger.info(f"  Interval: {runtime_config['monitoring_interval']} minutes")
    logger.info(f"  Sleep aware: {runtime_config['respect_sleep']}")
    logger.info(f"  Log level: {logging_config.get('level', 'INFO')}")
    logger.info("="*70)
    
    # Initialize monitoring engine with config
    engine = MonitoringEngine(runtime_config)
    
    try:
        engine.start(interval_minutes=runtime_config['monitoring_interval'])
    except KeyboardInterrupt:
        logger.info("\n🛑 Monitoring interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"💥 Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
