#!/usr/bin/env python3
"""
Configuration file for FRITZ!Box Monitor
Customize alert methods, thresholds, and device settings here.
"""

# ==============================================================================
# FRITZ!BOX SETTINGS
# ==============================================================================

FRITZ_CONFIG = {
    # FRITZ!Box hostname or IP address
    'hostname': '192.168.0.1',
    # Alternative: 'hostname': 'fritz.box'
    
    # Admin username (usually 'admin')
    'username': 'logger',
    
    # Admin password - NEVER hardcode here!
    # Instead: export FRITZ_PASSWORD="your_password" before running
    # Or set in environment variable in startup script
    'password': None,  # Will use FRITZ_PASSWORD env var
    
    # Alternative port if your FRITZ!Box uses non-standard port
    'port': 49000,
}


# ==============================================================================
# MONITORING SETTINGS
# ==============================================================================

MONITORING_CONFIG = {
    # How often to check logs (in minutes)
    # Default 5 minutes balances responsiveness and system load
    # Increase to 10-15 if system is slow
    'interval_minutes': 1,
    
    # Only monitor when system is awake (not in sleep/hibernation)
    # Set to False to monitor even when asleep
    'respect_sleep_state': True,
    
    # Max number of logs to parse per cycle
    # Limits memory usage for routers with very large logs
    'max_logs_per_cycle': 1000,
    
    # How long to keep alert history in memory (minutes)
    'alert_history_retention': 1440,  # 24 hours
}


# ==============================================================================
# ALERT CONFIGURATION
# ==============================================================================

# Choose ONE alert method: 'console', 'desktop', 'email', 'webhook'
ALERT_METHOD = 'desktop'  # Default: print to console

# Set via environment: export ALERT_METHOD="desktop"


# -------- DESKTOP NOTIFICATIONS --------
DESKTOP_ALERTS = {
    # Windows specific
    'windows': {
        'duration': 10,  # seconds to show notification
        'position': 'top-right'
    },
    # macOS specific
    'macos': {
        'sound': 'Submarine',  # Notification sound
        'reply': False
    },
    # Linux specific
    'linux': {
        'timeout': 10000,  # milliseconds
        'urgency': 'critical'
    }
}


# -------- EMAIL ALERTS --------
EMAIL_CONFIG = {
    # SMTP server settings
    'smtp_server': 'smtp.gmail.com',  # Gmail example
    'smtp_port': 587,
    'smtp_username': 'your_email@gmail.com',
    'smtp_password': None,  # Use env var: SMTP_PASSWORD
    
    # Alert recipients
    'from_address': 'your_email@gmail.com',
    'to_addresses': ['your_email@gmail.com'],  # Can be multiple
    
    # Email template
    'subject_template': '[ALERT] FRITZ!Box: {alert_type}',
    'alert_threshold': 'medium',  # Only send email for medium+ severity
}


# -------- WEBHOOK (SLACK, DISCORD, TEAMS, etc.) --------
WEBHOOK_CONFIG = {
    # Slack Incoming Webhook
    'slack': {
        'url': None,  # Set via SLACK_WEBHOOK_URL env var
        'channel': '#security-alerts',
        'username': 'FRITZ!Box Monitor',
        'icon_emoji': ':warning:'
    },
    
    # Discord Webhook
    'discord': {
        'url': None,  # Set via DISCORD_WEBHOOK_URL env var
        'username': 'FRITZ Monitor',
        'avatar_url': 'https://example.com/fritz.png'
    },
    
    # Microsoft Teams
    'teams': {
        'url': None,  # Set via TEAMS_WEBHOOK_URL env var
    },
    
    # Generic webhook (for custom endpoint)
    'generic': {
        'url': None,  # Set via WEBHOOK_URL env var
        'headers': {
            'Content-Type': 'application/json',
            'Authorization': None  # Add if needed
        },
        'method': 'POST'
    }
}


# ==============================================================================
# BASELINE TRAFFIC RULES
# ==============================================================================

# Common trusted traffic patterns
TRUSTED_TRAFFIC_PATTERNS = {
    'dns': {
        'ports': [53],
        'protocols': ['UDP', 'TCP'],
        'description': 'DNS queries (expected)',
        'auto_whitelist': True
    },
    'ntp': {
        'ports': [123],
        'protocols': ['UDP'],
        'description': 'Network Time Protocol (expected)',
        'auto_whitelist': True
    },
    'dhcp': {
        'ports': [67, 68],
        'protocols': ['UDP'],
        'description': 'DHCP (expected)',
        'auto_whitelist': True
    },
    'https': {
        'ports': [443],
        'protocols': ['TCP'],
        'description': 'HTTPS web traffic (expected)',
        'auto_whitelist': True
    },
    'http': {
        'ports': [80],
        'protocols': ['TCP'],
        'description': 'HTTP web traffic (expected)',
        'auto_whitelist': False  # Unusual nowadays
    },
    'mdns': {
        'ports': [5353],
        'protocols': ['UDP'],
        'description': 'Multicast DNS (expected)',
        'auto_whitelist': True
    }
}


# ==============================================================================
# SUSPICIOUS PATTERNS & DETECTION
# ==============================================================================

SUSPICIOUS_PATTERNS = {
    # Brute force detection
    'brute_force': {
        'enabled': True,
        'threshold': 5,  # attempts in window
        'time_window': 300,  # seconds
        'target_services': ['ssh', 'rdp', 'http', 'ftp'],
        'severity': 'high'
    },
    
    # Port scanning detection
    'port_scan': {
        'enabled': True,
        'threshold': 10,  # connections in window
        'time_window': 60,  # seconds
        'severity': 'high'
    },
    
    # Unusual port activity
    'unusual_ports': {
        'enabled': True,
        'high_risk_ports': [
            23,      # Telnet
            445,     # SMB (Windows sharing)
            3389,    # RDP
            3306,    # MySQL
            5432,    # PostgreSQL
            6379,    # Redis
            27017,   # MongoDB
            9200     # Elasticsearch
        ],
        'severity': 'medium'
    },
    
    # Data exfiltration detection
    'data_exfil': {
        'enabled': True,
        'threshold_mbps': 50,  # Trigger if sustained >50 Mbps
        'duration_seconds': 300,  # Over 5 minutes
        'severity': 'high'
    },
    
    # Unknown device connections
    'unknown_device': {
        'enabled': True,
        'severity': 'medium',
        'auto_learn': False  # Set True to auto-add new devices
    }
}


# ==============================================================================
# WHITELIST & TRUSTED SERVICES
# ==============================================================================

# IPs that should NEVER trigger alerts
TRUSTED_IPS = {
    '192.168.0.1': 'FRITZ!Box gateway',
    '8.8.8.8': 'Google DNS',
    '8.8.4.4': 'Google DNS secondary',
    '1.1.1.1': 'Cloudflare DNS',
    '1.0.0.1': 'Cloudflare DNS secondary',
    '9.9.9.9': 'Quad9 DNS',
    '208.67.222.222': 'OpenDNS',
}

# IP ranges that are trusted (CIDR notation)
TRUSTED_RANGES = [
    '192.168.0.0/16',    # Local network
    '10.0.0.0/8',        # Local network
    '172.16.0.0/12',     # Local network
    '127.0.0.0/8',       # Localhost
]

# Domains that are trusted (regex patterns)
TRUSTED_DOMAINS = [
    r'.*\.google\.com',
    r'.*\.apple\.com',
    r'.*\.microsoft\.com',
    r'.*\.cloudflare\.com',
]


# ==============================================================================
# LOGGING SETTINGS
# ==============================================================================

LOGGING_CONFIG = {
    # Log level: DEBUG, INFO, WARNING, ERROR, CRITICAL
    'level': 'DEBUG',
    
    # Log file location
    'file': 'fritz_monitor.log',
    
    # Maximum log file size (MB) before rotation
    'max_size_mb': 50,
    
    # Number of rotated logs to keep
    'backup_count': 10,
    
    # Include timestamps
    'timestamps': True,
    
    # Include function names
    'function_names': True,
}


# ==============================================================================
# KNOWLEDGE BASE SETTINGS
# ==============================================================================

KNOWLEDGE_BASE_CONFIG = {
    # Path to knowledge base file
    'database_file': 'network_knowledge_base.json',
    
    # Auto-save interval (seconds)
    'auto_save_interval': 300,
    
    # Auto-learn new devices
    'auto_learn': False,
    
    # Learn baseline from current traffic
    'learn_baseline': False,
}


# ==============================================================================
# ADVANCED / DEBUG
# ==============================================================================

ADVANCED_CONFIG = {
    # Enable verbose debug logging
    'debug_mode': True,
    
    # Log all parsed log lines
    'log_parsing_debug': True,
    
    # Simulate alerts without sending them (for testing)
    'dry_run': True,
    
    # Save each alert to separate JSON file
    'archive_alerts': True,
    'archive_dir': 'alerts_archive',
    
    # Network connectivity check before running
    'check_connectivity': True,
    
    # Timeout for FRITZ!Box responses (seconds)
    'fritz_timeout': 10,
}


# ==============================================================================
# USAGE EXAMPLES
# ==============================================================================

"""
Quick Start - Select ONE Alert Method:

1. Console (default):
   export ALERT_METHOD="console"1
   python fritz_monitor.py

2. Desktop Notifications:
   pip install win10toast  # Windows only
   export ALERT_METHOD="desktop"
   python fritz_monitor.py

3. Slack:
   export ALERT_METHOD="webhook"
   export WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
   python fritz_monitor.py

4. Email:
   pip install secure-smtplib
   # Set EMAIL_CONFIG above
   export ALERT_METHOD="email"
   python fritz_monitor.py

5. Discord:
   export ALERT_METHOD="webhook"
   export WEBHOOK_URL="https://discordapp.com/api/webhooks/YOUR/URL"
   python fritz_monitor.py
"""


# ==============================================================================
# INTEGRATION HELPERS
# ==============================================================================

def get_config(section: str = None):
    """Get configuration dictionary.
    
    Args:
        section: Optional section to retrieve (fritz, monitoring, alerts, etc.)
        
    Returns:
        Dictionary with configuration for the section, or entire config if no section specified.
        Safely returns defaults for missing values.
    """
    config = {
        'fritz': FRITZ_CONFIG,
        'monitoring': MONITORING_CONFIG,
        'alerts': {
            'method': ALERT_METHOD,
            'desktop': DESKTOP_ALERTS,
            'email': EMAIL_CONFIG,
            'webhook': WEBHOOK_CONFIG
        },
        'traffic': TRUSTED_TRAFFIC_PATTERNS,
        'detection': SUSPICIOUS_PATTERNS,
        'whitelist': {
            'ips': TRUSTED_IPS,
            'ranges': TRUSTED_RANGES,
            'domains': TRUSTED_DOMAINS
        },
        'logging': LOGGING_CONFIG,
        'knowledge_base': KNOWLEDGE_BASE_CONFIG,
        'advanced': ADVANCED_CONFIG
    }
    
    if section is None:
        return config
    
    # Return section if it exists, otherwise return empty dict
    return config.get(section, {})


if __name__ == '__main__':
    # Print example configuration
    import json
    print(json.dumps(get_config(), indent=2, default=str))
