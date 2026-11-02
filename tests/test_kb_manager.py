"""Unit tests for kb_manager.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock

from kb_manager import _validate_mac, _validate_ip, KnowledgeBaseManager
from fritz_monitor_macos import KnowledgeBase


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_manager(kb_data: dict) -> KnowledgeBaseManager:
    """Create a KnowledgeBaseManager with a mocked KnowledgeBase."""
    mgr = KnowledgeBaseManager.__new__(KnowledgeBaseManager)
    kb = MagicMock(spec=KnowledgeBase)
    kb.data = kb_data
    mgr.kb = kb
    return mgr


def _captured_print(fn, *args, **kwargs) -> str:
    """Call fn and return everything it printed as a single string."""
    with patch('builtins.print') as mock_print:
        fn(*args, **kwargs)
    return '\n'.join(
        ' '.join(str(a) for a in call_obj.args)
        for call_obj in mock_print.call_args_list
    )


# ---------------------------------------------------------------------------
# _validate_mac
# ---------------------------------------------------------------------------

class TestValidateMac(unittest.TestCase):

    VALID = [
        'AA:BB:CC:DD:EE:FF',
        'aa:bb:cc:dd:ee:ff',
        'A1:B2:C3:D4:E5:F6',
        '00:00:00:00:00:00',
        'FF:FF:FF:FF:FF:FF',
    ]
    INVALID = [
        '',
        'AA:BB:CC:DD:EE',           # 5 octets
        'AA:BB:CC:DD:EE:FF:00',     # 7 octets
        'AABBCCDDEEFF',             # no separators
        'AA-BB-CC-DD-EE-FF',        # hyphen separator
        'GG:HH:II:JJ:KK:LL',        # non-hex chars
        'AA:BB:CC:DD:EE:GG',        # invalid last octet
        ':BB:CC:DD:EE:FF',          # leading colon
    ]

    def test_valid_addresses_accepted(self):
        for mac in self.VALID:
            with self.subTest(mac=mac):
                self.assertTrue(_validate_mac(mac))

    def test_invalid_addresses_rejected(self):
        for mac in self.INVALID:
            with self.subTest(mac=mac):
                self.assertFalse(_validate_mac(mac))


# ---------------------------------------------------------------------------
# _validate_ip
# ---------------------------------------------------------------------------

class TestValidateIp(unittest.TestCase):

    VALID = [
        '192.168.178.1',
        '0.0.0.0',
        '255.255.255.255',
        '10.0.0.1',
        '::1',
        '2001:db8::1',
        'fe80::1',
    ]
    INVALID = [
        '',
        'not-an-ip',
        '256.0.0.1',
        '192.168',
        '192.168.1.1.1',
        'abc',
        '999.999.999.999',
        ' 192.168.1.1',     # leading space
    ]

    def test_valid_addresses_accepted(self):
        for ip in self.VALID:
            with self.subTest(ip=ip):
                self.assertTrue(_validate_ip(ip))

    def test_invalid_addresses_rejected(self):
        for ip in self.INVALID:
            with self.subTest(ip=ip):
                self.assertFalse(_validate_ip(ip))


# ---------------------------------------------------------------------------
# list_devices
# ---------------------------------------------------------------------------

class TestListDevices(unittest.TestCase):

    def test_empty_devices_shows_message(self):
        mgr = _make_manager({'known_devices': {}})
        output = _captured_print(mgr.list_devices)
        self.assertIn('No devices', output)

    def test_shows_hostname_and_ip(self):
        mgr = _make_manager({'known_devices': {
            'aa:bb:cc:dd:ee:ff': {
                'mac': 'AA:BB:CC:DD:EE:FF',
                'ip': '192.168.178.5',
                'hostname': 'MyLaptop',
                'type': 'laptop',
            }
        }})
        output = _captured_print(mgr.list_devices)
        self.assertIn('MyLaptop', output)
        self.assertIn('192.168.178.5', output)

    def test_shows_count(self):
        mgr = _make_manager({'known_devices': {
            'aa:00:00:00:00:01': {'mac': 'AA:00:00:00:00:01', 'ip': '10.0.0.1',
                                  'hostname': 'Dev1', 'type': 'other'},
            'aa:00:00:00:00:02': {'mac': 'AA:00:00:00:00:02', 'ip': '10.0.0.2',
                                  'hostname': 'Dev2', 'type': 'other'},
        }})
        output = _captured_print(mgr.list_devices)
        self.assertIn('2', output)


# ---------------------------------------------------------------------------
# list_whitelist / list_suspicious
# ---------------------------------------------------------------------------

class TestListWhitelist(unittest.TestCase):

    def test_empty_shows_message(self):
        mgr = _make_manager({'whitelisted_ips': []})
        output = _captured_print(mgr.list_whitelist)
        self.assertIn('No whitelisted', output)

    def test_shows_ips(self):
        mgr = _make_manager({'whitelisted_ips': ['8.8.8.8', '1.1.1.1']})
        output = _captured_print(mgr.list_whitelist)
        self.assertIn('8.8.8.8', output)
        self.assertIn('1.1.1.1', output)

    def test_accepts_set_type(self):
        mgr = _make_manager({'whitelisted_ips': {'8.8.8.8'}})
        output = _captured_print(mgr.list_whitelist)
        self.assertIn('8.8.8.8', output)


class TestListSuspiciousIps(unittest.TestCase):

    def test_empty_shows_message(self):
        mgr = _make_manager({'suspicious_ips': []})
        output = _captured_print(mgr.list_suspicious)
        self.assertIn('No suspicious IPs', output)

    def test_shows_flagged_ip(self):
        mgr = _make_manager({'suspicious_ips': ['1.2.3.4']})
        output = _captured_print(mgr.list_suspicious)
        self.assertIn('1.2.3.4', output)


# ---------------------------------------------------------------------------
# list_keywords
# ---------------------------------------------------------------------------

class TestListKeywords(unittest.TestCase):

    def _mgr(self):
        return _make_manager({
            'suspicious_keywords': ['gescheitert', 'verweigert'],
            'critical_keywords': ['falsches kennwort'],
        })

    def test_lists_suspicious_keywords(self):
        output = _captured_print(self._mgr().list_keywords, 'suspicious_keywords')
        self.assertIn('gescheitert', output)
        self.assertIn('verweigert', output)

    def test_lists_critical_keywords(self):
        output = _captured_print(self._mgr().list_keywords, 'critical_keywords')
        self.assertIn('falsches kennwort', output)

    def test_empty_list_shows_message(self):
        mgr = _make_manager({'suspicious_keywords': []})
        output = _captured_print(mgr.list_keywords, 'suspicious_keywords')
        self.assertIn('No suspicious', output)

    def test_shows_count(self):
        output = _captured_print(self._mgr().list_keywords, 'suspicious_keywords')
        self.assertIn('2', output)


# ---------------------------------------------------------------------------
# add_keyword_interactive
# ---------------------------------------------------------------------------

class TestAddKeyword(unittest.TestCase):

    def _mgr(self):
        return _make_manager({
            'suspicious_keywords': ['gescheitert'],
            'critical_keywords': [],
        })

    def test_adds_new_keyword(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='neues keyword'), \
             patch('builtins.print'):
            mgr.add_keyword_interactive('suspicious_keywords')
        self.assertIn('neues keyword', mgr.kb.data['suspicious_keywords'])
        mgr.kb.save.assert_called_once()

    def test_normalises_to_lowercase(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='UPPERCASE'), \
             patch('builtins.print'):
            mgr.add_keyword_interactive('suspicious_keywords')
        self.assertIn('uppercase', mgr.kb.data['suspicious_keywords'])
        self.assertNotIn('UPPERCASE', mgr.kb.data['suspicious_keywords'])

    def test_empty_input_rejected(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='   '), \
             patch('builtins.print'):
            mgr.add_keyword_interactive('suspicious_keywords')
        mgr.kb.save.assert_not_called()

    def test_duplicate_rejected(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='gescheitert'), \
             patch('builtins.print'):
            mgr.add_keyword_interactive('suspicious_keywords')
        # list length unchanged, save not called
        self.assertEqual(len(mgr.kb.data['suspicious_keywords']), 1)
        mgr.kb.save.assert_not_called()

    def test_adds_to_critical_list(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='brute force'), \
             patch('builtins.print'):
            mgr.add_keyword_interactive('critical_keywords')
        self.assertIn('brute force', mgr.kb.data['critical_keywords'])
        mgr.kb.save.assert_called_once()

    def test_print_confirms_addition(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='test kw'):
            output = _captured_print(mgr.add_keyword_interactive, 'suspicious_keywords')
        self.assertIn('test kw', output)


# ---------------------------------------------------------------------------
# delete_keyword_interactive
# ---------------------------------------------------------------------------

class TestDeleteKeyword(unittest.TestCase):

    def _mgr(self):
        return _make_manager({
            'suspicious_keywords': ['gescheitert', 'verweigert', 'fehlgeschlagen'],
        })

    def test_delete_by_number(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='1'), patch('builtins.print'):
            mgr.delete_keyword_interactive('suspicious_keywords')
        self.assertNotIn('gescheitert', mgr.kb.data['suspicious_keywords'])
        mgr.kb.save.assert_called_once()

    def test_delete_by_keyword_text(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='verweigert'), patch('builtins.print'):
            mgr.delete_keyword_interactive('suspicious_keywords')
        self.assertNotIn('verweigert', mgr.kb.data['suspicious_keywords'])
        mgr.kb.save.assert_called_once()

    def test_remaining_keywords_intact_after_delete(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='1'), patch('builtins.print'):
            mgr.delete_keyword_interactive('suspicious_keywords')
        self.assertEqual(len(mgr.kb.data['suspicious_keywords']), 2)

    def test_cancel_with_zero_no_change(self):
        mgr = self._mgr()
        original = list(mgr.kb.data['suspicious_keywords'])
        with patch('builtins.input', return_value='0'), patch('builtins.print'):
            mgr.delete_keyword_interactive('suspicious_keywords')
        self.assertEqual(mgr.kb.data['suspicious_keywords'], original)
        mgr.kb.save.assert_not_called()

    def test_invalid_number_no_change(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='99'), patch('builtins.print'):
            mgr.delete_keyword_interactive('suspicious_keywords')
        mgr.kb.save.assert_not_called()

    def test_nonexistent_text_no_change(self):
        mgr = self._mgr()
        with patch('builtins.input', return_value='nichtvorhanden'), patch('builtins.print'):
            mgr.delete_keyword_interactive('suspicious_keywords')
        mgr.kb.save.assert_not_called()

    def test_empty_list_shows_message(self):
        mgr = _make_manager({'suspicious_keywords': []})
        output = _captured_print(mgr.delete_keyword_interactive, 'suspicious_keywords')
        self.assertIn('No suspicious', output)
        mgr.kb.save.assert_not_called()


if __name__ == '__main__':
    unittest.main()
