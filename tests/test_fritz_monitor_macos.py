"""Unit tests for fritz_monitor_macos.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import tempfile
import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

import requests

from fritz_monitor_macos import (
    MacOSNotificationManager,
    MacOSPowerManager,
    FRITZBoxMonitor,
    KnowledgeBase,
    LogAnalyzer,
    AlertHandler,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(msg: str, ts: datetime = None) -> dict:
    """Build a minimal log-event dict."""
    return {
        'id': '1',
        'group': '9',
        'date': '23.04.26',
        'time': '10:00:00',
        'msg': msg,
        'timestamp': ts or datetime(2026, 4, 23, 10, 0, 0),
    }


def _make_kb_mock(suspicious=None, critical=None) -> MagicMock:
    """Return a MagicMock KnowledgeBase with controllable keyword lists."""
    kb = MagicMock()
    kb.data = {
        'suspicious_keywords': suspicious if suspicious is not None else ['gescheitert', 'fehlgeschlagen'],
        'critical_keywords':   critical   if critical   is not None else ['falsches kennwort'],
    }
    kb.is_whitelisted = MagicMock(return_value=False)
    kb.is_known_mac   = MagicMock(return_value=False)
    kb.is_known_ip    = MagicMock(return_value=False)
    return kb


# ---------------------------------------------------------------------------
# MacOSNotificationManager._sanitize_for_applescript
# ---------------------------------------------------------------------------

class TestSanitizeForAppleScript(unittest.TestCase):

    def test_plain_text_unchanged(self):
        self.assertEqual(
            MacOSNotificationManager._sanitize_for_applescript('Hello World'),
            'Hello World',
        )

    def test_newline_replaced(self):
        result = MacOSNotificationManager._sanitize_for_applescript('line1\nline2')
        self.assertNotIn('\n', result)
        self.assertIn('line1', result)
        self.assertIn('line2', result)

    def test_tab_replaced(self):
        result = MacOSNotificationManager._sanitize_for_applescript('col1\tcol2')
        self.assertNotIn('\t', result)

    def test_backslash_escaped(self):
        result = MacOSNotificationManager._sanitize_for_applescript('a\\b')
        self.assertIn('\\\\', result)

    def test_double_quote_escaped(self):
        result = MacOSNotificationManager._sanitize_for_applescript('say "hello"')
        self.assertIn('\\"', result)
        self.assertNotIn('"hello"', result)

    def test_single_quote_escaped(self):
        result = MacOSNotificationManager._sanitize_for_applescript("it's fine")
        self.assertIn("\\'", result)


# ---------------------------------------------------------------------------
# MacOSNotificationManager.notify
# ---------------------------------------------------------------------------

class TestNotify(unittest.TestCase):

    def _ok_run(self):
        m = MagicMock()
        m.returncode = 0
        return m

    def _fail_run(self):
        m = MagicMock()
        m.returncode = 1
        m.stderr = 'error msg'
        return m

    def test_returns_true_on_success(self):
        with patch('subprocess.run', return_value=self._ok_run()):
            self.assertTrue(MacOSNotificationManager.notify('T', 'M'))

    def test_returns_false_on_nonzero_returncode(self):
        with patch('subprocess.run', return_value=self._fail_run()):
            self.assertFalse(MacOSNotificationManager.notify('T', 'M'))

    def test_calls_osascript(self):
        with patch('subprocess.run', return_value=self._ok_run()) as mock_run:
            MacOSNotificationManager.notify('T', 'M')
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], 'osascript')

    def test_returns_false_on_exception(self):
        with patch('subprocess.run', side_effect=Exception('boom')):
            self.assertFalse(MacOSNotificationManager.notify('T', 'M'))

    def test_title_and_message_appear_in_script(self):
        with patch('subprocess.run', return_value=self._ok_run()) as mock_run:
            MacOSNotificationManager.notify('MyTitle', 'MyMessage')
        script_arg = mock_run.call_args[0][0][2]
        self.assertIn('MyTitle', script_arg)
        self.assertIn('MyMessage', script_arg)


# ---------------------------------------------------------------------------
# MacOSNotificationManager.send_alert_dialog
# ---------------------------------------------------------------------------

class TestSendAlertDialog(unittest.TestCase):

    def test_returns_true_on_success(self):
        with patch('subprocess.run', return_value=MagicMock()):
            self.assertTrue(MacOSNotificationManager.send_alert_dialog('T', 'M'))

    def test_returns_false_on_exception(self):
        with patch('subprocess.run', side_effect=Exception('boom')):
            self.assertFalse(MacOSNotificationManager.send_alert_dialog('T', 'M'))

    def test_invalid_alert_style_falls_back_to_warning(self):
        with patch('subprocess.run', return_value=MagicMock()) as mock_run:
            MacOSNotificationManager.send_alert_dialog('T', 'M', alert_style='inject; rm -rf /')
        script_arg = mock_run.call_args[0][0][2]
        self.assertIn('warning', script_arg)
        self.assertNotIn('inject', script_arg)

    def test_valid_styles_accepted(self):
        for style in ('warning', 'critical', 'informational'):
            with self.subTest(style=style):
                with patch('subprocess.run', return_value=MagicMock()) as mock_run:
                    MacOSNotificationManager.send_alert_dialog('T', 'M', alert_style=style)
                script_arg = mock_run.call_args[0][0][2]
                self.assertIn(style, script_arg)

    def test_calls_osascript(self):
        with patch('subprocess.run', return_value=MagicMock()) as mock_run:
            MacOSNotificationManager.send_alert_dialog('T', 'M')
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], 'osascript')


# ---------------------------------------------------------------------------
# MacOSPowerManager.is_system_awake
# ---------------------------------------------------------------------------

class TestIsSystemAwake(unittest.TestCase):

    def _pmset(self, stdout='', returncode=0):
        m = MagicMock()
        m.stdout = stdout
        m.returncode = returncode
        return m

    def test_awake_when_state_positive(self):
        with patch('subprocess.run', return_value=self._pmset('Current Power State: 4')):
            self.assertTrue(MacOSPowerManager.is_system_awake())

    def test_sleeping_when_state_zero(self):
        with patch('subprocess.run', return_value=self._pmset('Current Power State: 0')):
            self.assertFalse(MacOSPowerManager.is_system_awake())

    def test_defaults_to_awake_when_power_state_line_absent(self):
        with patch('subprocess.run', return_value=self._pmset('something else entirely')):
            self.assertTrue(MacOSPowerManager.is_system_awake())

    def test_defaults_to_awake_on_subprocess_exception(self):
        with patch('subprocess.run', side_effect=Exception('boom')):
            self.assertTrue(MacOSPowerManager.is_system_awake())

    def test_defaults_to_awake_when_state_not_parseable(self):
        with patch('subprocess.run', return_value=self._pmset('Current Power State: NaN')):
            self.assertTrue(MacOSPowerManager.is_system_awake())


# ---------------------------------------------------------------------------
# FRITZBoxMonitor.__init__
# ---------------------------------------------------------------------------

class TestFRITZBoxMonitorInit(unittest.TestCase):

    def test_default_hostname(self):
        self.assertEqual(FRITZBoxMonitor().hostname, '192.168.0.1')

    def test_default_username(self):
        self.assertEqual(FRITZBoxMonitor().username, 'logger')

    def test_default_password_empty(self):
        self.assertEqual(FRITZBoxMonitor().password, '')

    def test_custom_values_stored(self):
        fritz = FRITZBoxMonitor('192.168.178.1', 'admin', 'secret')
        self.assertEqual(fritz.hostname, '192.168.178.1')
        self.assertEqual(fritz.username, 'admin')
        self.assertEqual(fritz.password, 'secret')

    def test_last_log_timestamp_is_epoch(self):
        self.assertEqual(FRITZBoxMonitor().last_log_timestamp, datetime(1970, 1, 1))

    def test_base_url_uses_port_49000(self):
        fritz = FRITZBoxMonitor('192.168.178.1')
        self.assertIn('49000', fritz.base_url)


# ---------------------------------------------------------------------------
# FRITZBoxMonitor.test_connection
# ---------------------------------------------------------------------------

class TestFRITZBoxTestConnection(unittest.TestCase):

    def _fritz(self):
        return FRITZBoxMonitor('192.168.178.1', 'logger', '')

    def _mock_response(self, status_code):
        m = MagicMock()
        m.status_code = status_code
        return m

    def test_returns_true_on_200(self):
        fritz = self._fritz()
        fritz.session.get = MagicMock(return_value=self._mock_response(200))
        self.assertTrue(fritz.test_connection())

    def test_returns_true_on_401(self):
        fritz = self._fritz()
        fritz.session.get = MagicMock(return_value=self._mock_response(401))
        self.assertTrue(fritz.test_connection())

    def test_returns_false_on_500(self):
        fritz = self._fritz()
        fritz.session.get = MagicMock(return_value=self._mock_response(500))
        self.assertFalse(fritz.test_connection())

    def test_returns_false_on_connection_error(self):
        fritz = self._fritz()
        fritz.session.get = MagicMock(side_effect=requests.exceptions.ConnectionError)
        self.assertFalse(fritz.test_connection())

    def test_returns_false_on_generic_exception(self):
        fritz = self._fritz()
        fritz.session.get = MagicMock(side_effect=Exception('network down'))
        self.assertFalse(fritz.test_connection())

    def test_sets_last_successful_connect_on_success(self):
        fritz = self._fritz()
        fritz.session.get = MagicMock(return_value=self._mock_response(200))
        fritz.test_connection()
        self.assertIsNotNone(fritz.last_successful_connect)


# ---------------------------------------------------------------------------
# FRITZBoxMonitor._parse_log_path_response
# ---------------------------------------------------------------------------

_SOAP_LOG_PATH_XML = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:X_AVM-DE_GetDeviceLogPathResponse
        xmlns:u="urn:dslforum-org:service:DeviceInfo:1">
      <NewDeviceLogPath>/devicelog.lua?sid=abcdef1234</NewDeviceLogPath>
    </u:X_AVM-DE_GetDeviceLogPathResponse>
  </s:Body>
</s:Envelope>"""


class TestParseLogPathResponse(unittest.TestCase):

    def _fritz(self):
        return FRITZBoxMonitor()

    def test_extracts_path(self):
        fritz = self._fritz()
        path = fritz._parse_log_path_response(_SOAP_LOG_PATH_XML)
        self.assertEqual(path, '/devicelog.lua?sid=abcdef1234')

    def test_returns_none_on_malformed_xml(self):
        fritz = self._fritz()
        self.assertIsNone(fritz._parse_log_path_response('not xml'))

    def test_returns_none_when_element_missing(self):
        fritz = self._fritz()
        xml = ('<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
               '<s:Body></s:Body></s:Envelope>')
        self.assertIsNone(fritz._parse_log_path_response(xml))


# ---------------------------------------------------------------------------
# FRITZBoxMonitor._fetch_log_xml  (path-validation guard)
# ---------------------------------------------------------------------------

class TestFetchLogXmlPathValidation(unittest.TestCase):

    def _fritz(self):
        return FRITZBoxMonitor()

    def test_rejects_path_without_leading_slash(self):
        fritz = self._fritz()
        self.assertEqual(fritz._fetch_log_xml('devicelog.lua?sid=x'), [])

    def test_rejects_path_with_double_dot(self):
        fritz = self._fritz()
        self.assertEqual(fritz._fetch_log_xml('/../../etc/passwd'), [])

    def test_rejects_path_with_newline(self):
        fritz = self._fritz()
        self.assertEqual(fritz._fetch_log_xml('/valid\npath'), [])

    def test_valid_path_reaches_session_get(self):
        fritz = self._fritz()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<root></root>'
        fritz.session.get = MagicMock(return_value=mock_resp)
        fritz._fetch_log_xml('/devicelog.lua?sid=x')
        fritz.session.get.assert_called_once()

    def test_non_200_response_returns_empty(self):
        fritz = self._fritz()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        fritz.session.get = MagicMock(return_value=mock_resp)
        self.assertEqual(fritz._fetch_log_xml('/devicelog.lua?sid=x'), [])


# ---------------------------------------------------------------------------
# FRITZBoxMonitor._parse_log_xml
# ---------------------------------------------------------------------------

_LOG_XML = """<root>
<Event>
    <id>1</id><group>9</group>
    <date>23.04.26</date><time>10:30:00</time>
    <msg>WLAN-Gerät angemeldet: Testdevice, IP 192.168.178.5, MAC aa:bb:cc:dd:ee:ff</msg>
</Event>
<Event>
    <id>2</id><group>9</group>
    <date>23.04.26</date><time>09:00:00</time>
    <msg>Verbindung getrennt</msg>
</Event>
</root>"""


class TestParseLogXml(unittest.TestCase):

    def _fritz(self):
        return FRITZBoxMonitor()

    def test_returns_both_events_from_epoch(self):
        fritz = self._fritz()
        events = fritz._parse_log_xml(_LOG_XML)
        self.assertEqual(len(events), 2)

    def test_event_has_required_keys(self):
        fritz = self._fritz()
        events = fritz._parse_log_xml(_LOG_XML)
        for key in ('id', 'group', 'date', 'time', 'msg', 'timestamp'):
            with self.subTest(key=key):
                self.assertIn(key, events[0])

    def test_timestamp_parsed_correctly(self):
        fritz = self._fritz()
        events = fritz._parse_log_xml(_LOG_XML)
        ev1 = next(e for e in events if e['id'] == '1')
        self.assertEqual(ev1['timestamp'], datetime(2026, 4, 23, 10, 30, 0))

    def test_filters_events_not_newer_than_last_timestamp(self):
        fritz = self._fritz()
        fritz.last_log_timestamp = datetime(2026, 4, 23, 10, 0, 0)
        events = fritz._parse_log_xml(_LOG_XML)
        # Only the 10:30 event is newer
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['id'], '1')

    def test_updates_last_log_timestamp_to_newest(self):
        fritz = self._fritz()
        fritz._parse_log_xml(_LOG_XML)
        self.assertEqual(fritz.last_log_timestamp, datetime(2026, 4, 23, 10, 30, 0))

    def test_returns_empty_on_invalid_xml(self):
        fritz = self._fritz()
        self.assertEqual(fritz._parse_log_xml('not xml at all'), [])

    def test_empty_root_returns_empty_list(self):
        fritz = self._fritz()
        self.assertEqual(fritz._parse_log_xml('<root></root>'), [])


# ---------------------------------------------------------------------------
# KnowledgeBase._load_or_create
# ---------------------------------------------------------------------------

class TestKnowledgeBaseLoadOrCreate(unittest.TestCase):

    def test_creates_new_db_when_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            for key in ('known_devices', 'suspicious_keywords', 'critical_keywords',
                        'whitelisted_ips', 'suspicious_ips'):
                with self.subTest(key=key):
                    self.assertIn(key, kb.data)

    def test_new_db_has_default_keywords(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            self.assertGreater(len(kb.data['suspicious_keywords']), 0)
            self.assertGreater(len(kb.data['critical_keywords']), 0)

    def test_loads_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'kb.json')
            existing = {
                'known_devices': {
                    'aa:bb:cc': {'mac': 'AA:BB:CC', 'ip': '10.0.0.1', 'hostname': 'h', 'type': 'other'}
                },
                'whitelisted_ips': [],
                'suspicious_ips': [],
                'suspicious_keywords': ['existing'],
                'critical_keywords': [],
            }
            with open(path, 'w') as f:
                json.dump(existing, f)
            kb = KnowledgeBase(db_path=path)
            self.assertIn('aa:bb:cc', kb.data['known_devices'])
            self.assertEqual(kb.data['suspicious_keywords'], ['existing'])

    def test_migration_backfills_missing_keywords(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'kb.json')
            old_format = {'known_devices': {}, 'whitelisted_ips': [], 'suspicious_ips': []}
            with open(path, 'w') as f:
                json.dump(old_format, f)
            kb = KnowledgeBase(db_path=path)
            self.assertIn('suspicious_keywords', kb.data)
            self.assertIn('critical_keywords', kb.data)
            self.assertGreater(len(kb.data['suspicious_keywords']), 0)


# ---------------------------------------------------------------------------
# KnowledgeBase.save
# ---------------------------------------------------------------------------

class TestKnowledgeBaseSave(unittest.TestCase):

    def test_creates_file_on_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'kb.json')
            kb = KnowledgeBase(db_path=path)
            kb.save()
            self.assertTrue(os.path.exists(path))

    def test_saved_file_is_valid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'kb.json')
            kb = KnowledgeBase(db_path=path)
            kb.save()
            with open(path) as f:
                data = json.load(f)
            self.assertIn('known_devices', data)

    def test_sets_serialised_as_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'kb.json')
            kb = KnowledgeBase(db_path=path)
            kb.data['whitelisted_ips'] = {'1.2.3.4', '5.6.7.8'}
            kb.data['suspicious_ips'] = {'9.9.9.9'}
            kb.save()
            with open(path) as f:
                saved = json.load(f)
            self.assertIsInstance(saved['whitelisted_ips'], list)
            self.assertIsInstance(saved['suspicious_ips'], list)


# ---------------------------------------------------------------------------
# KnowledgeBase.add_device
# ---------------------------------------------------------------------------

class TestKnowledgeBaseAddDevice(unittest.TestCase):

    def test_device_stored_with_lowercase_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.add_device('AA:BB:CC:DD:EE:FF', '10.0.0.1', 'Host', 'laptop')
            self.assertIn('aa:bb:cc:dd:ee:ff', kb.data['known_devices'])

    def test_device_fields_stored_correctly(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.add_device('AA:BB:CC:DD:EE:FF', '10.0.0.1', 'Host', 'laptop')
            d = kb.data['known_devices']['aa:bb:cc:dd:ee:ff']
            self.assertEqual(d['ip'], '10.0.0.1')
            self.assertEqual(d['hostname'], 'Host')
            self.assertEqual(d['type'], 'laptop')
            self.assertEqual(d['mac'], 'AA:BB:CC:DD:EE:FF')

    def test_add_device_saves_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'kb.json')
            kb = KnowledgeBase(db_path=path)
            kb.add_device('AA:BB:CC:DD:EE:FF', '10.0.0.1')
            with open(path) as f:
                saved = json.load(f)
            self.assertIn('aa:bb:cc:dd:ee:ff', saved['known_devices'])


# ---------------------------------------------------------------------------
# KnowledgeBase.add_baseline_traffic
# ---------------------------------------------------------------------------

class TestKnowledgeBaseAddBaselineTraffic(unittest.TestCase):

    def test_entry_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.add_baseline_traffic('192.168.178.5', '8.8.8.8', 'UDP', 53)
            self.assertIn('192.168.178.5 -> 8.8.8.8:53/UDP', kb.data['baseline_traffic'])

    def test_count_increments_on_repeat(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.add_baseline_traffic('192.168.178.5', '8.8.8.8', 'UDP', 53)
            kb.add_baseline_traffic('192.168.178.5', '8.8.8.8', 'UDP', 53)
            entry = kb.data['baseline_traffic']['192.168.178.5 -> 8.8.8.8:53/UDP']
            self.assertEqual(entry['count'], 2)


# ---------------------------------------------------------------------------
# KnowledgeBase.whitelist_ip / is_whitelisted
# ---------------------------------------------------------------------------

class TestKnowledgeBaseWhitelist(unittest.TestCase):

    def test_whitelisted_ip_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.whitelist_ip('8.8.8.8')
            self.assertTrue(kb.is_whitelisted('8.8.8.8'))

    def test_non_whitelisted_ip_not_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            self.assertFalse(kb.is_whitelisted('9.9.9.9'))

    def test_is_whitelisted_handles_list_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.data['whitelisted_ips'] = ['1.1.1.1']
            self.assertTrue(kb.is_whitelisted('1.1.1.1'))
            self.assertFalse(kb.is_whitelisted('2.2.2.2'))


# ---------------------------------------------------------------------------
# KnowledgeBase.is_known_ip / is_known_mac
# ---------------------------------------------------------------------------

class TestKnowledgeBaseIsKnownIpMac(unittest.TestCase):

    def _kb(self, tmpdir):
        kb = KnowledgeBase(db_path=os.path.join(tmpdir, 'kb.json'))
        kb.add_device('AA:BB:CC:DD:EE:FF', '192.168.178.5', 'Host')
        return kb

    def test_known_ip_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(self._kb(tmp).is_known_ip('192.168.178.5'))

    def test_unknown_ip_not_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(self._kb(tmp).is_known_ip('10.0.0.99'))

    def test_known_mac_uppercase(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(self._kb(tmp).is_known_mac('AA:BB:CC:DD:EE:FF'))

    def test_known_mac_lowercase(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(self._kb(tmp).is_known_mac('aa:bb:cc:dd:ee:ff'))

    def test_unknown_mac_not_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(self._kb(tmp).is_known_mac('11:22:33:44:55:66'))


# ---------------------------------------------------------------------------
# KnowledgeBase.flag_suspicious
# ---------------------------------------------------------------------------

class TestKnowledgeBaseFlagSuspicious(unittest.TestCase):

    def test_flagged_ip_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.flag_suspicious('1.2.3.4')
            ips = kb.data.get('suspicious_ips', set())
            if isinstance(ips, list):
                ips = set(ips)
            self.assertIn('1.2.3.4', ips)

    def test_flag_multiple_ips(self):
        with tempfile.TemporaryDirectory() as tmp:
            kb = KnowledgeBase(db_path=os.path.join(tmp, 'kb.json'))
            kb.flag_suspicious('1.2.3.4')
            kb.flag_suspicious('5.6.7.8')
            ips = kb.data.get('suspicious_ips', set())
            if isinstance(ips, list):
                ips = set(ips)
            self.assertIn('5.6.7.8', ips)


# ---------------------------------------------------------------------------
# LogAnalyzer.__init__
# ---------------------------------------------------------------------------

class TestLogAnalyzerInit(unittest.TestCase):

    def test_loads_keywords_from_kb(self):
        kb = _make_kb_mock()
        analyzer = LogAnalyzer(kb)
        self.assertEqual(analyzer.suspicious_keywords, ['gescheitert', 'fehlgeschlagen'])
        self.assertEqual(analyzer.critical_keywords, ['falsches kennwort'])

    def test_dedup_dict_starts_empty(self):
        analyzer = LogAnalyzer(_make_kb_mock())
        self.assertEqual(len(analyzer._recent_alerts), 0)

    def test_last_analysis_time_is_none(self):
        analyzer = LogAnalyzer(_make_kb_mock())
        self.assertIsNone(analyzer.last_analysis_time)


# ---------------------------------------------------------------------------
# LogAnalyzer._extract_device_info
# ---------------------------------------------------------------------------

class TestExtractDeviceInfo(unittest.TestCase):

    def _analyzer(self):
        return LogAnalyzer(_make_kb_mock(suspicious=[], critical=[]))

    def test_extracts_hostname_ip_mac(self):
        analyzer = self._analyzer()
        msg = 'WLAN 2.4GHz, MyDevice, IP 192.168.178.5, MAC aa:bb:cc:dd:ee:ff, angemeldet'
        info = analyzer._extract_device_info(msg)
        self.assertIsNotNone(info)
        self.assertEqual(info['hostname'], 'MyDevice')
        self.assertEqual(info['ip'], '192.168.178.5')
        self.assertEqual(info['mac'], 'aa:bb:cc:dd:ee:ff')

    def test_strips_repeater_prefix(self):
        analyzer = self._analyzer()
        msg = '[fritz.repeater] WLAN 2.4GHz, MyDevice, IP 192.168.178.5, MAC aa:bb:cc:dd:ee:ff'
        info = analyzer._extract_device_info(msg)
        self.assertIsNotNone(info)
        self.assertEqual(info['hostname'], 'MyDevice')

    def test_fallback_ip_and_mac_only(self):
        analyzer = self._analyzer()
        msg = 'WLAN connect IP 192.168.178.99, MAC 11:22:33:44:55:66'
        info = analyzer._extract_device_info(msg)
        self.assertIsNotNone(info)
        self.assertEqual(info['ip'], '192.168.178.99')
        self.assertEqual(info['mac'], '11:22:33:44:55:66')
        self.assertIsNone(info['hostname'])

    def test_returns_none_when_no_match(self):
        analyzer = self._analyzer()
        self.assertIsNone(analyzer._extract_device_info('Some unrelated message'))


# ---------------------------------------------------------------------------
# LogAnalyzer._check_log_message
# ---------------------------------------------------------------------------

class TestCheckLogMessage(unittest.TestCase):

    def _analyzer(self):
        return LogAnalyzer(_make_kb_mock())

    def test_critical_keyword_returns_critical_alert(self):
        analyzer = self._analyzer()
        result = analyzer._check_log_message('Falsches Kennwort eingegeben', _make_event(''))
        self.assertIsNotNone(result)
        self.assertEqual(result['severity'], 'critical')
        self.assertEqual(result['type'], 'critical_security_event')

    def test_suspicious_keyword_returns_suspicious_alert(self):
        analyzer = self._analyzer()
        result = analyzer._check_log_message('Verbindung gescheitert', _make_event(''))
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'suspicious_activity')

    def test_gescheitert_gives_high_severity(self):
        analyzer = self._analyzer()
        result = analyzer._check_log_message('Verbindung gescheitert', _make_event(''))
        self.assertEqual(result['severity'], 'high')

    def test_other_suspicious_keyword_gives_medium_severity(self):
        analyzer = self._analyzer()
        result = analyzer._check_log_message('Verbindung fehlgeschlagen', _make_event(''))
        self.assertEqual(result['severity'], 'medium')

    def test_unknown_device_returns_unknown_device_alert(self):
        analyzer = self._analyzer()
        msg = 'WLAN-Gerät angemeldet: NewDevice, IP 10.0.0.5, MAC 11:22:33:44:55:66'
        result = analyzer._check_log_message(msg, _make_event(msg))
        self.assertIsNotNone(result)
        self.assertEqual(result['type'], 'unknown_device')
        self.assertEqual(result['severity'], 'high')

    def test_whitelisted_ip_skipped_for_unknown_device(self):
        analyzer = self._analyzer()
        analyzer.kb.is_whitelisted = MagicMock(return_value=True)
        msg = 'WLAN-Gerät angemeldet: NewDevice, IP 10.0.0.5, MAC 11:22:33:44:55:66'
        self.assertIsNone(analyzer._check_log_message(msg, _make_event(msg)))

    def test_known_mac_skipped_for_unknown_device(self):
        analyzer = self._analyzer()
        analyzer.kb.is_known_mac = MagicMock(return_value=True)
        msg = 'WLAN-Gerät angemeldet: KnownDev, IP 10.0.0.5, MAC aa:bb:cc:dd:ee:ff'
        self.assertIsNone(analyzer._check_log_message(msg, _make_event(msg)))

    def test_known_ip_skipped_for_unknown_device(self):
        analyzer = self._analyzer()
        analyzer.kb.is_known_ip = MagicMock(return_value=True)
        msg = 'WLAN-Gerät angemeldet: KnownDev, IP 10.0.0.5, MAC aa:bb:cc:dd:ee:ff'
        self.assertIsNone(analyzer._check_log_message(msg, _make_event(msg)))

    def test_clean_message_returns_none(self):
        analyzer = self._analyzer()
        self.assertIsNone(analyzer._check_log_message('Verbindung hergestellt', _make_event('')))

    def test_alert_contains_original_message(self):
        analyzer = self._analyzer()
        msg = 'Verbindung gescheitert'
        result = analyzer._check_log_message(msg, _make_event(msg))
        self.assertEqual(result['message'], msg)


# ---------------------------------------------------------------------------
# LogAnalyzer._is_duplicate
# ---------------------------------------------------------------------------

class TestIsDuplicate(unittest.TestCase):

    def _analyzer(self):
        return LogAnalyzer(_make_kb_mock(suspicious=[], critical=[]))

    def test_first_occurrence_is_not_duplicate(self):
        analyzer = self._analyzer()
        self.assertFalse(analyzer._is_duplicate({'type': 'test', 'message': 'hello'}))

    def test_second_occurrence_is_duplicate(self):
        analyzer = self._analyzer()
        alert = {'type': 'test', 'message': 'hello'}
        analyzer._is_duplicate(alert)
        self.assertTrue(analyzer._is_duplicate(alert))

    def test_different_message_not_duplicate(self):
        analyzer = self._analyzer()
        analyzer._is_duplicate({'type': 'test', 'message': 'alpha'})
        self.assertFalse(analyzer._is_duplicate({'type': 'test', 'message': 'beta'}))

    def test_different_type_not_duplicate(self):
        analyzer = self._analyzer()
        analyzer._is_duplicate({'type': 'type_a', 'message': 'msg'})
        self.assertFalse(analyzer._is_duplicate({'type': 'type_b', 'message': 'msg'}))


# ---------------------------------------------------------------------------
# LogAnalyzer.analyze
# ---------------------------------------------------------------------------

class TestAnalyze(unittest.TestCase):

    def _analyzer(self):
        return LogAnalyzer(_make_kb_mock())

    def test_returns_empty_for_empty_logs(self):
        self.assertEqual(self._analyzer().analyze([]), [])

    def test_returns_alert_for_suspicious_message(self):
        analyzer = self._analyzer()
        alerts = analyzer.analyze([_make_event('Verbindung gescheitert')])
        self.assertEqual(len(alerts), 1)

    def test_dedup_removes_second_identical_alert(self):
        analyzer = self._analyzer()
        event = _make_event('Verbindung gescheitert')
        alerts = analyzer.analyze([event, event])
        self.assertEqual(len(alerts), 1)

    def test_short_message_ignored(self):
        analyzer = self._analyzer()
        # 'hi' has len 2 < 5, so skipped
        self.assertEqual(analyzer.analyze([_make_event('hi')]), [])

    def test_empty_message_ignored(self):
        analyzer = self._analyzer()
        self.assertEqual(analyzer.analyze([_make_event('')]), [])

    def test_updates_last_analysis_time(self):
        analyzer = self._analyzer()
        analyzer.analyze([_make_event('Verbindung gescheitert')])
        self.assertIsNotNone(analyzer.last_analysis_time)

    def test_multiple_distinct_alerts_all_returned(self):
        analyzer = self._analyzer()
        logs = [
            _make_event('Verbindung gescheitert'),
            _make_event('Falsches Kennwort eingegeben'),
        ]
        alerts = analyzer.analyze(logs)
        self.assertEqual(len(alerts), 2)


# ---------------------------------------------------------------------------
# AlertHandler.process_alert / _send_notification
# ---------------------------------------------------------------------------

class TestAlertHandlerProcessAlert(unittest.TestCase):

    def _handler(self):
        kb = MagicMock()
        kb.is_whitelisted = MagicMock(return_value=False)
        handler = AlertHandler(kb)
        handler.notifications = MagicMock()
        handler.notifications.notify = MagicMock(return_value=True)
        handler.notifications.send_alert_dialog = MagicMock(return_value=True)
        return handler

    def _alert(self, severity='high', alert_type='suspicious_activity', ip=None):
        a = {'type': alert_type, 'severity': severity, 'message': 'Test alert message'}
        if ip is not None:
            a['ip'] = ip
        return a

    def test_whitelisted_ip_skipped(self):
        handler = self._handler()
        handler.kb.is_whitelisted = MagicMock(return_value=True)
        result = handler.process_alert(self._alert(ip='1.2.3.4'))
        self.assertFalse(result)
        handler.notifications.notify.assert_not_called()
        handler.notifications.send_alert_dialog.assert_not_called()

    def test_non_whitelisted_ip_processed(self):
        handler = self._handler()
        result = handler.process_alert(self._alert(ip='1.2.3.4'))
        self.assertTrue(result)

    def test_critical_alert_uses_dialog(self):
        handler = self._handler()
        handler.process_alert(self._alert(severity='critical'))
        handler.notifications.send_alert_dialog.assert_called_once()
        handler.notifications.notify.assert_not_called()

    def test_high_alert_uses_notify(self):
        handler = self._handler()
        handler.process_alert(self._alert(severity='high'))
        handler.notifications.notify.assert_called_once()
        handler.notifications.send_alert_dialog.assert_not_called()

    def test_medium_alert_uses_notify(self):
        handler = self._handler()
        handler.process_alert(self._alert(severity='medium'))
        handler.notifications.notify.assert_called_once()
        handler.notifications.send_alert_dialog.assert_not_called()

    def test_alert_added_to_history(self):
        handler = self._handler()
        handler.process_alert(self._alert())
        self.assertEqual(len(handler.alert_history), 1)

    def test_multiple_alerts_accumulate_in_history(self):
        handler = self._handler()
        handler.process_alert(self._alert(severity='high'))
        handler.process_alert(self._alert(severity='medium'))
        self.assertEqual(len(handler.alert_history), 2)

    def test_alert_without_ip_key_processed(self):
        handler = self._handler()
        # no 'ip' key — should not raise, should not call is_whitelisted
        result = handler.process_alert(self._alert())
        self.assertTrue(result)

    def test_critical_dialog_called_with_critical_style(self):
        handler = self._handler()
        handler.process_alert(self._alert(severity='critical'))
        _, kwargs = handler.notifications.send_alert_dialog.call_args
        self.assertEqual(kwargs.get('alert_style'), 'critical')


if __name__ == '__main__':
    unittest.main()
