"""Unit tests for config.py"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
import config


class TestGetConfigStructure(unittest.TestCase):

    def test_no_section_returns_complete_config(self):
        cfg = config.get_config()
        for section in ('fritz', 'monitoring', 'alerts', 'traffic', 'detection',
                        'whitelist', 'logging', 'knowledge_base', 'advanced'):
            with self.subTest(section=section):
                self.assertIn(section, cfg)

    def test_return_type_is_always_dict(self):
        self.assertIsInstance(config.get_config(), dict)
        self.assertIsInstance(config.get_config('fritz'), dict)
        self.assertIsInstance(config.get_config('monitoring'), dict)

    def test_unknown_section_returns_empty_dict(self):
        self.assertEqual(config.get_config('no_such_section'), {})

    def test_none_section_same_as_no_argument(self):
        self.assertEqual(config.get_config(None), config.get_config())


class TestFritzConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = config.get_config('fritz')

    def test_has_required_keys(self):
        for key in ('hostname', 'username', 'password', 'port'):
            with self.subTest(key=key):
                self.assertIn(key, self.cfg)

    def test_port_is_49000(self):
        self.assertEqual(self.cfg['port'], 49000)

    def test_password_is_none(self):
        self.assertIsNone(self.cfg['password'])

    def test_username_is_string(self):
        self.assertIsInstance(self.cfg['username'], str)
        self.assertTrue(self.cfg['username'])

    def test_hostname_is_string(self):
        self.assertIsInstance(self.cfg['hostname'], str)


class TestMonitoringConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = config.get_config('monitoring')

    def test_has_required_keys(self):
        for key in ('interval_minutes', 'respect_sleep_state',
                    'max_logs_per_cycle', 'alert_history_retention'):
            with self.subTest(key=key):
                self.assertIn(key, self.cfg)

    def test_interval_is_positive_int(self):
        self.assertIsInstance(self.cfg['interval_minutes'], int)
        self.assertGreater(self.cfg['interval_minutes'], 0)

    def test_max_logs_is_positive_int(self):
        self.assertIsInstance(self.cfg['max_logs_per_cycle'], int)
        self.assertGreater(self.cfg['max_logs_per_cycle'], 0)

    def test_respect_sleep_is_bool(self):
        self.assertIsInstance(self.cfg['respect_sleep_state'], bool)


class TestLoggingConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = config.get_config('logging')

    def test_has_required_keys(self):
        for key in ('level', 'file', 'max_size_mb', 'backup_count', 'timestamps'):
            with self.subTest(key=key):
                self.assertIn(key, self.cfg)

    def test_level_is_valid_string(self):
        self.assertIn(self.cfg['level'], ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'))

    def test_file_is_nonempty_string(self):
        self.assertIsInstance(self.cfg['file'], str)
        self.assertTrue(self.cfg['file'])

    def test_max_size_is_positive(self):
        self.assertGreater(self.cfg['max_size_mb'], 0)

    def test_backup_count_is_non_negative(self):
        self.assertGreaterEqual(self.cfg['backup_count'], 0)


class TestAlertsConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = config.get_config('alerts')

    def test_has_required_keys(self):
        for key in ('method', 'desktop', 'email', 'webhook'):
            with self.subTest(key=key):
                self.assertIn(key, self.cfg)

    def test_method_is_string(self):
        self.assertIsInstance(self.cfg['method'], str)

    def test_desktop_has_macos_key(self):
        self.assertIn('macos', self.cfg['desktop'])


class TestWhitelistConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = config.get_config('whitelist')

    def test_ips_is_dict(self):
        self.assertIsInstance(self.cfg.get('ips'), dict)

    def test_ranges_is_list(self):
        self.assertIsInstance(self.cfg.get('ranges'), list)

    def test_domains_is_list(self):
        self.assertIsInstance(self.cfg.get('domains'), list)

    def test_ips_values_are_strings(self):
        for ip, label in self.cfg['ips'].items():
            with self.subTest(ip=ip):
                self.assertIsInstance(label, str)


class TestDetectionConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = config.get_config('detection')

    def test_has_expected_patterns(self):
        for pattern in ('brute_force', 'port_scan', 'unknown_device'):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, self.cfg)

    def test_each_pattern_has_enabled_flag(self):
        for name, pattern in self.cfg.items():
            with self.subTest(pattern=name):
                self.assertIn('enabled', pattern)
                self.assertIsInstance(pattern['enabled'], bool)

    def test_each_pattern_has_severity(self):
        for name, pattern in self.cfg.items():
            with self.subTest(pattern=name):
                self.assertIn('severity', pattern)
                self.assertIn(pattern['severity'], ('low', 'medium', 'high', 'critical'))


class TestKnowledgeBaseConfig(unittest.TestCase):

    def setUp(self):
        self.cfg = config.get_config('knowledge_base')

    def test_database_file_is_json(self):
        self.assertIsInstance(self.cfg['database_file'], str)
        self.assertTrue(self.cfg['database_file'].endswith('.json'))

    def test_auto_save_interval_is_positive(self):
        self.assertGreater(self.cfg['auto_save_interval'], 0)


if __name__ == '__main__':
    unittest.main()
