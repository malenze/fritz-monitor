"""Unit tests for MonthlyRotatingFileHandler and MonitoringEngine._rotate_error_log_if_needed."""

import gzip
import os
import sys
import tempfile
import unittest
from datetime import datetime as real_datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fritz_monitor_macos import MonthlyRotatingFileHandler, MonitoringEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_engine():
    """Bare MonitoringEngine with only the attrs needed by _rotate_error_log_if_needed."""
    engine = MonitoringEngine.__new__(MonitoringEngine)
    engine._error_log_rotated_month = None
    return engine


def _patch_datetime(year=2026, month=4, day=24):
    """Return a patch context manager that fixes fritz_monitor_macos.datetime.now()."""
    mock_dt = MagicMock()
    mock_dt.now.return_value = real_datetime(year, month, day)
    mock_dt.fromtimestamp.side_effect = real_datetime.fromtimestamp
    return patch('fritz_monitor_macos.datetime', mock_dt)


# ---------------------------------------------------------------------------
# MonthlyRotatingFileHandler._next_rollover_month
# ---------------------------------------------------------------------------

class TestNextRolloverMonth(unittest.TestCase):

    def test_regular_month_increments(self):
        with _patch_datetime(2026, 4, 24):
            result = MonthlyRotatingFileHandler._next_rollover_month()
        self.assertEqual(result, (2026, 5))

    def test_december_wraps_to_january_of_next_year(self):
        with _patch_datetime(2026, 12, 1):
            result = MonthlyRotatingFileHandler._next_rollover_month()
        self.assertEqual(result, (2027, 1))


# ---------------------------------------------------------------------------
# MonthlyRotatingFileHandler._check_stale_on_open
# ---------------------------------------------------------------------------

class TestCheckStaleOnOpen(unittest.TestCase):

    def _fresh_handler(self, tmpdir):
        """Handler whose log file has today's mtime (no stale detection at init)."""
        log_path = os.path.join(tmpdir, 'fritz_monitor.log')
        Path(log_path).write_text('content')
        h = MonthlyRotatingFileHandler(log_path)
        self.addCleanup(h.close)
        return h

    def test_no_file_leaves_rollover_month_unchanged(self):
        """_check_stale_on_open is a no-op when the log file does not exist."""
        with tempfile.TemporaryDirectory() as tmp:
            handler = MonthlyRotatingFileHandler.__new__(MonthlyRotatingFileHandler)
            handler.baseFilename = os.path.join(tmp, 'nonexistent.log')
            handler._rollover_month = (2026, 6)
            handler._check_stale_on_open()
            self.assertEqual(handler._rollover_month, (2026, 6))

    def test_current_month_file_leaves_rollover_month_unchanged(self):
        """File with an mtime inside the current month must not trigger early rollover."""
        with tempfile.TemporaryDirectory() as tmp:
            handler = self._fresh_handler(tmp)
            original = handler._rollover_month
            # Set mtime to April 10 (within mocked-current April 2026)
            april_ts = real_datetime(2026, 4, 10).timestamp()
            os.utime(handler.baseFilename, (april_ts, april_ts))
            with _patch_datetime(2026, 4, 24):
                handler._check_stale_on_open()
            self.assertEqual(handler._rollover_month, original)

    def test_stale_file_sets_rollover_month_to_current(self):
        """File with an mtime before this month must trigger immediate rollover."""
        with tempfile.TemporaryDirectory() as tmp:
            handler = self._fresh_handler(tmp)
            # Age the file to last month
            march_ts = real_datetime(2026, 3, 15).timestamp()
            os.utime(handler.baseFilename, (march_ts, march_ts))
            with _patch_datetime(2026, 4, 24):
                handler._check_stale_on_open()
            self.assertEqual(handler._rollover_month, (2026, 4))


# ---------------------------------------------------------------------------
# MonthlyRotatingFileHandler.shouldRollover
# ---------------------------------------------------------------------------

class TestShouldRollover(unittest.TestCase):

    def _handler(self, tmpdir, rollover_month):
        log_path = os.path.join(tmpdir, 'fritz_monitor.log')
        Path(log_path).write_text('')
        h = MonthlyRotatingFileHandler(log_path)
        h._rollover_month = rollover_month
        self.addCleanup(h.close)
        return h

    def test_returns_0_before_rollover_month(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = self._handler(tmp, rollover_month=(2026, 6))
            with _patch_datetime(2026, 4, 24):  # April < June
                self.assertEqual(h.shouldRollover(None), 0)

    def test_returns_1_at_rollover_month(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = self._handler(tmp, rollover_month=(2026, 4))
            with _patch_datetime(2026, 4, 1):  # exactly April
                self.assertEqual(h.shouldRollover(None), 1)

    def test_returns_1_past_rollover_month(self):
        with tempfile.TemporaryDirectory() as tmp:
            h = self._handler(tmp, rollover_month=(2026, 3))
            with _patch_datetime(2026, 5, 1):  # May > March
                self.assertEqual(h.shouldRollover(None), 1)


# ---------------------------------------------------------------------------
# MonthlyRotatingFileHandler.doRollover
# ---------------------------------------------------------------------------

class TestDoRollover(unittest.TestCase):
    """Each test uses an absolute temp path to avoid working-directory sensitivity."""

    def _handler_with_content(self, tmpdir, rollover_month=(2026, 5),
                               content=b'log data\n'):
        log_path = os.path.join(tmpdir, 'fritz_monitor.log')
        Path(log_path).write_bytes(content)
        h = MonthlyRotatingFileHandler(log_path)
        h._rollover_month = rollover_month
        self.addCleanup(h.close)
        return h, Path(log_path)

    def test_gz_archive_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, _ = self._handler_with_content(tmp)
            h.doRollover()
            self.assertTrue(Path(tmp, 'fritz_monitor.2026-04.log.gz').exists())

    def test_gz_contains_original_content(self):
        content = b'important log entry\n'
        with tempfile.TemporaryDirectory() as tmp:
            h, _ = self._handler_with_content(tmp, content=content)
            h.doRollover()
            with gzip.open(Path(tmp, 'fritz_monitor.2026-04.log.gz'), 'rb') as f:
                self.assertEqual(f.read(), content)

    def test_intermediate_renamed_file_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, _ = self._handler_with_content(tmp)
            h.doRollover()
            self.assertFalse(Path(tmp, 'fritz_monitor.2026-04.log').exists())

    def test_original_log_replaced_by_fresh_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, log_path = self._handler_with_content(tmp)
            h.doRollover()
            self.assertTrue(log_path.exists())
            self.assertEqual(log_path.stat().st_size, 0)

    def test_stream_open_after_rollover(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, _ = self._handler_with_content(tmp)
            h.doRollover()
            self.assertIsNotNone(h.stream)

    def test_rollover_month_advances_by_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, _ = self._handler_with_content(tmp, rollover_month=(2026, 5))
            h.doRollover()
            self.assertEqual(h._rollover_month, (2026, 6))

    def test_rollover_month_wraps_december_to_next_january(self):
        with tempfile.TemporaryDirectory() as tmp:
            h, _ = self._handler_with_content(tmp, rollover_month=(2026, 12))
            h.doRollover()
            self.assertEqual(h._rollover_month, (2027, 1))

    def test_january_rollover_produces_december_suffix(self):
        """`_rollover_month=(2027,1)` → the archived month is December 2026."""
        with tempfile.TemporaryDirectory() as tmp:
            h, _ = self._handler_with_content(tmp, rollover_month=(2027, 1))
            h.doRollover()
            self.assertTrue(Path(tmp, 'fritz_monitor.2026-12.log.gz').exists())

    def test_missing_source_file_does_not_raise(self):
        """doRollover should complete without error if the log file was already removed."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'fritz_monitor.log')
            Path(log_path).write_text('')
            h = MonthlyRotatingFileHandler(log_path)
            h._rollover_month = (2026, 5)
            Path(log_path).unlink()   # remove before rollover
            try:
                h.doRollover()
            except Exception as exc:
                self.fail(f'doRollover raised unexpectedly: {exc}')


# ---------------------------------------------------------------------------
# MonitoringEngine._rotate_error_log_if_needed
# ---------------------------------------------------------------------------

class TestRotateErrorLogIfNeeded(unittest.TestCase):
    """Each test runs inside a TemporaryDirectory so relative paths are isolated."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.original_cwd = os.getcwd()
        os.chdir(self.tmpdir.name)

    def tearDown(self):
        os.chdir(self.original_cwd)
        self.tmpdir.cleanup()

    # ---- helpers -----------------------------------------------------------

    def _error_log(self):
        return Path(self.tmpdir.name, 'fritz_monitor.error.log')

    def _create_stale_error_log(self, content=b'crash output\n'):
        """Create error log with content whose mtime is in March 2026 (previous month)."""
        p = self._error_log()
        p.write_bytes(content)
        march_ts = real_datetime(2026, 3, 15).timestamp()
        os.utime(str(p), (march_ts, march_ts))
        return p

    # ---- skip conditions ---------------------------------------------------

    def test_skips_if_already_rotated_this_month(self):
        engine = _make_engine()
        engine._error_log_rotated_month = (2026, 4)   # already done this month
        self._create_stale_error_log()
        with patch('os.dup2') as mock_dup2:
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        mock_dup2.assert_not_called()
        self.assertEqual(list(Path(self.tmpdir.name).glob('*.gz')), [])

    def test_skips_if_file_does_not_exist(self):
        engine = _make_engine()
        with patch('os.dup2') as mock_dup2:
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        mock_dup2.assert_not_called()

    def test_skips_if_file_is_empty(self):
        engine = _make_engine()
        p = self._error_log()
        p.write_bytes(b'')                          # empty file
        march_ts = real_datetime(2026, 3, 15).timestamp()
        os.utime(str(p), (march_ts, march_ts))      # stale mtime — still skipped
        with patch('os.dup2') as mock_dup2:
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        mock_dup2.assert_not_called()

    def test_skips_if_mtime_is_current_month(self):
        engine = _make_engine()
        p = self._error_log()
        p.write_bytes(b'recent stderr\n')
        april_ts = real_datetime(2026, 4, 15).timestamp()   # within current month
        os.utime(str(p), (april_ts, april_ts))
        with patch('os.dup2') as mock_dup2:
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        mock_dup2.assert_not_called()

    # ---- rotation behaviour ------------------------------------------------

    def test_rotates_stale_file_creates_gz(self):
        engine = _make_engine()
        self._create_stale_error_log()
        with patch('os.dup2'):
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        gzs = list(Path(self.tmpdir.name).glob('*.gz'))
        self.assertEqual(len(gzs), 1)

    def test_rotates_stale_file_removes_intermediate(self):
        engine = _make_engine()
        self._create_stale_error_log()
        with patch('os.dup2'):
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        uncompressed = Path(self.tmpdir.name, 'fritz_monitor.error.2026-03.log')
        self.assertFalse(uncompressed.exists())

    def test_rotates_stale_file_correct_suffix(self):
        """File mtime in March 2026, current date April 2026 → suffix 2026-03."""
        engine = _make_engine()
        self._create_stale_error_log()
        with patch('os.dup2'):
            with _patch_datetime(2026, 4, 1):
                engine._rotate_error_log_if_needed()
        gz = Path(self.tmpdir.name, 'fritz_monitor.error.2026-03.log.gz')
        self.assertTrue(gz.exists())

    def test_gz_contains_original_content(self):
        engine = _make_engine()
        content = b'unhandled exception traceback\n'
        self._create_stale_error_log(content=content)
        with patch('os.dup2'):
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        gz = next(Path(self.tmpdir.name).glob('*.gz'))
        with gzip.open(gz, 'rb') as f:
            self.assertEqual(f.read(), content)

    def test_redirects_stderr_via_dup2(self):
        engine = _make_engine()
        self._create_stale_error_log()
        with patch('os.dup2') as mock_dup2:
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        mock_dup2.assert_called_once()
        # Second argument must be the stderr file descriptor
        _, target_fd = mock_dup2.call_args[0]
        self.assertEqual(target_fd, sys.stderr.fileno())

    def test_updates_rotated_month_attribute(self):
        engine = _make_engine()
        self._create_stale_error_log()
        with patch('os.dup2'):
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        self.assertEqual(engine._error_log_rotated_month, (2026, 4))

    def test_updates_rotated_month_even_when_no_rotation_needed(self):
        """_error_log_rotated_month should be updated regardless so the check
        is not repeated on every subsequent cycle within the same month."""
        engine = _make_engine()
        # No file → no rotation, but month should still be stamped
        with patch('os.dup2'):
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        self.assertEqual(engine._error_log_rotated_month, (2026, 4))

    def test_no_dup2_when_no_rotation_needed(self):
        engine = _make_engine()
        with patch('os.dup2') as mock_dup2:
            with _patch_datetime(2026, 4, 24):
                engine._rotate_error_log_if_needed()
        mock_dup2.assert_not_called()


if __name__ == '__main__':
    unittest.main()
