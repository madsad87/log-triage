import unittest
from pathlib import Path
from collections import Counter
import sys
import os

# Add parent directory to path to import log_analyzer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from unittest.mock import patch, MagicMock

from log_analyzer import parse_log_line, analyze_file, parse_log_date, LogMetrics, lookup_ip

class TestLogAnalyzer(unittest.TestCase):
    @patch("subprocess.run")
    def test_lookup_ip_success(self, mock_run):
        # Mock successful whois output
        mock_run.return_value = MagicMock(
            stdout="OrgName: Google LLC\nCountry: US\nNetName: GOOGLE",
            returncode=0
        )
        
        result = lookup_ip("8.8.8.8")
        self.assertEqual(result, "(Google LLC / US)")
        mock_run.assert_called_with(["whois", "8.8.8.8"], capture_output=True, text=True, timeout=5)

    @patch("subprocess.run")
    def test_lookup_ip_failure(self, mock_run):
        # Mock failure (e.g. timeout or command not found behavior)
        mock_run.side_effect = Exception("Command failed")
        
        result = lookup_ip("1.2.3.4")
        self.assertEqual(result, "") # Should fallback nicely

    def test_parse_valid_line(self):
        line = '127.0.0.1 - - [09/Dec/2025:11:00:00 -0600] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        result = parse_log_line(line)
        self.assertIsNotNone(result)
        self.assertEqual(result['ip'], '127.0.0.1')
        self.assertEqual(result['status'], '200')
        self.assertEqual(result['user_agent'], 'Mozilla/5.0')

    def test_parse_invalid_line(self):
        line = 'Invalid Log Line'
        result = parse_log_line(line)
        self.assertIsNone(result)

    def test_parse_date(self):
        ts = parse_log_date("09/Dec/2025:11:00:00 -0600")
        self.assertIsNotNone(ts)
        self.assertEqual(ts.year, 2025)
        self.assertEqual(ts.month, 12)
        self.assertEqual(ts.day, 9)

    def test_analyze_file_short_duration(self):
        # Case A: Logs < 24h (Summary only)
        test_file = Path("test_access.log")
        content = [
            '192.168.1.1 - - [09/Dec/2025:11:00:00 -0600] "GET / HTTP/1.1" 200 1024 "-" "UA1"',
            '192.168.1.1 - - [09/Dec/2025:11:00:01 -0600] "GET /admin-ajax.php HTTP/1.1" 200 1024 "-" "UA1"',
            '10.0.0.1 - - [09/Dec/2025:11:00:02 -0600] "GET / HTTP/1.1" 404 128 "-" "UA2"',
        ]
        with test_file.open("w") as f:
            f.write("\n".join(content))

        try:
            results = analyze_file(test_file)
            self.assertIn("Summary", results)
            metrics = results["Summary"]
            
            # Check Top IPs
            self.assertEqual(metrics.ip_counter['192.168.1.1'], 2)
            
            # Check Admin Ajax
            self.assertEqual(metrics.admin_ajax_count, 1)
            
            # Check Errors
            self.assertEqual(metrics.error_counts['4xx'], 1)

        finally:
            if test_file.exists():
                test_file.unlink()

    def test_analyze_file_long_duration(self):
        # Case B: Logs >= 24h (Daily buckets)
        test_file = Path("test_multi_day.log")
        content = [
            '127.0.0.1 - - [09/Dec/2025:10:00:00 -0600] "GET / HTTP/1.1" 200 1024 "-" "UA1"',
            '127.0.0.1 - - [10/Dec/2025:12:00:00 -0600] "GET / HTTP/1.1" 200 1024 "-" "UA1"',
        ]
        with test_file.open("w") as f:
            f.write("\n".join(content))

        try:
            results = analyze_file(test_file)
            self.assertNotIn("Summary", results)
            self.assertIn("2025-12-09", results)
            self.assertIn("2025-12-10", results)
            self.assertEqual(results["2025-12-09"].total_requests, 1)

        finally:
            if test_file.exists():
                test_file.unlink()

if __name__ == '__main__':
    unittest.main()
