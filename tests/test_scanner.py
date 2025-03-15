# tests/test_scanner.py
import unittest
from core.scanner import scan_file

class TestScanner(unittest.TestCase):
    def test_scan_file(self):
        patterns = [r"eval\("]
        malicious_hashes = set()
        result = scan_file("test_file.txt", patterns, malicious_hashes, "fake_api_key")
        self.assertIsInstance(result, list)

if __name__ == "__main__":
    unittest.main()