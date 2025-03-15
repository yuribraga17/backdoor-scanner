import unittest
from core.detector import detect_patterns

class TestDetector(unittest.TestCase):
    def test_detect_patterns(self):
        content = "eval('malicious code')"
        patterns = [r"eval\("]
        results = detect_patterns(content, patterns)
        self.assertEqual(len(results), 1)

if __name__ == "__main__":
    unittest.main()