# tests/test_utils.py
import unittest
from core.utils import translate

class TestUtils(unittest.TestCase):
    def test_translate(self):
        self.assertEqual(translate("title"), "Backdoor Scanner")

if __name__ == "__main__":
    unittest.main()