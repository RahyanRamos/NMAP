import unittest
from unittest.mock import patch
from redescan.cli import _resolve_method

class MethodSelectionTests(unittest.TestCase):
    @patch("redescan.cli.platform.system", return_value="Windows")
    def test_auto_uses_connect_on_windows(self, _system):
        self.assertEqual(_resolve_method("auto"), "connect")

    @patch("redescan.cli.platform.system", return_value="Linux")
    def test_auto_uses_raw_on_linux(self, _system):
        self.assertEqual(_resolve_method("auto"), "raw")

    def test_explicit_method_is_preserved(self):
        self.assertEqual(_resolve_method("connect"), "connect")
        self.assertEqual(_resolve_method("raw"), "raw")

if __name__ == "__main__":
    unittest.main()
