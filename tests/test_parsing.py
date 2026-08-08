import unittest
from redescan.parsing import expand_targets, parse_ports

class ParsePortsTests(unittest.TestCase):
    def test_accepts_lists_ranges_and_removes_duplicates(self):
        self.assertEqual(
            parse_ports("443, 80, 80, 1000-1002"),
            [80, 443, 1000, 1001, 1002],
        )

    def test_rejects_invalid_values(self):
        for value in ("", "0", "65536", "80-20", "abc", "80,,443"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)

class ExpandTargetsTests(unittest.TestCase):
    def test_accepts_addresses_and_cidr_without_duplicates(self):
        self.assertEqual(
            expand_targets(["192.0.2.1", "192.0.2.0/30"]),
            ["192.0.2.1", "192.0.2.2"],
        )

    def test_rejects_invalid_or_ipv6_targets(self):
        for value in ("host.local", "999.1.1.1", "2001:db8::1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                expand_targets([value])

if __name__ == "__main__":
    unittest.main()
