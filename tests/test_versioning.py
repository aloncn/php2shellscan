import unittest

from php2shellscan.versioning import assess_version, parse_php_version


class TestParse(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(parse_php_version("PHP/8.2.34"), (8, 2, 34))

    def test_inside_server_header(self):
        self.assertEqual(
            parse_php_version("Apache/2.4.62 (Unix) PHP/8.4.26"), (8, 4, 26))

    def test_two_component(self):
        self.assertEqual(parse_php_version("PHP/8.3"), (8, 3, 0))

    def test_none(self):
        self.assertIsNone(parse_php_version("nginx"))
        self.assertIsNone(parse_php_version(""))

    def test_ignores_non_php_numbers(self):
        # First 5-9.x.y-ish token wins; but plain nginx has none.
        self.assertIsNone(parse_php_version("2.4.62 nginx"))


class TestAssess(unittest.TestCase):
    def test_vulnerable_82(self):
        f = assess_version("PHP/8.2.34")
        self.assertTrue(f.vulnerable)
        self.assertEqual(f.status, "vulnerable")
        self.assertEqual(f.fixed_in, "8.2.35")

    def test_vulnerable_boundary_minus(self):
        self.assertTrue(assess_version("PHP/8.4.26").vulnerable)

    def test_patched_84(self):
        f = assess_version("PHP/8.4.27")
        self.assertFalse(f.vulnerable)
        self.assertEqual(f.status, "patched")

    def test_patched_85(self):
        f = assess_version("PHP/8.5.12")
        self.assertFalse(f.vulnerable)

    def test_eol_81(self):
        f = assess_version("PHP/8.1.31")
        self.assertTrue(f.vulnerable)
        self.assertEqual(f.status, "eol_unpatched")

    def test_eol_74(self):
        f = assess_version("PHP/7.4.33")
        self.assertTrue(f.vulnerable)

    def test_ancient_54(self):
        f = assess_version("PHP/5.4.45")
        self.assertTrue(f.vulnerable)

    def test_unknown(self):
        f = assess_version("nginx/1.27")
        self.assertIsNone(f.version)
        self.assertEqual(f.status, "unknown")

    def test_future_version(self):
        f = assess_version("PHP/8.6.0")
        # Branch not in the fixed set -> treated as eol_unpatched/conservative.
        self.assertTrue(f.vulnerable)


if __name__ == "__main__":
    unittest.main()
