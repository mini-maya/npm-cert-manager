import unittest

from app.certificates.validation import InvalidIdentityError, validate_domain, validate_ip


class ValidationTests(unittest.TestCase):
    def test_valid_domain(self):
        self.assertEqual(validate_domain("example.lan"), "example.lan")

    def test_invalid_domain(self):
        with self.assertRaises(InvalidIdentityError):
            validate_domain("-bad-domain-")

    def test_valid_ip(self):
        self.assertEqual(validate_ip("192.168.1.50"), "192.168.1.50")

    def test_invalid_ip(self):
        with self.assertRaises(InvalidIdentityError):
            validate_ip("999.999.999.999")


if __name__ == "__main__":
    unittest.main()
