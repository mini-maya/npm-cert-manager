import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app.certificates.ca import ensure_root_ca


class CAInitTests(unittest.TestCase):
    def test_create_ca_when_missing(self):
        with TemporaryDirectory() as tmp:
            key_path = Path(tmp) / "ca.key"
            cert_path = Path(tmp) / "ca.crt"

            created = ensure_root_ca(key_path, cert_path, common_name="Local Docker Root CA", valid_days=3650)
            self.assertTrue(created)
            self.assertTrue(key_path.exists())
            self.assertTrue(cert_path.exists())


if __name__ == "__main__":
    unittest.main()
