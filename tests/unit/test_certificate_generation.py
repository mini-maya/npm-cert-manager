import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509

from app.certificates.ca import CertificateAuthority, generate_root_ca
from app.certificates.generator import issue_certificate
from app.storage.models import Identity


class CertificateGenerationTests(unittest.TestCase):
    def test_generate_root_ca_and_sign_server_cert(self):
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ca = generate_root_ca("Test Root CA")
            (tmp_path / "ca.key").write_bytes(ca.key_pem)
            (tmp_path / "ca.crt").write_bytes(ca.cert_pem)

            authority = CertificateAuthority(tmp_path / "ca.key", tmp_path / "ca.crt")
            issued = issue_certificate(
                authority,
                [
                    Identity(type="DNS", value="example.lan", is_primary=True),
                    Identity(type="DNS", value="www.example.lan"),
                    Identity(type="IP", value="192.168.1.50"),
                ],
                primary_common_name="example.lan",
            )
            cert = x509.load_pem_x509_certificate(issued.cert_pem)
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertIn("example.lan", san.get_values_for_type(x509.DNSName))
            self.assertIn("www.example.lan", san.get_values_for_type(x509.DNSName))
            self.assertIn("192.168.1.50", [str(v) for v in san.get_values_for_type(x509.IPAddress)])


if __name__ == "__main__":
    unittest.main()
