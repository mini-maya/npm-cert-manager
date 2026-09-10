import unittest
import os
from tempfile import TemporaryDirectory
from pathlib import Path

from fastapi import HTTPException

from app.storage import repository as repo
from app.storage.models import CertificateMeta, Identity
from app import config
from app.api import certificates as cert_api
from app.npm.errors import NpmNotFoundError


class FakeClientMissing:
    def get_certificate(self, certificate_id: int):
        raise NpmNotFoundError("not found")
    def close(self):
        pass


class FakeClientExists:
    def get_certificate(self, certificate_id: int):
        return {"id": certificate_id}
    def close(self):
        pass


class PruneTests(unittest.TestCase):
    def test_prune_removes_local_mapping_when_npm_returns_404(self):
        with TemporaryDirectory() as tmp:
            os.environ["DATA_DIR"] = tmp
            config.settings = config.load_settings()

            meta = CertificateMeta(npm_certificate_id=1234, name="test-cert", identities=[Identity(type="DNS", value="example.lan", is_primary=True)])
            created = repo.create_certificate(meta)

            # monkeypatch the get_npm_client used by the API module
            cert_api.get_npm_client = lambda session_id: FakeClientMissing()

            # call prune directly
            cert_api.prune(created.local_id, session_id="dummy")

            self.assertIsNone(repo.get_certificate(created.local_id))

    def test_prune_refuses_when_certificate_still_exists(self):
        with TemporaryDirectory() as tmp:
            os.environ["DATA_DIR"] = tmp
            config.settings = config.load_settings()

            meta = CertificateMeta(npm_certificate_id=2222, name="keep-cert", identities=[Identity(type="DNS", value="keep.lan", is_primary=True)])
            created = repo.create_certificate(meta)

            cert_api.get_npm_client = lambda session_id: FakeClientExists()

            with self.assertRaises(HTTPException) as cm:
                cert_api.prune(created.local_id, session_id="dummy")
            self.assertEqual(cm.exception.status_code, 409)

            # ensure mapping still exists
            self.assertIsNotNone(repo.get_certificate(created.local_id))


if __name__ == "__main__":
    unittest.main()
