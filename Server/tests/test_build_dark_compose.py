import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build_dark_compose.py"
DIGEST = "sha256:" + ("a" * 64)
KEY_ID = "b" * 64


class DarkComposeBuilderTests(unittest.TestCase):
    def test_hmac_secret_is_split_between_non_root_services(self):
        source = {
            "services": {
                "auth": {
                    "image": f"example/auth@{DIGEST}",
                    "environment": {},
                    "networks": ["public", "private"],
                },
                "biometric": {
                    "image": f"example/biometric@{DIGEST}",
                    "environment": {},
                    "networks": ["private"],
                },
                "nginx": {
                    "image": f"example/nginx@{DIGEST}",
                    "environment": {},
                    "networks": ["public"],
                    "ports": ["443:443"],
                },
            },
            "networks": {
                "public": {},
                "private": {"internal": True},
            },
        }
        images = {
            name: service["image"]
            for name, service in source["services"].items()
        }

        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            source_path = directory_path / "source.yml"
            images_path = directory_path / "images.json"
            output_path = directory_path / "dark.yml"
            source_path.write_text(yaml.safe_dump(source), encoding="utf-8")
            images_path.write_text(json.dumps(images), encoding="utf-8")

            subprocess.run(
                [
                    sys.executable,
                    str(BUILDER),
                    str(source_path),
                    str(output_path),
                    str(images_path),
                    "--envelope-key-id",
                    KEY_ID,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            result = yaml.safe_load(output_path.read_text(encoding="utf-8"))

        auth = result["services"]["auth"]
        biometric = result["services"]["biometric"]
        self.assertEqual(auth["user"], "12000:12000")
        self.assertIn(
            {"source": "biometric_hmac_auth", "target": "biometric_hmac.key"},
            auth["secrets"],
        )
        self.assertIn(
            {
                "source": "biometric_hmac_worker",
                "target": "biometric_hmac.key",
            },
            biometric["secrets"],
        )
        self.assertEqual(
            result["secrets"]["biometric_hmac_auth"]["file"],
            "/etc/ostrovua/secrets/biometric_hmac.auth.key",
        )
        self.assertEqual(
            result["secrets"]["biometric_hmac_worker"]["file"],
            "/etc/ostrovua/secrets/biometric_hmac.worker.key",
        )
        self.assertEqual(
            auth["environment"]["BIOMETRIC_SHADOW_MODE_ENABLED"], "0"
        )
        self.assertEqual(
            biometric["environment"]["BIOMETRIC_CALIBRATION_APPROVED"], "0"
        )


if __name__ == "__main__":
    unittest.main()
