import sys
import unittest
from pathlib import Path


SERVER = Path(__file__).resolve().parents[1]
TOOLS = SERVER / "tools"
REPO = SERVER.parent
sys.path.insert(0, str(TOOLS))

from build_release_evidence_manifest import build_manifest  # noqa: E402


class ReleaseEvidenceManifestTests(unittest.TestCase):
    def test_rehearsal_manifest_hashes_files_without_contents(self):
        manifest = build_manifest(
            REPO,
            artifacts={
                "policy": "Server/biometric_service/policy.py",
                "models": "Server/biometric_service/model_manifest.json",
            },
            images={"auth": "sha256:" + ("a" * 64)},
            allow_dirty=True,
        )
        self.assertEqual(manifest["schema"], "ostrovua-release-evidence-v1")
        self.assertRegex(manifest["git"]["commit"], r"^[0-9a-f]{40}$")
        self.assertRegex(manifest["modelSetHash"], r"^[0-9a-f]{64}$")
        self.assertNotIn("contents", manifest["artifacts"]["policy"])

    def test_invalid_image_digest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "image_invalid"):
            build_manifest(
                REPO,
                artifacts={"policy": "Server/biometric_service/policy.py"},
                images={"auth": "latest"},
                allow_dirty=True,
            )

    def test_outside_artifact_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "artifact_outside_repo"):
            build_manifest(
                REPO,
                artifacts={"outside": "../outside.txt"},
                images={},
                allow_dirty=True,
            )


if __name__ == "__main__":
    unittest.main()
