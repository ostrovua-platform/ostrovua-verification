import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


IMPORTER = Path(__file__).resolve().parents[1] / "import_active_dsc.py"
DIRECT_VALIDATOR = Path(__file__).resolve().parents[1] / "validate_dsc_chain.js"


def run(command, *, cwd=None, check=True):
    return subprocess.run(
        [str(part) for part in command],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


class ActiveDscImporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl is required")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.ca_pem, self.ca_key, self.ca_der = self.make_ca("Trusted Root", 1)
        self.leaf_pem, self.leaf_der = self.make_leaf(
            "Document Signer", 2, self.ca_pem, self.ca_key
        )
        fingerprint = hashlib.sha256(self.ca_der.read_bytes()).hexdigest()
        self.pins = self.root / "pins_ua.txt"
        self.pins.write_text(f"{fingerprint}  # test root\n", encoding="utf-8")
        self.output = self.root / "dsc_ua.pem"

    def tearDown(self):
        self.temp.cleanup()

    def make_ca(self, common_name, serial):
        stem = common_name.lower().replace(" ", "-")
        pem = self.root / f"{stem}.pem"
        key = self.root / f"{stem}.key"
        der = self.root / f"{stem}.der"
        config = self.root / f"{stem}.cnf"
        config.write_text(
            "[req]\n"
            "distinguished_name=dn\n"
            "prompt=no\n"
            "x509_extensions=v3_ca\n"
            "[dn]\n"
            "C=UA\n"
            f"CN={common_name}\n"
            "[v3_ca]\n"
            "basicConstraints=critical,CA:TRUE\n"
            "keyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\n",
            encoding="utf-8",
        )
        run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-set_serial",
                str(serial),
                "-config",
                config,
                "-keyout",
                key,
                "-out",
                pem,
            ]
        )
        run(["openssl", "x509", "-in", pem, "-outform", "DER", "-out", der])
        return pem, key, der

    def make_leaf(self, common_name, serial, ca_pem, ca_key):
        stem = common_name.lower().replace(" ", "-") + f"-{serial}"
        key = self.root / f"{stem}.key"
        csr = self.root / f"{stem}.csr"
        pem = self.root / f"{stem}.pem"
        der = self.root / f"{stem}.der"
        ext = self.root / f"{stem}.ext"
        ext.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n",
            encoding="utf-8",
        )
        run(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                f"/C=UA/CN={common_name}",
                "-keyout",
                key,
                "-out",
                csr,
            ]
        )
        run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                csr,
                "-CA",
                ca_pem,
                "-CAkey",
                ca_key,
                "-set_serial",
                str(serial),
                "-days",
                "365",
                "-extfile",
                ext,
                "-out",
                pem,
            ]
        )
        run(["openssl", "x509", "-in", pem, "-outform", "DER", "-out", der])
        return pem, der

    def invoke(self, archive, *extra, check=False):
        return run(
            [
                "python3",
                IMPORTER,
                archive,
                "--ca-bundle",
                self.ca_pem,
                "--pins",
                self.pins,
                "--output",
                self.output,
                "--min-dsc",
                "1",
                *extra,
            ],
            check=check,
        )

    def test_imports_one_leaf_and_deduplicates(self):
        archive = self.root / "active.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            output.write(self.ca_der, "root.crt")
            output.write(self.leaf_der, "leaf.crt")
            output.write(self.leaf_der, "same-leaf.cer")

        result = self.invoke(archive, check=True)

        bundle = self.output.read_text(encoding="ascii")
        self.assertEqual(bundle.count("-----BEGIN CERTIFICATE-----"), 1)
        self.assertIn(b"source_anchors=1", result.stdout)
        self.assertIn(b"source_duplicates=1", result.stdout)
        self.assertIn(b"validated_dsc=1", result.stdout)

    def test_unknown_current_ca_aborts_without_replacing_output(self):
        unknown_ca, unknown_key, unknown_der = self.make_ca("Unknown Root", 100)
        _, unknown_leaf = self.make_leaf("Unknown Signer", 101, unknown_ca, unknown_key)
        archive = self.root / "unknown.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            output.write(self.ca_der, "trusted-root.crt")
            output.write(self.leaf_der, "trusted-leaf.crt")
            output.write(unknown_der, "unknown-root.crt")
            output.write(unknown_leaf, "unknown-leaf.crt")
        self.output.write_text("sentinel\n", encoding="ascii")

        result = self.invoke(archive)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"is not pinned", result.stderr)
        self.assertEqual(self.output.read_text(encoding="ascii"), "sentinel\n")

    def test_path_traversal_entry_is_rejected(self):
        archive = self.root / "traversal.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            output.writestr("../leaf.crt", self.leaf_der.read_bytes())

        result = self.invoke(archive)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"unsafe ZIP entry", result.stderr)
        self.assertFalse(self.output.exists())

    def test_checksum_mismatch_is_rejected(self):
        archive = self.root / "checksum.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            output.write(self.ca_der, "root.crt")
            output.write(self.leaf_der, "leaf.crt")

        result = self.invoke(archive, "--expected-sha256", "0" * 64)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"SHA-256 mismatch", result.stderr)
        self.assertFalse(self.output.exists())

    def test_direct_validator_accepts_leaf_signed_by_pinned_ca(self):
        result = run(
            ["node", DIRECT_VALIDATOR, self.leaf_pem, self.ca_pem, self.pins],
            check=True,
        )

        report = json.loads(result.stdout)
        self.assertEqual(report["leafFingerprint"], hashlib.sha256(self.leaf_der.read_bytes()).hexdigest())
        self.assertEqual(report["issuerFingerprint"], hashlib.sha256(self.ca_der.read_bytes()).hexdigest())

    def test_direct_validator_rejects_leaf_from_unknown_ca(self):
        unknown_ca, unknown_key, _ = self.make_ca("Unknown Direct Root", 200)
        unknown_leaf_pem, _ = self.make_leaf(
            "Unknown Direct Signer", 201, unknown_ca, unknown_key
        )

        result = run(
            ["node", DIRECT_VALIDATOR, unknown_leaf_pem, self.ca_pem, self.pins],
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"dsc_signature_invalid", result.stderr)

    def test_known_openssl_compatibility_error_uses_pinned_direct_verifier(self):
        archive = self.root / "compatibility.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            output.write(self.ca_der, "root.crt")
            output.write(self.leaf_der, "leaf.crt")

        wrapper = self.root / "openssl-compatibility-error"
        wrapper.write_text(
            "#!/bin/sh\n"
            "if [ \"$1\" = verify ]; then\n"
            "  echo 'Certificate public key has explicit ECC parameters' >&2\n"
            "  exit 1\n"
            "fi\n"
            f"exec {shutil.which('openssl')} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(0o755)

        result = self.invoke(archive, "--openssl", wrapper, check=True)

        self.assertIn(b"compatibility_fallbacks=1", result.stdout)
        self.assertIn(b"validated_dsc=1", result.stdout)


if __name__ == "__main__":
    unittest.main()
