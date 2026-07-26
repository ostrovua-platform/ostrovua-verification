import tempfile
import unittest

from pathlib import Path
import sys


SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SERVICE))

from replay_cache import NonceReplayCache  # noqa: E402


class ReplayCacheTests(unittest.TestCase):
    def test_nonce_is_accepted_exactly_once_across_instances(self):
        with tempfile.TemporaryDirectory() as directory:
            first = NonceReplayCache(Path(directory) / "nonces")
            second = NonceReplayCache(Path(directory) / "nonces")
            nonce = "0123456789abcdef0123456789abcdef"
            self.assertTrue(first.consume(nonce, now=1000))
            self.assertFalse(second.consume(nonce, now=1001))

    def test_expired_nonce_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = NonceReplayCache(
                Path(directory) / "nonces", ttl_seconds=30)
            nonce = "fedcba9876543210fedcba9876543210"
            self.assertTrue(cache.consume(nonce, now=1000))
            self.assertTrue(cache.consume(nonce, now=1031))

    def test_capacity_and_invalid_nonce_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = NonceReplayCache(
                Path(directory) / "nonces", maximum_entries=1)
            self.assertFalse(cache.consume("not-a-nonce", now=1000))
            self.assertTrue(cache.consume("0" * 32, now=1000))
            self.assertFalse(cache.consume("1" * 32, now=1001))


if __name__ == "__main__":
    unittest.main()
