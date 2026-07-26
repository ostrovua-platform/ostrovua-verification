"""Process-shared, fail-closed nonce replay cache for one-shot workers."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path


class NonceReplayCache:
    def __init__(
        self,
        directory: str | Path = "/tmp/ostrovua-biometric-nonces",
        ttl_seconds: int = 60,
        maximum_entries: int = 4096,
    ):
        self.directory = Path(directory)
        self.ttl_seconds = ttl_seconds
        self.maximum_entries = maximum_entries

    def _prepare(self) -> None:
        self.directory.mkdir(mode=0o700, parents=False, exist_ok=True)
        details = self.directory.lstat()
        if not stat.S_ISDIR(details.st_mode) or stat.S_ISLNK(details.st_mode):
            raise OSError("nonce cache path is not a private directory")
        os.chmod(self.directory, 0o700)

    def _cleanup(self, now: float) -> int:
        entries = 0
        cutoff = now - self.ttl_seconds
        with os.scandir(self.directory) as iterator:
            for entry in iterator:
                if not entry.name.endswith(".nonce") or entry.is_symlink():
                    raise OSError("nonce cache contains an unexpected entry")
                details = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(details.st_mode):
                    raise OSError("nonce cache contains a non-regular entry")
                if details.st_mtime < cutoff:
                    os.unlink(entry.path)
                else:
                    entries += 1
        return entries

    def consume(self, nonce: str, now: float | None = None) -> bool:
        if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
            return False
        try:
            self._prepare()
            current = time.time() if now is None else now
            if self._cleanup(current) >= self.maximum_entries:
                return False
            name = hashlib.sha256(nonce.encode("ascii")).hexdigest() + ".nonce"
            path = self.directory / name
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            try:
                os.write(descriptor, b"1")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.utime(path, (current, current), follow_symlinks=False)
            return True
        except FileExistsError:
            return False
        except OSError:
            # Cache availability is part of authentication. Never fail open.
            return False
