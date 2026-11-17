import hashlib
import re

from django.contrib.auth.hashers import BasePasswordHasher, check_password, make_password, mask_hash
from django.utils.crypto import constant_time_compare
from django.utils.translation import gettext_noop as _

# What secrets.token_hex() returns for 16 bytes or more: at least 128 bits of entropy.
GENERATED_SECRET_RE = re.compile(r"[0-9a-f]{32,}")


class GeneratedSecretHasher(BasePasswordHasher):
    """Salted SHA-256, for server-generated random secrets only.

    Key stretching slows down guessing a password. A random secret of 128 bits or more can't be guessed even
    with a fast hash, so stretching it buys nothing, while PBKDF2 costs ~0.8s of CPU on the web hosts for
    every check, and the app sends the secret with every Basic-auth request.
    """

    algorithm = "sha256_secret"

    def encode(self, password, salt):
        self._check_encode_args(password, salt)
        digest = hashlib.sha256((salt + password).encode()).hexdigest()
        return f"{self.algorithm}${salt}${digest}"

    def decode(self, encoded):
        algorithm, salt, digest = encoded.split("$", 2)
        assert algorithm == self.algorithm
        return {"algorithm": algorithm, "hash": digest, "salt": salt}

    def verify(self, password, encoded):
        decoded = self.decode(encoded)
        return constant_time_compare(encoded, self.encode(password, decoded["salt"]))

    def safe_summary(self, encoded):
        decoded = self.decode(encoded)
        return {
            _("algorithm"): decoded["algorithm"],
            _("salt"): mask_hash(decoded["salt"], show=2),
            _("hash"): mask_hash(decoded["hash"]),
        }

    def harden_runtime(self, password, encoded):
        pass


def make_secret_password(raw_password):
    """make_password that uses GeneratedSecretHasher when the password is a generated secret."""
    if is_generated_secret(raw_password):
        return make_password(raw_password, hasher=GeneratedSecretHasher.algorithm)
    return make_password(raw_password)


def check_secret_password(raw_password, encoded, setter=None):
    """check_password that prefers GeneratedSecretHasher for generated secrets.

    The setter is called after a match when the stored hash used a different hasher, so a generated secret
    still stored with PBKDF2 moves to the fast hasher, and one already on it is never moved back.
    """
    preferred = GeneratedSecretHasher.algorithm if is_generated_secret(raw_password) else "default"
    return check_password(raw_password, encoded, setter, preferred=preferred)


def is_generated_secret(raw_password):
    return bool(raw_password) and GENERATED_SECRET_RE.fullmatch(raw_password) is not None
