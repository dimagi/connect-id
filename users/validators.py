from datetime import timedelta

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.utils.timezone import now
from zxcvbn import zxcvbn

from users.hashers import is_generated_secret


class EntropyPasswordValidator:
    def __init__(self, min_strength=2):
        self.min_strength = min_strength

    def validate(self, password, user=None):
        results = zxcvbn(password, user_inputs=["commcare"])
        if results["score"] < self.min_strength:
            raise ValidationError("password is not complex enough")

    def get_help_text(self):
        return "password is not complex enough"


class NotGeneratedSecretValidator:
    """Reject chosen passwords that look like server-generated secrets.

    Those get the fast GeneratedSecretHasher, which is only safe for random secrets.
    """

    def validate(self, password, user=None):
        if is_generated_secret(password):
            raise ValidationError("password must not be only lowercase hex characters")

    def get_help_text(self):
        return "password must not be only lowercase hex characters"


def validate_not_after_tomorrow(value):
    if value > now().date() + timedelta(days=1):
        raise ValidationError("date cannot be in the future")


validate_language_codes = RegexValidator(
    regex=r"^[a-z]{3}(,[a-z]{3})*$",
    message="languages must be comma-separated ISO 639-3 codes",
)
