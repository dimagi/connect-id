from zxcvbn import zxcvbn
from django.core.exceptions import ValidationError

class EntropyPasswordValidator:

    def __init__(self, min_strength=2):
        self.min_strength = min_strength

    def validate(self, password, user=None):
        results = zxcvbn(password, user_inputs=['commcare'])
        if results['score'] < self.min_strength:
            raise ValidationError(
                "password is not complex enough"
            )

    def get_help_text(self):
        return "password is not complex enough"
