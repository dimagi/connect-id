from secrets import token_hex

import pytest
from django.contrib.auth.hashers import identify_hasher, make_password

from users.factories import UserDeviceInfoFactory, UserFactory
from users.hashers import GeneratedSecretHasher, check_secret_password, is_generated_secret, make_secret_password
from users.models import ConnectUser, UserDeviceInfo

GENERATED = token_hex()


@pytest.mark.parametrize(
    "raw, expected",
    [
        (token_hex(), True),
        (token_hex(16), True),
        (token_hex(15), False),
        (token_hex().upper(), False),
        ("correct horse battery staple", False),
        ("", False),
        (None, False),
    ],
)
def test_is_generated_secret(raw, expected):
    assert is_generated_secret(raw) is expected


@pytest.mark.parametrize(
    "raw, algorithm",
    [
        (GENERATED, GeneratedSecretHasher.algorithm),
        ("correct horse battery staple", "pbkdf2_sha256"),
    ],
)
def test_make_secret_password(raw, algorithm):
    encoded = make_secret_password(raw)
    assert identify_hasher(encoded).algorithm == algorithm
    assert check_secret_password(raw, encoded)
    assert not check_secret_password(raw + "x", encoded)


def test_hashes_are_salted():
    assert make_secret_password(GENERATED) != make_secret_password(GENERATED)


@pytest.mark.django_db
class TestPasswordUpgrade:
    @pytest.mark.parametrize("model", [ConnectUser, UserDeviceInfo])
    def test_pbkdf2_hash_of_generated_secret_moves_to_fast_hasher(self, model):
        obj = _make(model, make_password(GENERATED))

        assert obj.check_password(GENERATED)

        obj.refresh_from_db()
        assert identify_hasher(obj.password).algorithm == GeneratedSecretHasher.algorithm
        assert obj.check_password(GENERATED)

    @pytest.mark.parametrize("model", [ConnectUser, UserDeviceInfo])
    def test_fast_hash_stays_after_check(self, model):
        obj = _make(model, make_secret_password(GENERATED))
        stored = obj.password

        assert obj.check_password(GENERATED)

        obj.refresh_from_db()
        assert obj.password == stored

    @pytest.mark.parametrize("model", [ConnectUser, UserDeviceInfo])
    def test_wrong_password_does_not_change_hash(self, model):
        obj = _make(model, make_password(GENERATED))
        stored = obj.password

        assert not obj.check_password(token_hex())

        obj.refresh_from_db()
        assert obj.password == stored

    def test_chosen_user_password_stays_on_pbkdf2(self):
        user = UserFactory()
        user.set_password("correct horse battery staple")
        user.save()

        assert user.check_password("correct horse battery staple")

        user.refresh_from_db()
        assert identify_hasher(user.password).algorithm == "pbkdf2_sha256"


def _make(model, encoded):
    if model is ConnectUser:
        user = UserFactory()
        ConnectUser.objects.filter(pk=user.pk).update(password=encoded)
        user.refresh_from_db()
        return user
    return UserDeviceInfoFactory(password=encoded)
