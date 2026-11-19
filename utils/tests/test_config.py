import pytest
from constance import config as constance_config
from constance.backends.database import DatabaseBackend
from constance.codecs import dumps
from constance.forms import ConstanceForm
from constance.models import Constance
from django.core.cache.backends.filebased import FileBasedCache

from utils.cache import FailSoftRedisCache
from utils.config import code_set


def test_code_set_drops_blanks_and_spaces_and_lowers(config):
    config.BLACKLISTED_COUNTRY_CODES = " KE, ng ,, "

    assert code_set("BLACKLISTED_COUNTRY_CODES") == {"ke", "ng"}


def test_code_set_is_empty_for_an_empty_setting(config):
    config.BLACKLISTED_COUNTRY_CODES = ""

    assert code_set("BLACKLISTED_COUNTRY_CODES") == set()


@pytest.fixture
def database_backend(monkeypatch, tmp_path):
    """The production backend: values in the database, cached. The conftest `config` fixture keeps them in memory.

    The cache is file-based rather than Redis, so the test needs no Redis and leaves none behind. Constance
    refuses a local-memory cache.
    """
    backend = DatabaseBackend()
    backend._cache = FileBasedCache(str(tmp_path), {"TIMEOUT": 300})
    monkeypatch.setattr(constance_config, "_backend", backend)
    return backend


@pytest.mark.django_db
def test_values_saved_to_the_database_are_read_back(database_backend):
    constance_config.SMS_SUPPORTED_COUNTRY_CODES = "265"
    constance_config.PHONE_COUNTRY_HOURLY_LIMIT = 7

    assert code_set("SMS_SUPPORTED_COUNTRY_CODES") == {"265"}
    assert constance_config.PHONE_COUNTRY_HOURLY_LIMIT == 7
    assert Constance.objects.get(key="PHONE_COUNTRY_HOURLY_LIMIT")


@pytest.mark.django_db
def test_reads_come_from_the_cache(database_backend, django_assert_num_queries):
    constance_config.PHONE_COUNTRY_HOURLY_LIMIT = 7
    # A change that skips the cache, e.g. made straight in the database, isn't seen until the cache expires.
    Constance.objects.filter(key="PHONE_COUNTRY_HOURLY_LIMIT").update(value=dumps(8))

    with django_assert_num_queries(0):
        assert constance_config.PHONE_COUNTRY_HOURLY_LIMIT == 7


@pytest.mark.django_db
def test_a_saved_change_is_seen_at_once(database_backend):
    constance_config.PHONE_COUNTRY_HOURLY_LIMIT = 7
    assert constance_config.PHONE_COUNTRY_HOURLY_LIMIT == 7

    constance_config.PHONE_COUNTRY_HOURLY_LIMIT = 9

    assert constance_config.PHONE_COUNTRY_HOURLY_LIMIT == 9


@pytest.mark.django_db
def test_reads_fall_back_to_the_database_when_the_cache_is_down(database_backend):
    constance_config.PHONE_COUNTRY_HOURLY_LIMIT = 7
    database_backend._cache = FailSoftRedisCache("redis://127.0.0.1:1/0", {"KEY_PREFIX": "constance"})

    assert constance_config.PHONE_COUNTRY_HOURLY_LIMIT == 7


@pytest.mark.parametrize(
    "field, value, valid",
    [
        ("SMS_SUPPORTED_COUNTRY_CODES", "265, 258,1", True),
        ("SMS_SUPPORTED_COUNTRY_CODES", "", True),
        ("SMS_SUPPORTED_COUNTRY_CODES", "+265", False),
        ("SMS_SUPPORTED_COUNTRY_CODES", "265 258", False),
        ("SMS_SUPPORTED_COUNTRY_CODES", "mw", False),
        ("BLACKLISTED_COUNTRY_CODES", "ke, NG", True),
        ("BLACKLISTED_COUNTRY_CODES", "", True),
        ("BLACKLISTED_COUNTRY_CODES", "ken", False),
        ("BLACKLISTED_COUNTRY_CODES", "254", False),
    ],
)
def test_admin_form_rejects_malformed_country_lists(config, field, value, valid):
    form = ConstanceForm(initial={})

    errors = []
    try:
        form.fields[field].clean(value)
    except Exception as e:
        errors.append(e)

    assert (not errors) == valid


@pytest.mark.django_db
def test_superusers_can_open_the_settings_page(client, django_user_model):
    admin = django_user_model.objects.create_superuser(username="admin", password="pw", phone_number="+15555550100")
    client.force_login(admin)

    response = client.get("/admin/constance/config/")

    assert response.status_code == 200
    assert b"SMS_SUPPORTED_COUNTRY_CODES" in response.content
    assert b"BLACKLISTED_COUNTRY_CODES" in response.content
