import pytest
from django.conf import settings as project_settings
from rest_framework.test import APIRequestFactory

from utils.rest_framework import SharedAnonRateThrottle


@pytest.fixture
def num_proxies(settings):
    def set_num_proxies(count):
        settings.REST_FRAMEWORK = {**project_settings.REST_FRAMEWORK, "NUM_PROXIES": count}

    return set_num_proxies


def anon_key(forwarded_for=None, remote_addr="10.0.0.9"):
    extra = {"REMOTE_ADDR": remote_addr}
    if forwarded_for is not None:
        extra["HTTP_X_FORWARDED_FOR"] = forwarded_for
    request = APIRequestFactory().get("/", **extra)
    request.user = None
    return SharedAnonRateThrottle().get_cache_key(request, None)


def test_num_proxies_is_set():
    # Production has the ALB, then Traefik
    assert project_settings.REST_FRAMEWORK["NUM_PROXIES"] == 2


def test_client_supplied_forwarded_for_entries_are_ignored():
    # The client sent "1.2.3.4"; the ALB appended the client's address, then Traefik the ALB's
    assert anon_key("1.2.3.4, 203.0.113.7, 10.0.0.5") == "throttle_anon_203.0.113.7"


def test_changing_the_spoofed_entry_does_not_change_the_bucket():
    assert anon_key("1.1.1.1, 203.0.113.7, 10.0.0.5") == anon_key("2.2.2.2, 203.0.113.7, 10.0.0.5")


def test_one_proxy(num_proxies):
    num_proxies(1)

    assert anon_key("1.2.3.4, 203.0.113.7") == "throttle_anon_203.0.113.7"


def test_zero_proxies_uses_remote_addr(num_proxies):
    num_proxies(0)

    assert anon_key("1.2.3.4") == "throttle_anon_10.0.0.9"


def test_no_forwarded_for_uses_remote_addr():
    assert anon_key() == "throttle_anon_10.0.0.9"
