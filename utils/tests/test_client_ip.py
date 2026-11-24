import pytest
from django.conf import settings as project_settings
from rest_framework.test import APIRequestFactory

from utils import get_ip
from utils.rest_framework import SharedAnonRateThrottle


@pytest.fixture
def num_proxies(settings):
    def set_num_proxies(count):
        settings.REST_FRAMEWORK = {**project_settings.REST_FRAMEWORK, "NUM_PROXIES": count}

    return set_num_proxies


def make_request(forwarded_for=None, remote_addr="10.0.0.9"):
    extra = {"REMOTE_ADDR": remote_addr}
    if forwarded_for is not None:
        extra["HTTP_X_FORWARDED_FOR"] = forwarded_for
    return APIRequestFactory().get("/", **extra)


def anon_key(request):
    request.user = None
    return SharedAnonRateThrottle().get_cache_key(request, None)


def test_num_proxies_is_set():
    assert project_settings.REST_FRAMEWORK["NUM_PROXIES"] == 1


def test_client_supplied_forwarded_for_entries_are_ignored():
    # The client sent "1.2.3.4"; the proxy appended the address it saw
    request = make_request("1.2.3.4, 203.0.113.7")

    assert get_ip(request) == "203.0.113.7"
    assert anon_key(request) == "throttle_anon_203.0.113.7"


def test_changing_the_spoofed_entry_does_not_change_the_bucket():
    assert anon_key(make_request("1.1.1.1, 203.0.113.7")) == anon_key(make_request("2.2.2.2, 203.0.113.7"))


def test_two_proxies(num_proxies):
    num_proxies(2)
    request = make_request("1.2.3.4, 203.0.113.7, 10.0.0.5")

    assert get_ip(request) == "203.0.113.7"
    assert anon_key(request) == "throttle_anon_203.0.113.7"


def test_zero_proxies_uses_remote_addr(num_proxies):
    num_proxies(0)

    assert get_ip(make_request("1.2.3.4")) == "10.0.0.9"


def test_no_forwarded_for_uses_remote_addr():
    assert get_ip(make_request()) == "10.0.0.9"


def test_not_an_address_gives_none():
    assert get_ip(make_request("not-an-ip")) is None
