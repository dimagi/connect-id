"""Tests for AllowCIDRMiddleware, the first entry in the middleware stack.

django-allow-cidr does not declare support for Django 4.2 and nothing else exercises it, so these
cover it directly. The middleware whitelists *Host headers* that fall inside ``ALLOWED_CIDR_NETS``
(the usual case being a load balancer health check addressing the instance by IP), which is why
these assert on ``HTTP_HOST`` rather than on the client address.
"""

import allow_cidr.middleware as allow_cidr_middleware
import pytest
from django.test import Client, override_settings

# Unauthenticated and DB-free, so a request either survives the middleware or it doesn't.
URL = "/.well-known/assetlinks.json"

ALLOWED_NET = "10.0.0.0/8"
HOST_INSIDE_NET = "10.1.2.3"
HOST_OUTSIDE_NET = "192.168.5.5"
NAMED_HOST = "connectid.example.com"


@pytest.fixture(autouse=True)
def reset_allow_cidr_globals():
    """The middleware appends to a module-level global on construction; keep tests independent."""
    original = list(allow_cidr_middleware.ORIG_ALLOWED_HOSTS)
    allow_cidr_middleware.ORIG_ALLOWED_HOSTS.clear()
    yield
    allow_cidr_middleware.ORIG_ALLOWED_HOSTS.clear()
    allow_cidr_middleware.ORIG_ALLOWED_HOSTS.extend(original)


def _get(host):
    """A fresh Client per call, so the middleware chain is built under the active settings."""
    return Client().get(URL, HTTP_HOST=host)


@pytest.mark.parametrize(
    ("host", "expected_status"),
    [
        (HOST_INSIDE_NET, 200),
        (HOST_OUTSIDE_NET, 400),
        # Enabling the middleware must not cost us the regular ALLOWED_HOSTS entries...
        (NAMED_HOST, 200),
        # ...nor let a non-IP host outside ALLOWED_HOSTS through the CIDR check.
        ("attacker.example.net", 400),
    ],
    ids=["ip-inside-cidr", "ip-outside-cidr", "named-host-in-allowed-hosts", "unknown-named-host"],
)
@override_settings(ALLOWED_CIDR_NETS=[ALLOWED_NET], ALLOWED_HOSTS=[NAMED_HOST])
def test_host_admission(host, expected_status):
    assert _get(host).status_code == expected_status


@override_settings(ALLOWED_CIDR_NETS=[], ALLOWED_HOSTS=[NAMED_HOST])
def test_middleware_disabled_without_cidr_nets():
    """Our production default is an empty list, which disables the middleware via MiddlewareNotUsed.

    Confirms the acceptance above is really the middleware's doing and not ALLOWED_HOSTS.
    """
    assert _get(HOST_INSIDE_NET).status_code == 400
    assert _get(NAMED_HOST).status_code == 200
