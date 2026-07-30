"""Firebase Admin SDK setup.

Kept out of ``settings`` so the credential construction and app initialization are importable and
testable on their own; settings supplies only the environment values.
"""

from firebase_admin import App, credentials, initialize_app

# Cap the FCM HTTP timeout well under Gunicorn's worker timeout (default 120s otherwise), so a slow
# Firebase round-trip fails fast instead of outliving the worker.
DEFAULT_HTTP_TIMEOUT_SECONDS = 15


def build_service_account_credentials(
    *,
    project_id: str,
    private_key_id: str,
    private_key: str,
    client_email: str,
    client_id: str,
    client_x509_cert_url: str,
) -> dict:
    """Build the service-account dict that ``credentials.Certificate`` expects."""
    return {
        "type": "service_account",
        "project_id": project_id,
        "private_key_id": private_key_id,
        "private_key": private_key,
        "client_email": client_email,
        "client_id": client_id,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": client_x509_cert_url,
        "universe_domain": "googleapis.com",
    }


def initialize_firebase_app(
    service_account: dict,
    *,
    http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
    name: str | None = None,
) -> App:
    """Initialize a Firebase app from a service-account dict.

    ``name`` is only used by tests; production initializes the default app, which is what
    ``FCM_DJANGO_SETTINGS["DEFAULT_FIREBASE_APP"] = None`` resolves to.
    """
    creds = credentials.Certificate(service_account)
    kwargs = {"credential": creds, "options": {"httpTimeout": http_timeout_seconds}}
    if name is not None:
        kwargs["name"] = name
    return initialize_app(**kwargs)
