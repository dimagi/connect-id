# Connect-ID

Django REST API backend for personal identity and digital credential management, part of the CommCare Connect ecosystem by Dimagi.

## Commands

```bash
# Dev setup
cp .env_template .env              # then fill in values
docker compose up                  # PostgreSQL on :5433, Redis on :6379
uv sync                            # create .venv and install deps (incl. dev) from uv.lock
uv run ./manage.py migrate         # or activate: source .venv/bin/activate
uv run ./manage.py runserver

# Dependencies (uv)
uv add <pkg>                       # add a runtime dependency
uv add --dev <pkg>                 # add a dev dependency
uv lock                            # re-resolve uv.lock after editing pyproject.toml

# Tests
pytest                             # all tests (uses --reuse-db by default)
pytest users/tests/test_views.py   # specific file
pytest -k test_name                # specific test

# Code quality (all run via pre-commit)
pre-commit run -a                  # run all hooks
ruff format .                      # format (line-length: 119)
ruff check --fix .                 # lint + sort imports

# Celery
celery -A connectid.celery_app worker -B -l INFO
```

## Architecture

```
connectid/          # Django project settings, URLs, WSGI/ASGI, Celery config
users/              # Core app: auth, registration, credentials, phone validation
messaging/          # Messages, channels, notifications (FCM push)
flags/              # Feature toggles (django-waffle)
payments/           # Payment/transaction tracking
services/ai/        # OpenChatStudio integration (name similarity)
utils/              # Shared helpers: SMS, notifications, middleware, app integrity
  app_integrity/    # Google Play Integrity verification
test_utils/         # Test decorators and helpers
docker/             # Entrypoint scripts (start, start_migrate, start_celery)
deploy/             # Kamal deployment config
```

## Key Files

- `connectid/settings.py` - All Django settings, env var configuration
- `connectid/urls.py` - Root URL routing
- `users/models.py` - ConnectUser (custom user model), UserKey, PhoneDevice, Credential models
- `users/views.py` - Main API endpoints (~1000 lines)
- `conftest.py` - Shared pytest fixtures (user, authed_client, oauth_app, etc.)

## Tech Stack

- **Python 3.11**, Django 4.1, Django REST Framework
- **PostgreSQL** + **Redis** (Celery broker/cache)
- **Celery** with beat scheduler for async tasks
- **OAuth2/OIDC** via django-oauth-toolkit
- **Firebase** (FCM push notifications)
- **Twilio** (SMS)
- **AWS S3** (photo storage)
- **Google Play Integrity** for app validation
- **django-waffle** for feature flags
- **Sentry** for error tracking

## Code Style

- Ruff formatter, line-length 119
- Ruff linter (E/W/F/I rules, line-length 119, excludes migrations) — import sorting replaces isort
- Pre-commit hooks enforce all of the above plus pyupgrade (3.11+) and django-upgrade (4.1)

## Gotchas

- **Custom user model**: `ConnectUser` extends AbstractUser. Phone number is the primary identifier, not email/username.
- **Phone-based auth**: Phone numbers must be unique among active users. Numbers with `TEST_NUMBER_PREFIX` bypass SMS sending.
- **Recovery pin**: Must use `set_recovery_pin()` method (hashes internally), never assign directly.
- **Celery runs eagerly**: `CELERY_TASK_ALWAYS_EAGER = True` in settings, so async tasks execute synchronously in dev/test.
- **API versioning**: Via Accept header, defaults to v2.0. v1.0 is deprecated but still supported.
- **App integrity**: All app requests validate Google Play Integrity tokens. Use `@skip_app_integrity_check` decorator in tests.
- **Docker Compose PostgreSQL**: Runs on port **5433** (not 5432).
- **User lock vs deactivation**: `is_locked` (security lock from failed attempts) is separate from `is_active` (account deactivation).
- **Message status flow**: PENDING -> SENT_TO_SERVICE -> DELIVERED -> CONFIRMED_RECEIVED
- **AllowCIDRMiddleware**: Runs first in middleware stack for IP whitelisting.

## Testing

- pytest with pytest-django, `--reuse-db` enabled by default
- Factory Boy factories in each app (`users/factories.py`, `messaging/factories.py`, etc.)
- `test_utils/decorators.py` has `@skip_app_integrity_check` for bypassing integrity checks in tests
- CI runs linting + pytest against PostgreSQL 12

## Environment

All config via env vars (see `.env_template`). Key ones:

- `DATABASE_URL` - PostgreSQL connection string
- `CELERY_BROKER_URL` / `REDIS_URL` - Redis URLs
- `TWILIO_*` - SMS provider credentials
- `FCM_*` - Firebase Cloud Messaging credentials
- `GOOGLE_*` - Google Play Integrity / Analytics
- `OIDC_RSA_PRIVATE_KEY` - OAuth2/OIDC signing key
- `AWS_S3_PHOTO_BUCKET_NAME` - Photo storage bucket
- `SENTRY_DSN` - Error tracking
- `MAPBOX_ACCESS_TOKEN` - Geolocation/country code detection
