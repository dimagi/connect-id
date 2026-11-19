# Connect-ID

## Steps to Set Up the Project Locally:

1. **Install [uv](https://docs.astral.sh/uv/) to manage Python and dependencies:**

   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. **Create the virtual environment and install dependencies (including dev):**

   ```bash
   uv sync
   ```

   This creates a virtual environment in `.venv` (using Python 3.11) and installs
   all dependencies from `uv.lock`. Activate it with `source .venv/bin/activate`,
   or prefix commands with `uv run` (e.g. `uv run ./manage.py runserver`).

   To add a new dependency:

   ```bash
   uv add <pkg>           # runtime dependency
   uv add --dev <pkg>     # dev-only dependency
   ```

3. **Install Git hooks:**

   ```bash
   uv run pre-commit install
   uv run pre-commit run -a
   ```

4. **Create an environment file:**

   ```bash
   cp .env_template .env
   ```

   The template works as-is against the services in `docker-compose.yml`. Every
   other setting is commented out and has a default in `connectid/settings.py`;
   uncomment only what you need. Note that a key left present but empty
   overrides its default rather than falling back to it.

5. **Run local services with docker-compose:**

   ```bash
   docker compose up
   ```

   To use your own PostgreSQL and Redis instead, skip this step and point
   `DATABASE_URL`, `CELERY_BROKER_URL`, and `REDIS_URL` at them.

6. **Run Django migrations and start the development server:**

   ```bash
   uv run ./manage.py migrate
   uv run ./manage.py runserver
   ```

## Running locally without external services

Individual external services (Connect, SMS, service integrity) can be disabled in the `.env`
to support local development. Some service toggles can only be disabled if `DEBUG=True`, and
some services may require `CELERY_TASK_ALWAYS_EAGER=True` if there is no local celery config.

## Health checks

| Path              | Use                                                            | Checks                                                  | Auth  |
| ----------------- | -------------------------------------------------------------- | ------------------------------------------------------- | ----- |
| `/up`             | Container health check (Kamal, see `deploy/config/deploy.yml`) | None: Django is serving requests                        | None  |
| `/status/`        | Status page / uptime monitor                                   | Database, Redis (Celery broker)                         | Token |
| `/status/celery/` | Status page / uptime monitor                                   | A Celery worker answers a ping and consumes every queue | Token |

`/status/` URLs return 200 when every check passes and 500 when any fails, with one line per
check. Pick the format with `?format=json` or `?format=text`, or the `Accept` header.

When `HEALTH_CHECK_TOKENS` (comma-separated) is set, `/status/` URLs need one of those tokens,
either in an `Authorization: Bearer <token>` header (preferred: it keeps the token out of URLs
and access logs) or as `?token=<token>`. A missing or wrong token gets a 404. `/up` is never
protected. `/status/` leaves out Celery
so the web tier is not reported down because workers are. Neither `/up` nor `/status/` is
traced in Sentry.

The checks are defined in `connectid/health_checks.py`, built on
[django-health-check](https://codingjoe.dev/django-health-check/).

## Production Deploy

Production is deployed with [Kamal 2](https://kamal-deploy.org/), only from the
[Deploy workflow](.github/workflows/deploy.yml). It runs on a schedule (Monday, Wednesday and Friday,
when there is something new on `main` and CI passed) and can be started by hand from the Actions tab.
Do not deploy from a laptop.

- `deploy/config/deploy.yml`: servers, roles, kamal-proxy and logging config.
- `deploy/.kamal/secrets`: commands that fetch secrets at deploy time (no values are committed).
- `deploy/Gemfile.lock`: the pinned Kamal version; Dependabot proposes updates. CI installs it with
  `bundle exec`, using the Ruby version in `deploy/.ruby-version`.

The web host sits behind an ALB, which terminates TLS. kamal-proxy runs on the web host on port 80
and switches traffic to the new container once `/up` answers. The celery and celery-beat roles are
not proxied.

App environment variables are read on each host from `/home/connect/www/docker.env`.
