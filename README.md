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
[Deploy workflow](.github/workflows/deploy.yml). Do not deploy from a laptop.

Production deploys continuously: every push to `main` is deployed by the `Deploy` workflow once CI passes on it.
A deploy is skipped if CI failed, if a newer commit has landed on `main` since (that commit's own CI run deploys
it), or if the commit is already live. These are checked again just before the deploy starts, in case things
changed while it waited for an earlier deploy to finish. Deploys never overlap; merges that land while one is
running go out together in the next one.

To retry a failed deploy or redeploy, run the `Deploy` workflow by hand from the Actions tab. It must be run on
`main` (any other branch fails) and deploys right away, without waiting for CI. To ship a fix, merge it to `main`.

- `deploy/config/deploy.yml`: servers, roles, kamal-proxy and logging config.
- `deploy/.kamal/secrets`: commands that fetch secrets at deploy time (no values are committed).
- `deploy/Gemfile.lock`: the pinned Kamal version; Dependabot proposes updates. CI installs it with
  `bundle exec`, using the Ruby version in `deploy/.ruby-version`.

The web host sits behind an ALB, which terminates TLS. kamal-proxy runs on the web host on port 80
and switches traffic to the new container once `/up` answers. It keeps the ALB's `X-Forwarded-For` and appends
the ALB's address, which is why `NUM_PROXIES` is 2. The celery and celery-beat roles are not proxied.

### App environment

Every role gets the same environment, from `deploy/`:

- **Plain config** (hosts, client IDs, table names): `env.clear` in `config/deploy.yml`.
- **Secrets**: the `connect-id/production` secret in AWS Secrets Manager (us-east-1), one JSON key per env var.
  `config/secrets.yml` lists them with their type; `.kamal/secrets` fetches the secret once per deploy and extracts
  each key, and `env.secret` in `config/deploy.yml` reads its list from `config/secrets.yml`.

django-constance settings (country lists, SMS and OTP limits) are not env vars in production: edit them in admin
(see [docs/runtime-config.md](docs/runtime-config.md)).

A changed value reaches the containers on the next deploy: the next merge to `main`, or a run of the `Deploy` workflow
from GitHub Actions (Actions > Deploy > Run workflow, on `main`).

#### Adding an env var

Every env var the app reads (`connectid/settings.py`, `docker/`) must be handled one of three ways, or
`deploy/tests/test_production_secret.py` fails:

- **Plain config**: add it to `env.clear` in `deploy/config/deploy.yml`, quoted. Merging the PR deploys it. Change
  a plain value the same way.
- **Secret**: add it to `deploy/config/secrets.yml` and `deploy/.kamal/secrets`, and store its value before merging
  (see "Adding a secret" below).
- **Not set in production**, so the `settings.py` default applies: add it to `NOT_DEPLOYED` in
  `deploy/tests/test_production_secret.py`.

#### Managing secrets

Use `deploy/bin/production_secret.py` with [uv](https://docs.astral.sh/uv/) and the AWS CLI (logged in with
`aws sso login`), not the AWS console. On the way to the container Kamal expands `$NAME` in a secret and escapes
newlines and backslashes; the script stores each value in the form that comes out unchanged. It never prints a value.

```bash
uv run deploy/bin/production_secret.py list                  # every secret, its type, and whether it is set
uv run deploy/bin/production_secret.py set TWILIO_AUTH_TOKEN # prompts for the value, without echoing it
uv run deploy/bin/production_secret.py set OIDC_RSA_PRIVATE_KEY < key.pem    # multiline and json: pipe it in
uv run deploy/bin/production_secret.py check                 # what would stop a deploy
uv run deploy/bin/production_secret.py import docker.env     # copy values from an env file, after a yes/no on the diff
```

**Rotating a secret**: `set` it, then `check` it. It goes out with the next deploy; to ship it now, run the `Deploy`
workflow from GitHub Actions (Actions > Deploy > Run workflow, on `main`).

**Adding a secret**: in a PR, add `NAME: type` to `deploy/config/secrets.yml` (type is blank for a plain value,
`multiline` for one read with `env.str(..., multiline=True)` such as a PEM key, or `json`) and a
`NAME=$(kamal secrets extract NAME ${SECRETS})` line to `deploy/.kamal/secrets`. Then, from that branch, `set` it
and `check` **before** merging, since merging deploys it.

**Removing a secret**: take it out of both files first, and delete it from the secret after that deploy.

Before every deploy the pre-deploy hook (`deploy/.kamal/hooks/pre-deploy`) runs `check` and stops the deploy, before
any container changes, if a key is missing or a value would not arrive as intended (e.g. a `$` added in the console).

The deploy role (`github_deploy`) can read this one secret (`secretsmanager:GetSecretValue`) and call
`secretsmanager:BatchGetSecretValue`, which Kamal uses. Writing it takes your own AWS access.
