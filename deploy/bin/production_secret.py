#!/usr/bin/env python3
"""Manage the app's secrets in AWS Secrets Manager (the connect-id/production secret).

Kamal reads that secret at deploy time (deploy/.kamal/secrets) and hands each key to the containers as an env var
(`env.secret` in deploy/config/deploy.yml). Plain config is in `env.clear` there instead.

    production_secret.py plan  SOURCE            # key names only: what goes where, what can't be stored
    production_secret.py push  [--dry-run] SOURCE  # create or replace the secret from an env file
    production_secret.py push  --merge SOURCE      # change only the keys in SOURCE (add or rotate a secret)
    production_secret.py clear SOURCE            # print an `env.clear` block for deploy.yml (plain config only)
    production_secret.py check                   # pre-deploy hook: every value in the secret is safe to deploy

SOURCE is a file in Docker's --env-file format (e.g. the old /home/connect/www/docker.env), or `-` for stdin.
Only keys deployed as secrets, i.e. extracted in deploy/.kamal/secrets, are stored. Values are never printed or
written to disk: the JSON goes to the AWS CLI on its stdin. Needs Python 3.9+ and the AWS CLI, nothing else.

Why values are encoded: between Secrets Manager and the container, Kamal 2.12 changes values in two places.
  1. It reads deploy/.kamal/secrets with dotenv, which expands `$NAME` and `${NAME}` in each secret's value (from the
     deploying machine's environment, else to nothing) and turns `\\$` into `$`.
  2. It writes the secrets into an env file for `docker run --env-file`, escaped with Ruby's String#dump (a newline
     becomes the two characters `\\n`, a backslash is doubled, ...). Docker doesn't unescape them. It also drops one
     trailing newline.
So the stored value is the one that comes out of those two steps as the value the container should see: every `$`
is written `\\$`, and escapes like `\\n` are stored as the character they stand for (a PEM key is stored with real
newlines). `push` does this and checks the result by running Kamal's steps forward; `check` (run by the pre-deploy
hook) refuses a deploy if a value would be changed by step 1, e.g. after a hand edit in the AWS console.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_SECRET_ID = "connect-id/production"
DEFAULT_REGION = "us-east-1"
KAMAL_SECRETS_FILE = Path(__file__).resolve().parent.parent / ".kamal" / "secrets"

# Every env var the app reads (connectid/settings.py, docker/start*, libraries) falls in exactly one group below.
# deploy/tests/test_production_secret.py fails when settings.py reads one that isn't listed.

# May be deployed as secrets. Which ones are, is the list in deploy/.kamal/secrets.
SECRET_KEYS = frozenset(
    {
        "SECRET_KEY",
        "DATABASE_URL",
        "CELERY_BROKER_URL",
        "RATE_LIMIT_REDIS_URL",
        "TWILIO_ACCOUNT_SID",
        "TWILIO_AUTH_TOKEN",
        "FCM_PRIVATE_KEY",
        "FCM_PRIVATE_KEY_ID",
        "GOOGLE_PRIVATE_KEY",
        "GOOGLE_PRIVATE_KEY_ID",
        "OIDC_RSA_PRIVATE_KEY",
        "BIGQUERY_GOOGLE_CREDENTIALS_JSON",
        "OCS_API_KEY",
        "GA_API_SECRET",
        "SUPERSET_UPLOAD_PASSWORD",
        "COMMCARE_CONNECT_CLIENT_SECRET",
        "MAPBOX_ACCESS_TOKEN",
        "SENTRY_DSN",
        "HEALTH_CHECK_TOKENS",
        # Only if the hosts use static AWS keys rather than their instance role
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
    }
)

# Plain config: goes in `env.clear` in deploy.yml, never in the secret.
CLEAR_KEYS = frozenset(
    {
        "AWS_DEFAULT_REGION",
        "AWS_S3_MESSAGE_ATTACHMENTS_BUCKET_NAME",
        "AWS_S3_PHOTO_BUCKET_NAME",
        "AXES_ENABLED",
        "BIGQUERY_CONFIGURATION_SESSION_TABLE",
        "BIGQUERY_DATASET_ID",
        "CELERY_TASK_ALWAYS_EAGER",
        "CELERY_TASK_EAGER_PROPAGATES",
        "COMMCARE_CONNECT_CLIENT_ID",
        "CONNECT_DISABLED",
        "CSRF_TRUSTED_ORIGINS",
        "DEBUG",
        "DEFAULT_FILE_STORAGE_BACKEND",
        "DEFAULT_FROM_EMAIL",
        "DJANGO_ALLOWED_CIDR_NETS",
        "DJANGO_ALLOWED_HOSTS",
        "DJANGO_EMAIL_BACKEND",
        "EMAIL_OTP_VALIDITY_SECONDS",
        "FCM_CLIENT_EMAIL",
        "FCM_CLIENT_ID",
        "FCM_CLIENT_X509_CERT_URL",
        "FCM_HTTP_TIMEOUT_SECONDS",
        "FCM_PROJECT_ID",
        "FIREBASE_APP_ID",
        "GOOGLE_CLIENT_EMAIL",
        "GOOGLE_CLIENT_ID",
        "GOOGLE_CLIENT_X509_CERT_URL",
        "GOOGLE_PROJECT_ID",
        "NUM_PROXIES",
        "OCS_CULTURAL_NAME_BOT_ID",
        "PLAYSTORE_INTEGRITY_DISABLED",
        "REFRESH_TOKEN_EXPIRE_SECONDS",
        "REQUEST_LOG_LEVEL",
        "RICH_MESSAGING_ENABLED",
        "SENTRY_ENVIRONMENT",
        "SENTRY_RELEASE",
        "SENTRY_TRACES_SAMPLE_RATE",
        "SMS_DEFAULT_VENDOR",
        "SUPERSET_UPLOAD_BASE_URL",
        "SUPERSET_UPLOAD_DATABASE_ID",
        "SUPERSET_UPLOAD_TABLE_NAME",
        "SUPERSET_UPLOAD_TABLE_SCHEMA",
        "SUPERSET_UPLOAD_USERNAME",
        "TWILIO_MESSAGING_SERVICE",
        "WEB_CONCURRENCY",
    }
)

# django-constance seeds: only read the first time a setting is used, then the database wins
# (docs/runtime-config.md). Not deployed.
SEED_KEYS = frozenset(
    {
        "SMS_SUPPORTED_COUNTRY_CODES",
        "BLACKLISTED_COUNTRY_CODES",
        "PHONE_COUNTRY_HOURLY_LIMIT",
        "PHONE_COUNTRY_DAILY_LIMIT",
        "SMS_NUMBER_HOURLY_LIMIT",
        "SMS_NUMBER_DAILY_LIMIT",
        "OTP_USER_HOURLY_LIMIT",
        "OTP_USER_DAILY_LIMIT",
        "RATE_LIMIT_WARN_FRACTION",
    }
)

# Read by nothing in the app. Not deployed.
UNUSED_KEYS = frozenset({"REDIS_URL"})

# Read by settings.py with env.str(..., multiline=True): a literal \n in the value becomes a newline.
MULTILINE_KEYS = frozenset({"FCM_PRIVATE_KEY", "GOOGLE_PRIVATE_KEY", "OIDC_RSA_PRIVATE_KEY"})
# Parsed with json.loads by settings.py
JSON_KEYS = frozenset({"BIGQUERY_GOOGLE_CREDENTIALS_JSON"})


class SecretError(Exception):
    pass


# ---------------------------------------------------------------------------------------------------------------------
# Env files, as Docker reads them (docker/cli opts/parse.go)


def _env_file_line(number, line):
    """(key, value, problem) for one line of a Docker --env-file. key is None when the line sets nothing."""
    line = line.removesuffix("\r").lstrip()
    if not line or line.startswith("#"):
        return None, None, None
    key, sep, value = line.partition("=")
    key = key.lstrip(" \t")
    if not key or any(c in key for c in " \t"):
        return None, None, f"line {number}: not KEY=value (skipped)"
    if not sep:
        return None, None, f"{key}: no '=', Docker copies it from the host's environment (skipped)"
    return key, value, None


def parse_env_file(text):
    """Return ({key: value}, [problems]) for a Docker --env-file. Values are taken as is: Docker doesn't unquote or
    unescape them. Problems name keys only."""
    env, problems = {}, []
    for number, line in enumerate(text.removeprefix("\ufeff").split("\n"), start=1):
        key, value, problem = _env_file_line(number, line)
        if problem:
            problems.append(problem)
        if key is None:
            continue
        if key in env:
            problems.append(f"{key}: set more than once, the last value is used")
        env[key] = value
    return env, problems


def deployed_secret_keys(path=None):
    """The keys extracted from the secret in deploy/.kamal/secrets, in file order."""
    path = path or KAMAL_SECRETS_FILE
    pattern = re.compile(r"^([A-Z0-9_]+)=\$\(kamal secrets extract ([A-Z0-9_]+) \$\{SECRETS\}\)\s*$")
    keys = []
    for line in Path(path).read_text().splitlines():
        match = pattern.match(line)
        if match:
            if match.group(1) != match.group(2):
                raise SecretError(f"{path}: {match.group(1)} extracts {match.group(2)}")
            keys.append(match.group(1))
    return keys


# ---------------------------------------------------------------------------------------------------------------------
# What Kamal 2.12 does to a value on its way from Secrets Manager to the container. Mirrors Dotenv 3.2's
# Substitutions::Variable, Kamal's InlineCommandSubstitution (.chomp) and Kamal::EnvFile (String#dump). Checked
# against the real gems by deploy/tests/kamal_roundtrip.py.

_DOTENV_VARIABLE = re.compile(r"(\\)?(\$)(?!\()\{?([A-Z0-9_]+)?\}?", re.IGNORECASE)


def dotenv_substitute(value, env=None):
    env = env or {}

    def replace(match):
        if match.group(1):
            return match.group(0)[1:]
        if match.group(3):
            return env.get(match.group(3), "")
        return match.group(0)

    return _DOTENV_VARIABLE.sub(replace, value)


def ruby_chomp(value):
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith(("\n", "\r")):
        return value[:-1]
    return value


_DUMP_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\f": "\\f",
    "\v": "\\v",
    "\b": "\\b",
    "\a": "\\a",
    "\x1b": "\\e",
}
_UNDUMP_ESCAPES = {escaped[1]: char for char, escaped in _DUMP_ESCAPES.items() if char != '"'}


def _ruby_dump_ascii(value):
    out = []
    for i, char in enumerate(value):
        if char in _DUMP_ESCAPES:
            out.append(_DUMP_ESCAPES[char])
        elif char == "#" and value[i + 1 : i + 2] in ("{", "$", "@"):
            out.append("\\#")
        elif " " <= char <= "~":
            out.append(char)
        else:
            out.append(f"\\x{ord(char):02X}")
    return "".join(out)


def kamal_env_file_value(value):
    """Kamal::EnvFile#escape_docker_env_file_value: ASCII runs are dumped, other runs kept as they are."""
    parts = []
    for part in re.findall(r"[\x00-\x7f]+|[^\x00-\x7f]+", value):
        if part.isascii():
            part = _ruby_dump_ascii(part).replace('\\"', '"')
            part = re.sub(r"\\#", "#", part)
        parts.append(part)
    return "".join(parts)


def container_value(stored):
    """The env var value a container gets for a value stored in Secrets Manager."""
    return kamal_env_file_value(ruby_chomp(dotenv_substitute(stored)))


_DUMP_ESCAPE = re.compile(r"\\(x[0-9A-F]{2}|.)", re.DOTALL)


def _undump(value):
    """Reverse Ruby's String#dump escapes (\\n, \\\\, \\xHH, ...). Other backslashes are kept as they are."""

    def replace(match):
        escape = match.group(1)
        if escape in _UNDUMP_ESCAPES:
            return _UNDUMP_ESCAPES[escape]
        if len(escape) == 3:
            return chr(int(escape[1:], 16))
        return match.group(0)

    return _DUMP_ESCAPE.sub(replace, value)


def encode(value):
    """The value to store so that the container gets `value`. Raises SecretError if Kamal can't deliver it."""
    stored = _undump(value)
    if ruby_chomp(stored) != stored:
        stored += "\n"  # Kamal drops one trailing newline
    stored = re.sub(r"\$(?!\()", r"\\$", stored)  # dotenv leaves '$(' alone
    if container_value(stored) != value:
        raise SecretError("Kamal can't deliver this value unchanged")
    return stored


def _json_problem(key, seen):
    if not seen:  # settings.py treats empty as unset
        return None
    try:
        parsed = json.loads(seen)
    except ValueError:
        return f"{key}: is not valid JSON once deployed (store it with `push`, not by hand)"
    if isinstance(parsed, dict) and "\\" in str(parsed.get("private_key", "")):
        return f"{key}: private_key would have literal backslashes (store it with `push`, not by hand)"
    return None


def deploy_problems(key, stored):
    """Why a stored value would not reach the container as intended (no values in the messages)."""
    if dotenv_substitute(stored) != re.sub(r"\\\$(?!\()", "$", stored):
        return [f"{key}: has a '$' not written as '\\$', which Kamal would expand"]
    seen = container_value(stored)
    if key in MULTILINE_KEYS and "\\\\" in seen:
        return [f"{key}: has a literal '\\n' (store the key with real newlines)"]
    problem = _json_problem(key, seen) if key in JSON_KEYS else None
    return [problem] if problem else []


# ---------------------------------------------------------------------------------------------------------------------
# Commands


def read_source(source):
    text = sys.stdin.read() if source == "-" else Path(source).read_text()
    env, problems = parse_env_file(text)
    for problem in problems:
        print(f"warning: {problem}", file=sys.stderr)
    return env


def classify(env, deployed):
    """Key names in env by group (see GROUP_HELP), each sorted. A key goes in the first group whose set has it."""
    sets = [
        ("secret", deployed),
        ("secret, not deployed", SECRET_KEYS),
        ("clear", CLEAR_KEYS),
        ("seed", SEED_KEYS),
        ("unused", UNUSED_KEYS),
    ]
    groups = {name: [] for name in GROUP_HELP}
    for key in sorted(env):
        group = next((name for name, keys in sets if key in keys), "unknown")
        groups[group].append(key)
    return groups


GROUP_HELP = {
    "secret": "stored in the secret and deployed",
    "secret, not deployed": "secret, but not in deploy/.kamal/secrets: add it there and to env.secret to deploy it",
    "clear": "plain config: belongs in env.clear in deploy/config/deploy.yml",
    "seed": "django-constance seed, dropped (the database holds the value)",
    "unused": "read by nothing, dropped",
    "unknown": "not known to this script: classify it in production_secret.py",
}


def encode_all(env, keys):
    stored, problems = {}, []
    for key in keys:
        try:
            stored[key] = encode(env[key])
        except SecretError as e:
            problems.append(f"{key}: {e}")
            continue
        problems += deploy_problems(key, stored[key])
    return stored, problems


def print_keys(heading, keys):
    if keys:
        print(f"{heading}:")
        print("".join(f"  {key}\n" for key in keys), end="")


def cmd_plan(args):
    env = read_source(args.source)
    deployed = deployed_secret_keys()
    groups = classify(env, set(deployed))
    for name, keys in groups.items():
        print_keys(f"{name} ({GROUP_HELP[name]})", keys)
    missing = [key for key in deployed if key not in env]
    print_keys("deployed but missing from the source (the deploy would fail)", missing)
    _, problems = encode_all(env, groups["secret"])
    for problem in problems:
        print(f"error: {problem}")
    return 1 if problems or missing else 0


_SHELL_SENSITIVE = re.compile(r"\$\{|`|#[{$@]")


def cmd_clear(args):
    env = read_source(args.source)
    print("env:\n  clear:")
    for key in sorted(k for k in env if k in CLEAR_KEYS):
        value = env[key]
        if _SHELL_SENSITIVE.search(value):
            print(f"    # {key}: has '${{', a backtick or '#{{', '#$' or '#@', which a shell would change")
        print(f"    {key}: {json.dumps(value, ensure_ascii=False)}")
    return 0


def aws(args, region, stdin=None):
    return subprocess.run(
        ["aws", "--region", region, "secretsmanager", *args, "--output", "json"],
        input=stdin,
        capture_output=True,
        text=True,
    )


def fetch_secret(secret_id, region):
    result = aws(["get-secret-value", "--secret-id", secret_id, "--query", "SecretString"], region)
    if result.returncode != 0:
        raise SecretError(f"could not read {secret_id}: {result.stderr.strip()}")
    return json.loads(json.loads(result.stdout))


def secret_exists(secret_id, region):
    result = aws(["describe-secret", "--secret-id", secret_id, "--query", "ARN"], region)
    if result.returncode == 0:
        return True
    if "ResourceNotFoundException" in result.stderr:
        return False
    raise SecretError(f"could not look up {secret_id}: {result.stderr.strip()}")


def keys_to_push(env, deployed, merge):
    """The deployed secret keys to store from env. Without --merge, every deployed key must be there."""
    missing = [key for key in deployed if key not in env]
    if missing and not merge:
        raise SecretError("deployed but missing from the source: " + ", ".join(missing))
    keys = [key for key in deployed if key in env]
    if not keys:
        raise SecretError("the source has no deployed secret keys")
    return keys


def encode_or_refuse(env, keys):
    stored, problems = encode_all(env, keys)
    if problems:
        raise SecretError("not stored, fix these first:\n" + "\n".join(f"  {p}" for p in problems))
    return stored


def write_command(args, exists):
    if exists:
        return ["put-secret-value", "--secret-id", args.secret_id]
    command = ["create-secret", "--name", args.secret_id, "--description", "connect-id app env (see deploy/)"]
    if args.kms_key_id:
        command += ["--kms-key-id", args.kms_key_id]
    return command


def store(args, stored):
    """Write the secret: create it, replace its value, or with --merge update the given keys. Returns its ARN."""
    exists = secret_exists(args.secret_id, args.region)
    if args.merge and not exists:
        raise SecretError(f"{args.secret_id} doesn't exist yet, run push without --merge")
    if args.merge:
        stored = {**fetch_secret(args.secret_id, args.region), **stored}
    payload = json.dumps(stored, ensure_ascii=False)
    command = [*write_command(args, exists), "--secret-string", "file:///dev/stdin", "--query", "ARN"]
    result = aws(command, args.region, stdin=payload)
    if result.returncode != 0:
        raise SecretError(result.stderr.strip())
    return ("updated" if exists else "created"), json.loads(result.stdout)


def cmd_push(args):
    env = read_source(args.source)
    deployed = deployed_secret_keys()
    keys = keys_to_push(env, deployed, args.merge)
    stored = encode_or_refuse(env, keys)
    action = "merge into" if args.merge else "replace"
    print(f"{'would ' if args.dry_run else ''}{action} {args.secret_id}: " + ", ".join(keys))
    ignored = sorted(key for key in env if key not in deployed)
    if ignored:
        print("not stored (not deployed as secrets): " + ", ".join(ignored))
    if not args.dry_run:
        outcome, arn = store(args, stored)
        print(f"{outcome} {arn}")
    return 0


def stored_problems(stored, deployed, secret_id):
    """Why the stored secret can't be deployed: deployed keys missing from it, or values Kamal would change."""
    problems = [f"{key}: missing from {secret_id}" for key in deployed if key not in stored]
    for key in (key for key in deployed if key in stored):
        problems += deploy_problems(key, stored[key])
    return problems


def cmd_check(args):
    stored = fetch_secret(args.secret_id, args.region)
    deployed = deployed_secret_keys()
    extra = sorted(set(stored) - set(deployed))
    if extra:
        print(f"note: in {args.secret_id} but not deployed: " + ", ".join(extra))
    problems = stored_problems(stored, deployed, args.secret_id)
    if problems:
        print(f"{args.secret_id} is not safe to deploy:\n" + "".join(f"  {p}\n" for p in problems), end="")
        print("Fix the values with deploy/bin/production_secret.py push --merge (see README, Production Deploy).")
        return 1
    print(f"{args.secret_id}: {len(deployed)} deployed keys OK")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--secret-id", default=DEFAULT_SECRET_ID)
    parser.add_argument("--region", default=DEFAULT_REGION)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="list key names by where they go; check every secret can be deployed")
    plan.add_argument("source", help="env file, or - for stdin")
    plan.set_defaults(run=cmd_plan)

    push = commands.add_parser("push", help="store the deployed secret keys from an env file")
    push.add_argument("source", help="env file, or - for stdin")
    push.add_argument("--dry-run", action="store_true", help="print key names only, change nothing")
    push.add_argument("--merge", action="store_true", help="only add or change the keys in the source")
    push.add_argument("--kms-key-id", help="customer-managed KMS key, when creating the secret")
    push.set_defaults(run=cmd_push)

    clear = commands.add_parser("clear", help="print env.clear for deploy.yml from an env file (prints values)")
    clear.add_argument("source", help="env file, or - for stdin")
    clear.set_defaults(run=cmd_clear)

    check = commands.add_parser("check", help="fail if a value in the secret would not deploy as intended")
    check.set_defaults(run=cmd_check)

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except SecretError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
