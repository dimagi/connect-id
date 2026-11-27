#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pyyaml"]
# ///
"""Manage the app's secrets: the connect-id/production JSON secret in AWS Secrets Manager.

    uv run deploy/bin/production_secret.py list            # every secret, its type, and whether it is set
    uv run deploy/bin/production_secret.py set NAME        # prompts for the value (or reads it from stdin)
    uv run deploy/bin/production_secret.py check           # what would stop a deploy; the pre-deploy hook runs it
    uv run deploy/bin/production_secret.py import FILE     # copies values from an env file, after a yes/no on the diff

The secrets are listed in deploy/config/secrets.yml, each with its type. Kamal fetches the secret at deploy time
(deploy/.kamal/secrets) and gives each key to the containers as an env var (env.secret in deploy/config/deploy.yml).
Values are never printed or written to disk: the JSON goes to the AWS CLI on its stdin. Needs uv and the AWS CLI.

Why values are stored encoded: between Secrets Manager and the container, Kamal 2.12 changes values twice.
  1. It reads deploy/.kamal/secrets with dotenv, which expands `$NAME` and `${NAME}` in each secret's value (from the
     deploying machine's environment, else to nothing) and turns `\\$` into `$`.
  2. It writes the secrets into an env file for `docker run --env-file`, escaped with Ruby's String#dump (a newline
     becomes the two characters `\\n`, a backslash is doubled, ...). Docker doesn't unescape them. It also drops one
     trailing newline.
So the script stores the value that comes out of those two steps as what the container should get: every `$` (except
in `$(`) is written `\\$`, and escapes like `\\n` are stored as the character they stand for. It checks each value by
running Kamal's steps forward, and refuses one Kamal can't deliver. Hand edits in the AWS console skip this, which is
what `check` (and so the pre-deploy hook) catches.
"""

import argparse
import getpass
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

DEFAULT_SECRET_ID = "connect-id/production"
DEFAULT_REGION = "us-east-1"
DEPLOY_DIR = Path(__file__).resolve().parent.parent
SECRETS_FILE = DEPLOY_DIR / "config" / "secrets.yml"
KAMAL_SECRETS_FILE = DEPLOY_DIR / ".kamal" / "secrets"

# How settings.py reads each type, and so what `set` expects:
#   plain      one line, as is
#   multiline  env.str(..., multiline=True): `set` takes the text with real newlines, e.g. a PEM key
#   json       json.loads: `set` takes any JSON and stores it on one line
TYPES = ("plain", "multiline", "json")


class SecretError(Exception):
    pass


def _unknown_types(secrets):
    return [f"{name} ({kind})" for name, kind in secrets.items() if kind not in TYPES]


def load_secrets(path=None):
    """{name: type} from deploy/config/secrets.yml, in file order. A secret with no type is plain."""
    path = path or SECRETS_FILE
    entries = yaml.safe_load(Path(path).read_text())
    if not isinstance(entries, dict):
        raise SecretError(f"{path}: expected NAME: type entries")
    secrets = {name: kind or "plain" for name, kind in entries.items()}
    if _unknown_types(secrets):
        unknown = ", ".join(_unknown_types(secrets))
        raise SecretError(f"{path}: unknown type for {unknown}; use one of {', '.join(TYPES)}")
    return secrets


# ---------------------------------------------------------------------------------------------------------------------
# Env files, as Docker reads them (docker/cli opts/parse.go)


def _env_file_line(number, line):
    """(key, value, problem) for one line of a Docker --env-file. key is None when the line sets nothing."""
    line = line.removesuffix("\r").lstrip()
    if not line or line.startswith("#"):
        return None, None, None
    key, sep, value = line.partition("=")
    key = key.lstrip(" \t")
    if not re.fullmatch(r"[^ \t]+", key):  # Docker refuses an empty name or one with spaces
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
    """Ruby's String#chomp: drop one trailing \\r\\n, \\n or \\r."""
    return re.sub(r"(?:\r\n|\n|\r)\Z", "", value, count=1)


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


# ---------------------------------------------------------------------------------------------------------------------
# Types


def container_target(kind, value):
    """What the container should get for a value given to `set`, before Kamal's encoding."""
    if kind == "json":
        try:
            return json.dumps(json.loads(value), ensure_ascii=False)
        except ValueError:
            raise SecretError("not valid JSON") from None
    value = value.replace("\r\n", "\n")
    if kind == "multiline":
        return value.replace("\n", "\\n")
    if "\n" in value:
        raise SecretError("has a newline; if it should, give it type multiline in secrets.yml")
    return value


def _strings(value):
    if isinstance(value, dict):
        value = list(value.values())
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return [value] if isinstance(value, str) else []


def _json_problem(seen):
    if not seen:  # settings.py treats empty JSON as unset
        return None
    try:
        parsed = json.loads(seen)
    except ValueError:
        return "is not valid JSON once deployed (store it with `set`, not by hand)"
    if any("\\" in s for s in _strings(parsed)):
        return "would have literal backslashes inside its JSON strings (store it with `set`, not by hand)"
    return None


def type_problem(kind, seen):
    """Why the value a container gets (`seen`) would not work for its type, or None."""
    if kind == "multiline" and "\\\\" in seen:
        return "has a literal '\\n' (store it with `set`, not by hand)"
    return _json_problem(seen) if kind == "json" else None


def deploy_problems(name, kind, stored):
    """Why a stored value would not reach the container as intended. Messages name the key, never the value."""
    if dotenv_substitute(stored) != re.sub(r"\\\$(?!\()", "$", stored):
        return [f"{name}: has a '$' not written as '\\$', which Kamal would expand"]
    problem = type_problem(kind, container_value(stored))
    return [f"{name}: {problem}"] if problem else []


# ---------------------------------------------------------------------------------------------------------------------
# Secrets Manager


def aws(args, region, stdin=None):
    return subprocess.run(
        ["aws", "--region", region, "secretsmanager", *args, "--output", "json"],
        input=stdin,
        capture_output=True,
        text=True,
    )


def _get_secret(args, query):
    return aws(["get-secret-value", "--secret-id", args.secret_id, "--query", query], args.region)


def fetch_secret(args):
    """(its JSON as a dict, its version). The version is None, and the dict empty, if the secret doesn't exist yet."""
    result = _get_secret(args, "{values: SecretString, version: VersionId}")
    if result.returncode == 0:
        secret = json.loads(result.stdout)
        return json.loads(secret["values"]), secret["version"]
    if "ResourceNotFoundException" in result.stderr:
        return {}, None
    raise SecretError(f"could not read {args.secret_id}: {result.stderr.strip()}")


def write_secret(args, stored, version):
    """Store the whole JSON as the secret's new value, if it is still at `version` (None: create it). Returns its ARN.

    Secrets Manager stores the JSON whole, so a write based on an older read would undo whatever was written since.
    """
    if version and json.loads(_get_secret(args, "VersionId").stdout or "null") != version:
        raise SecretError(f"{args.secret_id} changed since it was read, nothing written: run the command again")
    if version:
        command = ["put-secret-value", "--secret-id", args.secret_id]
    else:
        command = ["create-secret", "--name", args.secret_id, "--description", "connect-id app env (see deploy/)"]
        command += ["--kms-key-id", args.kms_key_id] if args.kms_key_id else []
    command += ["--secret-string", "file:///dev/stdin", "--query", "ARN"]
    result = aws(command, args.region, stdin=json.dumps(stored, ensure_ascii=False))
    if result.returncode != 0:
        raise SecretError(result.stderr.strip())
    return json.loads(result.stdout)


# ---------------------------------------------------------------------------------------------------------------------
# Commands


def cmd_list(args):
    secrets = load_secrets()
    stored, _ = fetch_secret(args)
    width = max(map(len, secrets))
    for name, kind in secrets.items():
        print(f"{name:<{width}}  {kind:<9}  {'set' if name in stored else 'MISSING'}")
    for name in sorted(set(stored) - set(secrets)):
        print(f"{name:<{width}}  {'':<9}  in the secret but not in secrets.yml, so not deployed")
    return 0


def read_value(name, kind):
    if not sys.stdin.isatty():
        return sys.stdin.read().removesuffix("\n")
    if kind != "plain":
        print(f"{name} is {kind}: pipe it in, e.g. production_secret.py set {name} < file", file=sys.stderr)
    return getpass.getpass(f"{name}: ")


def cmd_set(args):
    secrets = load_secrets()
    if args.name not in secrets:
        raise SecretError(f"{args.name} is not in {SECRETS_FILE.name}: add it there (and to .kamal/secrets) first")
    kind = secrets[args.name]
    value = read_value(args.name, kind)
    if not value:
        raise SecretError("empty value, nothing stored")
    try:
        encoded = encode(container_target(kind, value))
    except SecretError as e:
        raise SecretError(f"{args.name}: {e}") from None
    current, version = fetch_secret(args)
    arn = write_secret(args, {**current, args.name: encoded}, version)
    print(f"set {args.name} in {arn}")
    return 0


def encode_for_import(env, secrets):
    """{name: stored value} for the secrets in env. Raises SecretError naming every key that can't be stored."""
    stored, problems = {}, []
    for name in (name for name in secrets if name in env):
        try:
            stored[name] = encode(env[name])
            problems += deploy_problems(name, secrets[name], stored[name])
        except SecretError as e:
            problems.append(f"{name}: {e}")
    if problems:
        raise SecretError("nothing imported, fix these first:\n" + "\n".join(f"  {p}" for p in problems))
    return stored


def diff_group(name, value, current):
    if name not in current:
        return "add"
    return "unchanged" if current[name] == value else "change"


def import_plan(env, secrets, current):
    """(values to store, {group: [names]}) for importing an env file. Raises SecretError naming bad keys."""
    stored = encode_for_import(env, secrets)
    groups = {"add": [], "change": [], "unchanged": []}
    for name, value in stored.items():
        groups[diff_group(name, value, current)].append(name)
    groups["not in the file, left as is"] = [name for name in secrets if name not in env]
    groups["in the file but not in secrets.yml, ignored"] = sorted(set(env) - set(secrets))
    return {name: stored[name] for name in groups["add"] + groups["change"]}, groups


def print_groups(groups):
    for group, names in groups.items():
        if names:
            print(f"{group}: " + ", ".join(names))


def confirmed(args, count):
    return args.yes or input(f"Write {count} keys to {args.secret_id}? [y/N] ").strip().lower() == "y"


def cmd_import(args):
    env, problems = parse_env_file(Path(args.file).read_text())
    for problem in problems:
        print(f"warning: {problem}", file=sys.stderr)
    current, version = fetch_secret(args)
    updates, groups = import_plan(env, load_secrets(), current)
    print_groups(groups)
    if not updates:
        print("nothing to change")
        return 0
    if not confirmed(args, len(updates)):
        print("nothing changed")
        return 1
    arn = write_secret(args, {**current, **updates}, version)
    print(f"wrote {len(updates)} keys to {arn}")
    return 0


def kamal_secrets_problems(secrets):
    """A problem if .kamal/secrets doesn't extract exactly the secrets in secrets.yml."""
    extracted = deployed_secret_keys()
    missing, extra = sorted(set(secrets) - set(extracted)), sorted(set(extracted) - set(secrets))
    if missing or extra:
        return [f".kamal/secrets doesn't match secrets.yml: missing {missing or '-'}, extra {extra or '-'}"]
    return []


def check_problems(secrets, stored, args):
    """Why a deploy would fail or deliver wrong values. Messages name keys, never values."""
    problems = kamal_secrets_problems(secrets)
    problems += [f"{name}: missing from {args.secret_id}" for name in secrets if name not in stored]
    for name in (name for name in secrets if name in stored):
        problems += deploy_problems(name, secrets[name], stored[name])
    return problems


def cmd_check(args):
    secrets = load_secrets()
    stored, version = fetch_secret(args)
    extra = sorted(set(stored) - set(secrets))
    if extra:
        print(f"note: in {args.secret_id} but not in secrets.yml, so not deployed: " + ", ".join(extra))
    problems = check_problems(secrets, stored, args) if version else [f"{args.secret_id} doesn't exist"]
    if problems:
        print(f"{args.secret_id} is not ready to deploy:\n" + "".join(f"  {p}\n" for p in problems), end="")
        print("See README, Production Deploy, for fixing a value with `set`.")
        return 1
    print(f"{args.secret_id}: {len(secrets)} secrets OK")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--secret-id", default=DEFAULT_SECRET_ID)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--kms-key-id", help="customer-managed KMS key, used only when creating the secret")
    commands = parser.add_subparsers(dest="command", required=True)

    list_ = commands.add_parser("list", help="list the secrets, their types and whether each is set")
    list_.set_defaults(run=cmd_list)

    set_ = commands.add_parser("set", help="set one secret; prompts for it, or reads it from stdin")
    set_.add_argument("name")
    set_.set_defaults(run=cmd_set)

    check = commands.add_parser("check", help="list what would stop a deploy or deliver a wrong value")
    check.set_defaults(run=cmd_check)

    import_ = commands.add_parser("import", help="copy the secrets from an env file (Docker --env-file format)")
    import_.add_argument("file", help="e.g. <(ssh host cat docker.env)")
    import_.add_argument("--yes", action="store_true", help="don't ask before writing")
    import_.set_defaults(run=cmd_import)

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except SecretError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
