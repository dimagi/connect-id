"""Tests for deploy/bin/production_secret.py and the deploy config it ties together.

The model of Kamal's escaping in production_secret.py is checked against the real gem by kamal_roundtrip.py
(CI's kamal-secrets job); these tests need no Ruby.
"""

import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from deploy.bin import production_secret as ps

DEPLOY_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = DEPLOY_DIR.parent


PEM = "-----BEGIN TEST KEY-----\nAAAA\nBBBB\n-----END TEST KEY-----\n"
PEM_ESCAPED = PEM.replace("\n", "\\n")  # as in an env file
CREDENTIALS = {"type": "service_account", "private_key": PEM, "client_email": "a@b.c"}

# Env vars the app reads that production leaves at their settings.py default, or that only seed a django-constance
# setting (docs/runtime-config.md). Everything else the app reads must be in env.clear or config/secrets.yml.
NOT_DEPLOYED = {
    "AWS_DEFAULT_REGION",
    "AWS_S3_MESSAGE_ATTACHMENTS_BUCKET_NAME",
    "AWS_S3_PHOTO_BUCKET_NAME",
    "AXES_ENABLED",
    "CELERY_TASK_ALWAYS_EAGER",
    "CELERY_TASK_EAGER_PROPAGATES",
    "CONNECT_DISABLED",
    "DEBUG",
    "DEFAULT_FILE_STORAGE_BACKEND",
    "EMAIL_OTP_VALIDITY_SECONDS",
    "FCM_HTTP_TIMEOUT_SECONDS",
    "NUM_PROXIES",
    "PLAYSTORE_INTEGRITY_DISABLED",
    "RATE_LIMIT_REDIS_URL",
    "REFRESH_TOKEN_EXPIRE_SECONDS",
    "REQUEST_LOG_LEVEL",
    "SENTRY_ENVIRONMENT",
    "SENTRY_TRACES_SAMPLE_RATE",
    "SMS_DEFAULT_VENDOR",
    "WEB_CONCURRENCY",
    # django-constance seeds
    "BLACKLISTED_COUNTRY_CODES",
    "OTP_USER_DAILY_LIMIT",
    "OTP_USER_HOURLY_LIMIT",
    "PHONE_COUNTRY_DAILY_LIMIT",
    "PHONE_COUNTRY_HOURLY_LIMIT",
    "RATE_LIMIT_WARN_FRACTION",
    "SMS_NUMBER_DAILY_LIMIT",
    "SMS_NUMBER_HOURLY_LIMIT",
    "SMS_SUPPORTED_COUNTRY_CODES",
}


def deploy_config():
    return yaml.safe_load((DEPLOY_DIR / "config" / "deploy.yml").read_text())


# --- the env file parser follows Docker ------------------------------------------------------------------------------


def test_parse_env_file_takes_values_as_is():
    env, problems = ps.parse_env_file(
        "\ufeffA=1\n# comment\n\n  B = x \nC='quoted'\nD=\"q\"\nE=a=b\r\nF=\nNOVALUE\nA=2\nbad key=1\n"
    )
    assert env == {"A": "2", "C": "'quoted'", "D": '"q"', "E": "a=b", "F": ""}
    assert problems == [
        "line 4: not KEY=value (skipped)",
        "NOVALUE: no '=', Docker copies it from the host's environment (skipped)",
        "A: set more than once, the last value is used",
        "line 11: not KEY=value (skipped)",
    ]


# --- encoding --------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "plain",
        "",
        "pa$$word$HOME${HOME}$(echo no)$",
        PEM_ESCAPED,
        PEM_ESCAPED.removesuffix("\\n"),
        json.dumps(CREDENTIALS),
        "quotes ' \" #{x} #$y #@z",
        " spaces ",
        "unicode café",
        "tab\\tand\\\\backslash",
    ],
)
def test_encoded_values_reach_the_container_unchanged(value):
    assert ps.container_value(ps.encode(value)) == value


def test_encode_escapes_dollar_signs():
    assert ps.encode("a$b${C}$") == "a\\$b\\${C}\\$"
    assert ps.encode("$(x)") == "$(x)"


@pytest.mark.parametrize("value", ["lone\\qbackslash", 'escaped\\"quote', "a\\$b", "ends\\"])
def test_values_kamal_cannot_deliver_are_refused(value):
    with pytest.raises(ps.SecretError):
        ps.encode(value)


def test_dotenv_substitution_model():
    env = {"HOME": "/root"}
    assert ps.dotenv_substitute("a$HOME b${HOME} $nope \\$HOME $( $ ${}", env) == "a/root b/root  $HOME $( $ ${}"


# --- types -----------------------------------------------------------------------------------------------------------


def test_multiline_values_are_stored_with_real_newlines():
    for given in (PEM, PEM_ESCAPED):  # pasted from a file, or already escaped
        stored = ps.encode(ps.container_target("multiline", given))
        assert "\\" not in stored
        assert ps.container_value(stored) == PEM_ESCAPED  # what settings.py's multiline=True expects
        assert ps.deploy_problems("K", "multiline", stored) == []


def test_json_values_are_stored_on_one_line():
    pretty = json.dumps(CREDENTIALS, indent=2)
    stored = ps.encode(ps.container_target("json", pretty))
    assert json.loads(ps.container_value(stored)) == CREDENTIALS
    assert ps.deploy_problems("K", "json", stored) == []
    with pytest.raises(ps.SecretError, match="not valid JSON"):
        ps.container_target("json", "{nope")


def test_plain_values_have_no_newline():
    assert ps.container_target("plain", "token") == "token"
    with pytest.raises(ps.SecretError, match="multiline"):
        ps.container_target("plain", "two\nlines")


@pytest.mark.parametrize(
    "kind,stored,problem",
    [
        ("plain", "abc$def", "'$' not written as '\\$'"),
        ("plain", "abc${DEF}", "'$' not written as '\\$'"),
        ("multiline", PEM_ESCAPED, "literal '\\n'"),  # pasted into the console as in an env file
        ("json", json.dumps(CREDENTIALS), "literal backslashes"),  # the JSON file pasted as is
        ("json", "not json", "not valid JSON"),
    ],
)
def test_deploy_problems_catch_hand_edited_values(kind, stored, problem):
    (message,) = ps.deploy_problems("KEY", kind, stored)
    assert message.startswith("KEY: ")
    assert problem in message


def test_deploy_problems_accept_harmless_values():
    assert ps.deploy_problems("K", "plain", "a$ $% $(x) \\$b") == []
    assert ps.deploy_problems("K", "json", "") == []  # settings.py treats empty as unset


# --- the deploy config agrees with itself ----------------------------------------------------------------------------


def test_secrets_yml_is_valid():
    secrets = ps.load_secrets()
    assert secrets, "no secrets in config/secrets.yml"
    assert set(secrets.values()) <= set(ps.TYPES)


def test_load_secrets_rejects_unknown_types(tmp_path):
    path = tmp_path / "secrets.yml"
    path.write_text("A:\nB: multiline\nC: pem\n")
    with pytest.raises(ps.SecretError, match="C \\(pem\\)"):
        ps.load_secrets(path)
    path.write_text("A:\nB: multiline\n")
    assert ps.load_secrets(path) == {"A": "plain", "B": "multiline"}


def test_kamal_secrets_extracts_every_secret():
    assert ps.deployed_secret_keys() == list(ps.load_secrets()), (
        "deploy/.kamal/secrets needs one `NAME=$(kamal secrets extract NAME ${SECRETS})` line per entry in "
        "config/secrets.yml, in the same order"
    )


def test_kamal_secrets_fetches_the_secret_once_with_the_built_in_adapter():
    lines = (DEPLOY_DIR / ".kamal" / "secrets").read_text().splitlines()
    fetches = [line for line in lines if "kamal secrets fetch" in line]
    assert fetches == ["SECRETS=$(kamal secrets fetch --adapter aws_secrets_manager connect-id/production)"]
    assert ps.DEFAULT_SECRET_ID == "connect-id/production"


def test_env_secret_is_read_from_secrets_yml():
    # Rendered by Kamal's ERB; kamal_roundtrip.py checks the result with Kamal itself
    assert deploy_config()["env"]["secret"] == '<%= YAML.load_file("config/secrets.yml").keys.inspect %>'


def test_env_clear_is_plain_config_only():
    clear = deploy_config()["env"]["clear"]
    assert isinstance(clear, dict)
    assert not set(clear) & set(ps.load_secrets()), "a key can't be both clear and secret"
    for key, value in clear.items():
        assert isinstance(value, str), f"{key}: quote it, Kamal would pass {value!r} as YAML read it"
        assert "${" not in value and "`" not in value, f"{key}: the host's shell would expand this"


def test_roles_get_no_env_file():
    for name, role in deploy_config()["servers"].items():
        assert "env-file" not in role.get("options", {}), name


def test_every_env_var_the_app_reads_is_deployed_or_left_out_on_purpose():
    settings = (REPO_DIR / "connectid" / "settings.py").read_text()
    read = set(re.findall(r"\benv(?:\.\w+)?\(\s*\"([A-Z][A-Z0-9_]*)\"", settings))
    for script in (REPO_DIR / "docker").iterdir():
        read |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", script.read_text()))
    assert "SECRET_KEY" in read and "WEB_CONCURRENCY" in read  # the patterns still find things
    deployed = set(deploy_config()["env"]["clear"]) | set(ps.load_secrets())
    assert read - deployed - NOT_DEPLOYED == set(), (
        "add these to env.clear in deploy/config/deploy.yml or to deploy/config/secrets.yml, "
        "or to NOT_DEPLOYED here if production keeps the default"
    )
    assert NOT_DEPLOYED & deployed == set()


def test_multiline_secrets_are_read_as_multiline():
    settings = (REPO_DIR / "connectid" / "settings.py").read_text()
    for name, kind in ps.load_secrets().items():
        if kind == "multiline":
            assert f'env.str("{name}", multiline=True' in settings, name


# --- commands --------------------------------------------------------------------------------------------------------


class FakeAws:
    """Stands in for the AWS CLI. `existing` is the stored secret, None if there's none."""

    def __init__(self, existing=None):
        self.existing = existing
        self.writes = []

    def __call__(self, command, input=None, **kwargs):
        action = command[4]
        if action == "get-secret-value":
            if self.existing is None:
                return subprocess.CompletedProcess(command, 254, "", "ResourceNotFoundException: nope")
            return subprocess.CompletedProcess(command, 0, json.dumps(json.dumps(self.existing)), "")
        if action in ("create-secret", "put-secret-value"):
            self.writes.append((action, json.loads(input)))
            self.existing = json.loads(input)
            return subprocess.CompletedProcess(command, 0, '"arn:aws:secretsmanager:x:1:secret:connect-id/p-AbC"', "")
        raise AssertionError(command)


@pytest.fixture
def deploy_files(tmp_path, monkeypatch):
    """A secrets.yml and matching .kamal/secrets with SECRET_KEY (plain) and OIDC_RSA_PRIVATE_KEY (multiline)."""
    secrets_yml = tmp_path / "secrets.yml"
    secrets_yml.write_text("SECRET_KEY:\nOIDC_RSA_PRIVATE_KEY: multiline\n")
    kamal_secrets = tmp_path / "kamal-secrets"
    kamal_secrets.write_text(
        "SECRETS=$(kamal secrets fetch --adapter aws_secrets_manager connect-id/production)\n"
        "SECRET_KEY=$(kamal secrets extract SECRET_KEY ${SECRETS})\n"
        "OIDC_RSA_PRIVATE_KEY=$(kamal secrets extract OIDC_RSA_PRIVATE_KEY ${SECRETS})\n"
    )
    monkeypatch.setattr(ps, "SECRETS_FILE", secrets_yml)
    monkeypatch.setattr(ps, "KAMAL_SECRETS_FILE", kamal_secrets)


@pytest.fixture
def aws(deploy_files, monkeypatch):
    fake = FakeAws()
    monkeypatch.setattr(ps.subprocess, "run", fake)
    return fake


@pytest.fixture
def stdin(monkeypatch):
    """Feeds a value to `set` as if piped in."""

    class Piped:
        def __init__(self):
            self.text = ""

        def isatty(self):
            return False

        def read(self):
            return self.text

    piped = Piped()
    monkeypatch.setattr(ps.sys, "stdin", piped)
    return piped


def test_list_shows_types_and_what_is_set(aws, capsys):
    aws.existing = {"SECRET_KEY": "x", "OLD": "y"}
    assert ps.main(["list"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split() == ["SECRET_KEY", "plain", "set"]
    assert out[1].split() == ["OIDC_RSA_PRIVATE_KEY", "multiline", "MISSING"]
    assert out[2].startswith("OLD") and "not in secrets.yml" in out[2]
    assert "x" not in "".join(line.split()[-1] for line in out)


def test_set_creates_then_updates_without_printing_the_value(aws, stdin, capsys):
    stdin.text = "sup3r$ecret\n"
    assert ps.main(["set", "SECRET_KEY"]) == 0
    stdin.text = PEM
    assert ps.main(["set", "OIDC_RSA_PRIVATE_KEY"]) == 0
    assert [action for action, _ in aws.writes] == ["create-secret", "put-secret-value"]
    stored = aws.writes[-1][1]
    assert ps.container_value(stored["SECRET_KEY"]) == "sup3r$ecret"
    # One trailing newline is dropped from what's piped in (as from `echo`), harmless for a key
    assert ps.container_value(stored["OIDC_RSA_PRIVATE_KEY"]) == PEM_ESCAPED.removesuffix("\\n")
    out = capsys.readouterr()
    assert "sup3r" not in out.out + out.err and "AAAA" not in out.out + out.err


def test_set_prompts_without_echo_on_a_terminal(aws, monkeypatch):
    monkeypatch.setattr(ps.sys.stdin, "isatty", lambda: True, raising=False)
    monkeypatch.setattr(ps.getpass, "getpass", lambda prompt: "typed")
    assert ps.main(["set", "SECRET_KEY"]) == 0
    assert aws.writes[-1][1] == {"SECRET_KEY": "typed"}


def test_set_refuses_unknown_names_and_bad_values(aws, stdin, capsys):
    stdin.text = "x"
    assert ps.main(["set", "NOT_LISTED"]) == 1
    assert "not in secrets.yml" in capsys.readouterr().err
    stdin.text = "back\\slash"
    assert ps.main(["set", "SECRET_KEY"]) == 1
    err = capsys.readouterr().err
    assert "SECRET_KEY: Kamal can't deliver" in err and "slash" not in err
    stdin.text = ""
    assert ps.main(["set", "SECRET_KEY"]) == 1
    assert aws.writes == []


def test_import_shows_the_diff_and_asks_first(aws, tmp_path, monkeypatch, capsys):
    aws.existing = {"SECRET_KEY": ps.encode("old"), "OTHER": "kept"}
    env_file = tmp_path / "docker.env"
    env_file.write_text(f"SECRET_KEY=n$w\nOIDC_RSA_PRIVATE_KEY={PEM_ESCAPED}\nDEBUG=False\n")

    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert ps.main(["import", str(env_file)]) == 1
    out = capsys.readouterr().out
    assert "add: OIDC_RSA_PRIVATE_KEY\n" in out and "change: SECRET_KEY\n" in out
    assert "in the file but not in secrets.yml, ignored: DEBUG\n" in out
    assert "n$w" not in out and aws.writes == []

    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert ps.main(["import", str(env_file)]) == 0
    stored = aws.writes[-1][1]
    assert stored["OTHER"] == "kept"
    assert ps.container_value(stored["SECRET_KEY"]) == "n$w"
    assert ps.container_value(stored["OIDC_RSA_PRIVATE_KEY"]) == PEM_ESCAPED

    assert ps.main(["import", str(env_file)]) == 0
    assert "nothing to change" in capsys.readouterr().out


def test_import_refuses_values_kamal_cannot_deliver(aws, tmp_path, capsys):
    env_file = tmp_path / "docker.env"
    env_file.write_text("SECRET_KEY=back\\slash\n")
    assert ps.main(["import", "--yes", str(env_file)]) == 1
    err = capsys.readouterr().err
    assert "SECRET_KEY: Kamal can't deliver" in err and "slash" not in err
    assert aws.writes == []


def test_check(aws, capsys):
    aws.existing = {"SECRET_KEY": ps.encode("a$b"), "OIDC_RSA_PRIVATE_KEY": ps.encode(PEM_ESCAPED), "EXTRA": "x"}
    assert ps.main(["check"]) == 0
    assert "not deployed: EXTRA" in capsys.readouterr().out

    aws.existing = {"SECRET_KEY": "a$b"}
    assert ps.main(["check"]) == 1
    out = capsys.readouterr().out
    assert "SECRET_KEY: has a '$'" in out
    assert "OIDC_RSA_PRIVATE_KEY: missing" in out

    aws.existing = None
    assert ps.main(["check"]) == 1
    assert "doesn't exist" in capsys.readouterr().out


def test_check_catches_kamal_secrets_out_of_step(aws, capsys):
    ps.SECRETS_FILE.write_text("SECRET_KEY:\nOIDC_RSA_PRIVATE_KEY: multiline\nNEW_ONE:\n")
    aws.existing = {"SECRET_KEY": "a", "OIDC_RSA_PRIVATE_KEY": "b", "NEW_ONE": "c"}
    assert ps.main(["check"]) == 1
    assert ".kamal/secrets doesn't match secrets.yml: missing ['NEW_ONE']" in capsys.readouterr().out
