"""Tests for deploy/bin/production_secret.py and the deploy config it ties together.

The model of Kamal's escaping in production_secret.py is checked against the real gem by kamal_roundtrip.py
(CI's kamal-secrets job); these tests need no Ruby.
"""

import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest
import yaml

DEPLOY_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = DEPLOY_DIR.parent

_spec = importlib.util.spec_from_file_location("production_secret", DEPLOY_DIR / "bin" / "production_secret.py")
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)

PEM = "-----BEGIN TEST KEY-----\\nAAAA\\nBBBB\\n-----END TEST KEY-----\\n"
CREDENTIALS_JSON = '{"type": "service_account", "private_key": "' + PEM + '", "client_email": "a@b.c"}'


def deploy_config():
    return yaml.safe_load((DEPLOY_DIR / "config" / "deploy.yml").read_text())


# --- the env file parser follows Docker ------------------------------------------------------------------------------


def test_parse_env_file_takes_values_as_is():
    env, problems = ps.parse_env_file(
        "﻿A=1\n# comment\n\n  B = x \nC='quoted'\nD=\"q\"\nE=a=b\r\nF=\nNOVALUE\nA=2\nbad key=1\n"
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
        PEM,
        PEM.removesuffix("\\n"),
        CREDENTIALS_JSON,
        "quotes ' \" #{x} #$y #@z",
        " spaces ",
        "unicode café",
        "tab\\tand\\\\backslash",
    ],
)
def test_encoded_values_reach_the_container_unchanged(value):
    stored = ps.encode(value)
    assert ps.container_value(stored) == value
    assert ps.deploy_problems("SOME_KEY", stored) == []


def test_encode_stores_pem_keys_with_real_newlines():
    stored = ps.encode(PEM)
    assert "\\" not in stored
    # one extra newline, because Kamal drops one
    assert stored == "-----BEGIN TEST KEY-----\nAAAA\nBBBB\n-----END TEST KEY-----\n\n"
    assert ps.deploy_problems("OIDC_RSA_PRIVATE_KEY", stored) == []


def test_encode_escapes_dollar_signs():
    assert ps.encode("a$b${C}$") == "a\\$b\\${C}\\$"
    assert ps.encode("$(x)") == "$(x)"


def test_encoded_json_still_parses_in_the_container():
    stored = ps.encode(CREDENTIALS_JSON)
    assert json.loads(ps.container_value(stored)) == json.loads(CREDENTIALS_JSON)
    assert ps.deploy_problems("BIGQUERY_GOOGLE_CREDENTIALS_JSON", stored) == []


@pytest.mark.parametrize("value", ["lone\\qbackslash", 'escaped\\"quote', "a\\$b", "ends\\"])
def test_values_kamal_cannot_deliver_are_refused(value):
    with pytest.raises(ps.SecretError):
        ps.encode(value)


def test_dotenv_substitution_model():
    env = {"HOME": "/root"}
    assert ps.dotenv_substitute("a$HOME b${HOME} $nope \\$HOME $( $ ${}", env) == "a/root b/root  $HOME $( $ ${}"


@pytest.mark.parametrize(
    "key,stored,problem",
    [
        ("SECRET_KEY", "abc$def", "'$' not written as '\\$'"),
        ("SECRET_KEY", "abc${DEF}", "'$' not written as '\\$'"),
        ("OIDC_RSA_PRIVATE_KEY", PEM, "literal '\\n'"),
        ("BIGQUERY_GOOGLE_CREDENTIALS_JSON", CREDENTIALS_JSON, "literal backslashes"),
        ("BIGQUERY_GOOGLE_CREDENTIALS_JSON", "not json", "not valid JSON"),
    ],
)
def test_deploy_problems_catch_hand_edited_values(key, stored, problem):
    (message,) = ps.deploy_problems(key, stored)
    assert message.startswith(f"{key}: ")
    assert problem in message


def test_empty_json_is_fine():
    assert ps.deploy_problems("BIGQUERY_GOOGLE_CREDENTIALS_JSON", ps.encode("")) == []


def test_deploy_problems_accept_harmless_dollars():
    assert ps.deploy_problems("SECRET_KEY", "a$ $% $(x) \\$b") == []


# --- the deploy config agrees with itself ----------------------------------------------------------------------------


def test_kamal_secrets_and_deploy_yml_list_the_same_secrets():
    extracted = ps.deployed_secret_keys()
    assert extracted, "no keys extracted in .kamal/secrets"
    assert len(extracted) == len(set(extracted))
    assert extracted == deploy_config()["env"]["secret"]
    assert set(extracted) <= ps.SECRET_KEYS


def test_kamal_secrets_fetches_the_secret_once_with_the_built_in_adapter():
    lines = (DEPLOY_DIR / ".kamal" / "secrets").read_text().splitlines()
    fetches = [line for line in lines if "kamal secrets fetch" in line]
    assert fetches == ["SECRETS=$(kamal secrets fetch --adapter aws_secrets_manager connect-id/production)"]
    assert ps.DEFAULT_SECRET_ID == "connect-id/production"


def test_env_clear_is_plain_config_only():
    clear = deploy_config()["env"]["clear"]
    assert isinstance(clear, dict), "fill in env.clear in deploy/config/deploy.yml (production_secret.py clear)"
    assert set(clear) <= ps.CLEAR_KEYS
    for key, value in clear.items():
        assert isinstance(value, str), f"{key}: quote it, Kamal would pass {value!r} as YAML read it"
        assert "${" not in value and "`" not in value, f"{key}: the host's shell would expand this"


def test_roles_get_no_env_file():
    for name, role in deploy_config()["servers"].items():
        assert "env-file" not in role.get("options", {}), name


def test_key_groups_do_not_overlap():
    groups = [ps.SECRET_KEYS, ps.CLEAR_KEYS, ps.SEED_KEYS, ps.UNUSED_KEYS]
    assert sum(len(g) for g in groups) == len(set().union(*groups))
    assert ps.MULTILINE_KEYS | ps.JSON_KEYS <= ps.SECRET_KEYS


def test_every_env_var_the_app_reads_is_classified():
    settings = (REPO_DIR / "connectid" / "settings.py").read_text()
    read = set(re.findall(r"\benv(?:\.\w+)?\(\s*\"([A-Z][A-Z0-9_]*)\"", settings))
    for script in (REPO_DIR / "docker").iterdir():
        read |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", script.read_text()))
    assert "SECRET_KEY" in read and "WEB_CONCURRENCY" in read  # the patterns still find things
    known = ps.SECRET_KEYS | ps.CLEAR_KEYS | ps.SEED_KEYS
    assert read - known == set(), "classify these in deploy/bin/production_secret.py"


def test_settings_reads_multiline_keys_as_multiline():
    settings = (REPO_DIR / "connectid" / "settings.py").read_text()
    for key in ps.MULTILINE_KEYS:
        assert f'env.str("{key}", multiline=True' in settings, key


# --- commands --------------------------------------------------------------------------------------------------------


class FakeAws:
    def __init__(self, existing=None):
        self.existing = existing
        self.calls = []

    def __call__(self, command, input=None, **kwargs):
        self.calls.append((command, input))
        action = command[4]
        if action == "describe-secret":
            if self.existing is None:
                return subprocess.CompletedProcess(command, 254, "", "ResourceNotFoundException: nope")
            return subprocess.CompletedProcess(command, 0, '"arn:x"', "")
        if action == "get-secret-value":
            return subprocess.CompletedProcess(command, 0, json.dumps(json.dumps(self.existing)), "")
        if action in ("create-secret", "put-secret-value"):
            return subprocess.CompletedProcess(command, 0, '"arn:aws:secretsmanager:x:1:secret:connect-id/p-AbC"', "")
        raise AssertionError(command)


@pytest.fixture
def secrets_file(tmp_path, monkeypatch):
    path = tmp_path / "secrets"
    path.write_text(
        "KAMAL_REGISTRY_PASSWORD=$(aws ecr get-login-password)\n"
        "SECRETS=$(kamal secrets fetch --adapter aws_secrets_manager connect-id/production)\n"
        "SECRET_KEY=$(kamal secrets extract SECRET_KEY ${SECRETS})\n"
        "OIDC_RSA_PRIVATE_KEY=$(kamal secrets extract OIDC_RSA_PRIVATE_KEY ${SECRETS})\n"
    )
    monkeypatch.setattr(ps, "KAMAL_SECRETS_FILE", path)
    return path


@pytest.fixture
def docker_env(tmp_path):
    path = tmp_path / "docker.env"
    path.write_text(
        f"SECRET_KEY=sup3r$ecret\nOIDC_RSA_PRIVATE_KEY={PEM}\nDEBUG=False\nSMS_NUMBER_DAILY_LIMIT=10\nODD=1\n"
    )
    return path


def test_push_creates_the_secret_without_printing_values(secrets_file, docker_env, monkeypatch, capsys):
    aws = FakeAws()
    monkeypatch.setattr(ps.subprocess, "run", aws)
    assert ps.main(["push", str(docker_env)]) == 0
    command, payload = aws.calls[-1]
    assert command[3:6] == ["secretsmanager", "create-secret", "--name"]
    assert "--secret-string" in command and "file:///dev/stdin" in command
    stored = json.loads(payload)
    assert set(stored) == {"SECRET_KEY", "OIDC_RSA_PRIVATE_KEY"}
    assert ps.container_value(stored["SECRET_KEY"]) == "sup3r$ecret"
    assert ps.container_value(stored["OIDC_RSA_PRIVATE_KEY"]) == PEM
    out = capsys.readouterr()
    assert "sup3r" not in out.out + out.err and "AAAA" not in out.out + out.err
    assert "DEBUG, ODD, SMS_NUMBER_DAILY_LIMIT" in out.out


def test_push_dry_run_calls_nothing(secrets_file, docker_env, monkeypatch, capsys):
    monkeypatch.setattr(ps.subprocess, "run", FakeAws())
    assert ps.main(["push", "--dry-run", str(docker_env)]) == 0
    assert ps.subprocess.run.calls == []
    assert "would replace connect-id/production: SECRET_KEY, OIDC_RSA_PRIVATE_KEY" in capsys.readouterr().out


def test_push_updates_an_existing_secret(secrets_file, docker_env, monkeypatch):
    aws = FakeAws(existing={"OLD": "x"})
    monkeypatch.setattr(ps.subprocess, "run", aws)
    assert ps.main(["push", str(docker_env)]) == 0
    command, payload = aws.calls[-1]
    assert command[4:6] == ["put-secret-value", "--secret-id"]
    assert set(json.loads(payload)) == {"SECRET_KEY", "OIDC_RSA_PRIVATE_KEY"}  # replaced, not merged


def test_push_merge_changes_only_the_given_keys(secrets_file, tmp_path, monkeypatch):
    aws = FakeAws(existing={"SECRET_KEY": "old", "OIDC_RSA_PRIVATE_KEY": "keep"})
    monkeypatch.setattr(ps.subprocess, "run", aws)
    source = tmp_path / "one.env"
    source.write_text("SECRET_KEY=n$w\n")
    assert ps.main(["push", "--merge", str(source)]) == 0
    assert json.loads(aws.calls[-1][1]) == {"SECRET_KEY": "n\\$w", "OIDC_RSA_PRIVATE_KEY": "keep"}


def test_push_refuses_missing_keys_and_undeliverable_values(secrets_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ps.subprocess, "run", FakeAws())
    source = tmp_path / "bad.env"
    source.write_text("SECRET_KEY=back\\slash\n")
    assert ps.main(["push", str(source)]) == 1
    assert "missing from the source: OIDC_RSA_PRIVATE_KEY" in capsys.readouterr().err
    source.write_text(f"SECRET_KEY=back\\slash\nOIDC_RSA_PRIVATE_KEY={PEM}\n")
    assert ps.main(["push", str(source)]) == 1
    err = capsys.readouterr().err
    assert "SECRET_KEY: Kamal can't deliver this value unchanged" in err and "slash" not in err
    assert ps.subprocess.run.calls == []


def test_plan_lists_key_names_by_group(secrets_file, docker_env, capsys):
    assert ps.main(["plan", str(docker_env)]) == 0
    out = capsys.readouterr().out
    assert "secret (" in out and "  SECRET_KEY\n" in out
    assert "clear (" in out and "  DEBUG\n" in out
    assert "seed (" in out and "  SMS_NUMBER_DAILY_LIMIT\n" in out
    assert "unknown (" in out and "  ODD\n" in out
    assert "sup3r" not in out


def test_clear_prints_yaml_for_plain_config_only(docker_env, capsys):
    assert ps.main(["clear", str(docker_env)]) == 0
    out = capsys.readouterr().out
    assert yaml.safe_load(out) == {"env": {"clear": {"DEBUG": "False"}}}


def test_check(secrets_file, monkeypatch, capsys):
    aws = FakeAws(existing={"SECRET_KEY": ps.encode("a$b"), "OIDC_RSA_PRIVATE_KEY": ps.encode(PEM), "EXTRA": "x"})
    monkeypatch.setattr(ps.subprocess, "run", aws)
    assert ps.main(["check"]) == 0
    assert "not deployed: EXTRA" in capsys.readouterr().out

    aws.existing = {"SECRET_KEY": "a$b"}
    assert ps.main(["check"]) == 1
    out = capsys.readouterr().out
    assert "SECRET_KEY: has a '$'" in out
    assert "OIDC_RSA_PRIVATE_KEY: missing" in out
