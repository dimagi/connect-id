#!/usr/bin/env python3
"""Checks, against the real Kamal gem, that values stored by bin/production_secret.py reach the container unchanged.

Run from deploy/ with Ruby and the bundle installed (CI's kamal-secrets job does this):

    python3 tests/kamal_roundtrip.py

It loads the committed config/deploy.yml and .kamal/secrets with Kamal itself, with a stand-in `aws` command that
serves made-up values, and compares what Kamal would write to each role's env file (read the way Docker reads
--env-file) with the values the containers should get. Then it checks bin/production_secret.py's model of Kamal
(container_value) against Kamal on random strings, so a Kamal or dotenv upgrade that changes the escaping fails
here rather than in production.
"""

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEPLOY_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DEPLOY_DIR / "bin"))
import production_secret as ps  # noqa: E402

# Values as they would appear in docker.env, i.e. what the container must end up with
VECTORS = [
    "plain-value_123",
    "pa$$word$HOME${HOME}$(echo no)$",
    "-----BEGIN TEST KEY-----\\nAAAA\\nBBBB\\n-----END TEST KEY-----\\n",
    "-----BEGIN TEST KEY-----\\nAAAA\\n-----END TEST KEY-----",
    '{"type": "service_account", "private_key": "-----BEGIN TEST KEY-----\\nAAAA\\n-----END TEST KEY-----\\n"}',
    "postgres://user:p@ss#w0rd!@db.example.com:5432/connect",
    "quotes ' and \" and #{interp} #$x #@y",
    " leading and trailing spaces ",
    "unicode café ünïcödé",
    "a,b,c",
    "",
    "tab\\tand\\\\backslash",
]

FAKE_AWS = """#!/usr/bin/env python3
import json, os, sys
if "--version" in sys.argv:
    print("aws-cli/2 (stand-in)")
elif "ecr" in sys.argv:
    print("registry-token")
elif "batch-get-secret-value" in sys.argv:
    secret = open(os.environ["FAKE_SECRET_FILE"]).read()
    print(json.dumps({"SecretValues": [{"Name": "connect-id/production", "SecretString": secret}], "Errors": []}))
else:
    sys.exit("unexpected aws call: " + " ".join(sys.argv[1:]))
"""

RUBY = r"""
require "kamal"
require "json"
config = Kamal::Configuration.create_from(config_file: Pathname.new("config/deploy.yml"))
out = {}
config.roles.each do |role|
  host = role.hosts.first
  out[role.name] = { "env_file" => role.secrets_io(host).string, "clear_args" => role.env(host).clear_args }
end
puts JSON.dump(out)
"""


def docker_env_file(text):
    env, problems = ps.parse_env_file(text)
    assert not problems, problems
    return env


def run_kamal(workdir, env):
    result = subprocess.run(
        ["bundle", "exec", "ruby", "-e", RUBY],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        sys.exit(f"kamal failed:\n{result.stderr}")
    return json.loads(result.stdout)


def main():
    keys = ps.deployed_secret_keys()
    want = {key: VECTORS[i % len(VECTORS)] for i, key in enumerate(keys)}
    stored = {key: ps.encode(value) for key, value in want.items()}

    # Clear values with the characters that need care on Kamal's command line
    clear = {"PLAIN": "x", "LIST": "a.example.com,b.example.com", "QUOTES": 'it\'s "q"', "DOLLAR": "a$b$1"}

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        shutil.copytree(DEPLOY_DIR / ".kamal", tmp / ".kamal", ignore=shutil.ignore_patterns("hooks"))
        (tmp / "config").mkdir()
        config = (DEPLOY_DIR / "config" / "deploy.yml").read_text()
        # The committed env.clear (possibly still empty) is swapped for the test values
        before, _, after = config.partition("env:\n  clear:\n")
        _, _, after = after.partition("  secret:\n")
        clear_yaml = "".join(f"    {k}: {json.dumps(v)}\n" for k, v in clear.items())
        (tmp / "config" / "deploy.yml").write_text(f"{before}env:\n  clear:\n{clear_yaml}  secret:\n{after}")
        (tmp / "bin").mkdir()
        (tmp / "bin" / "aws").write_text(FAKE_AWS)
        (tmp / "bin" / "aws").chmod(0o755)
        (tmp / "secret.json").write_text(json.dumps(stored))
        env = {
            **os.environ,
            "PATH": f"{tmp / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "FAKE_SECRET_FILE": str(tmp / "secret.json"),
            "BUNDLE_GEMFILE": str(DEPLOY_DIR / "Gemfile"),
        }
        roles = run_kamal(tmp, env)

        failures = []
        for role, out in roles.items():
            got = docker_env_file(out["env_file"])
            for key, value in want.items():
                if got.get(key) != value:
                    failures.append(f"{role}: {key} differs ({value!r} -> {got.get(key)!r})")
            extra = set(got) - set(want)
            if extra:
                failures.append(f"{role}: unexpected keys {sorted(extra)}")
            # Clear values go on the `docker run` command line, run by a POSIX shell on the host
            args = out["clear_args"]
            pairs = [args[i + 1] for i in range(0, len(args), 2)]
            script = "for a in " + " ".join(pairs) + '; do printf "%s\\0" "$a"; done'
            shell = subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=True).stdout
            got_clear = dict(p.split("=", 1) for p in shell.split("\0") if p)
            for key, value in clear.items():
                if got_clear.get(key) != value:
                    failures.append(f"{role}: clear {key} differs ({value!r} -> {got_clear.get(key)!r})")

        # The Python model of Kamal against Kamal itself, on random values
        rng = random.Random(20261126)
        alphabet = "ab$\\{}()#@\"' \n\r\tx-=,é\x01\x7fn"
        samples = ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 12))) for _ in range(400)]
        (tmp / "secret.json").write_text(json.dumps({key: samples[0] for key in keys}))
        secrets_file = (tmp / ".kamal" / "secrets").read_text()
        for start in range(0, len(samples), len(keys)):
            batch = dict(zip(keys, samples[start : start + len(keys)]))
            batch = {**{key: "" for key in keys}, **batch}
            (tmp / "secret.json").write_text(json.dumps(batch))
            (tmp / ".kamal" / "secrets").write_text(secrets_file)
            out = run_kamal(tmp, env)["web"]["env_file"]
            got = docker_env_file(out)
            for key, sample in batch.items():
                expected = ps.kamal_env_file_value(ps.ruby_chomp(ps.dotenv_substitute(sample, os.environ)))
                if got.get(key) != expected:
                    failures.append(f"model: {sample!r} -> kamal {got.get(key)!r}, model {expected!r}")

    if failures:
        print("\n".join(failures[:40]))
        print(f"FAILED: {len(failures)} differences")
        return 1
    print(f"OK: {len(want)} secrets in {len(roles)} roles, {len(clear)} clear values, {len(samples)} model samples")
    return 0


if __name__ == "__main__":
    sys.exit(main())
