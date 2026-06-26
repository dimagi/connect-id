import json
from datetime import datetime, timezone
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from users.factories import (
    CredentialFactory,
    IssuingAuthorityFactory,
    ServerKeysFactory,
    UserCredentialFactory,
    UserFactory,
)
from users.models import Credential, IssuingAuthority, UserCredential

COMMAND = "sync_usercredential_created_at"
MIGRATION_DEFAULT = datetime(2026, 6, 24, 12, 32, tzinfo=timezone.utc)  # stand-in for the auto_now_add default


@pytest.fixture
def connect_issuer(db):
    return IssuingAuthorityFactory(
        issuing_authority=IssuingAuthority.IssuingAuthorityTypes.CONNECT,
        issuer_environment=IssuingAuthority.IssuingAuthorityEnvironments.STAGING,
        server_credentials=ServerKeysFactory(),
    )


@pytest.fixture
def hq_issuer(db):
    return IssuingAuthorityFactory(
        issuing_authority=IssuingAuthority.IssuingAuthorityTypes.HQ,
        issuer_environment=IssuingAuthority.IssuingAuthorityEnvironments.PRODUCTION,
        server_credentials=ServerKeysFactory(),
    )


@pytest.fixture
def prod_issuer(db):
    return IssuingAuthorityFactory(
        issuing_authority=IssuingAuthority.IssuingAuthorityTypes.CONNECT,
        issuer_environment=IssuingAuthority.IssuingAuthorityEnvironments.PRODUCTION,
        server_credentials=ServerKeysFactory(),
    )


def make_user_credential(issuer, *, username=None, type="LEARN", level="LEARN_PASSED", slug="1997", created_at=None):
    """Create a UserCredential with an explicit created_at (bypassing auto_now_add)."""
    user = UserFactory(username=username) if username else UserFactory()
    credential = CredentialFactory(issuer=issuer, type=type, level=level, slug=slug, opportunity_id=slug)
    uc = UserCredentialFactory(user=user, credential=credential)
    created_at = created_at or MIGRATION_DEFAULT
    UserCredential.objects.filter(pk=uc.pk).update(created_at=created_at)
    uc.refresh_from_db()
    return uc


def export_record(uc, issued_on):
    return {
        "user__username": uc.user.username,
        "credential_type": uc.credential.type,
        "level": uc.credential.level,
        "opportunity_id": uc.credential.slug,
        "issued_on": issued_on.isoformat(),
    }


def write_export(tmp_path, records):
    path = tmp_path / "connect_issued_on_export.json"
    path.write_text(json.dumps(records))
    return str(path)


def write_raw(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def run(path, *args):
    # --no-input skips the interactive confirmation; the prompt itself is covered separately.
    out = StringIO()
    call_command(COMMAND, "--input", path, "--no-input", *args, stdout=out)
    return out.getvalue()


@pytest.mark.django_db
class TestSyncUserCredentialCreatedAt:
    def test_loads_export_file_and_applies_all_records(self, connect_issuer, tmp_path):
        """End-to-end: a multi-record export written to disk is read, parsed and applied."""
        issued = {
            "1991": datetime(2026, 6, 10, 1, 0, 0, 976910, tzinfo=timezone.utc),
            "1997": datetime(2026, 6, 13, 1, 0, 0, 591117, tzinfo=timezone.utc),
            "2044": datetime(2026, 6, 24, 1, 0, 0, 960949, tzinfo=timezone.utc),
        }
        ucs = [make_user_credential(connect_issuer, slug=slug) for slug in issued]
        path = write_export(tmp_path, [export_record(uc, issued[uc.credential.slug]) for uc in ucs])

        output = run(path, "--apply")

        assert "Loaded 3 exported issued_on records" in output
        for uc in ucs:
            uc.refresh_from_db()
            assert uc.created_at == issued[uc.credential.slug]

    def test_dry_run_does_not_write(self, connect_issuer, tmp_path):
        uc = make_user_credential(connect_issuer)
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(uc, issued_on)])

        output = run(path)  # no --apply

        uc.refresh_from_db()
        assert uc.created_at == MIGRATION_DEFAULT
        assert "DRY RUN" in output
        assert "to_update: 1" in output

    def test_already_correct_is_skipped(self, connect_issuer, tmp_path):
        issued_on = datetime(2026, 5, 6, 1, 0, 2, tzinfo=timezone.utc)
        uc = make_user_credential(connect_issuer, created_at=issued_on)
        path = write_export(tmp_path, [export_record(uc, issued_on)])

        output = run(path, "--apply")

        uc.refresh_from_db()
        assert uc.created_at == issued_on
        assert "already_correct: 1" in output
        assert "to_update: 0" in output

    def test_no_pid_match_is_reported(self, connect_issuer, tmp_path):
        uc = make_user_credential(connect_issuer, slug="1997")
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        # Export references a different opportunity that has no PersonalID row.
        record = export_record(uc, issued_on)
        record["opportunity_id"] = "9999"
        path = write_export(tmp_path, [record])

        output = run(path, "--apply")

        uc.refresh_from_db()
        assert uc.created_at == MIGRATION_DEFAULT
        assert "no_pid_match: 1" in output

    def test_only_connect_issued_credentials_are_touched(self, connect_issuer, hq_issuer, tmp_path):
        username = "shared-user"
        connect_uc = make_user_credential(connect_issuer, username=username, slug="1997")
        # Same join key but HQ-issued -> must be ignored.
        hq_user = UserFactory(username=username + "-hq")
        hq_cred = CredentialFactory(
            issuer=hq_issuer, type="LEARN", level="LEARN_PASSED", slug="1997", opportunity_id="1997"
        )
        hq_uc = UserCredentialFactory(user=hq_user, credential=hq_cred)
        UserCredential.objects.filter(pk=hq_uc.pk).update(created_at=MIGRATION_DEFAULT)

        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        records = [
            export_record(connect_uc, issued_on),
            {
                "user__username": hq_user.username,
                "credential_type": "LEARN",
                "level": "LEARN_PASSED",
                "opportunity_id": "1997",
                "issued_on": issued_on.isoformat(),
            },
        ]
        path = write_export(tmp_path, records)

        run(path, "--apply")

        connect_uc.refresh_from_db()
        hq_uc.refresh_from_db()
        assert connect_uc.created_at == issued_on
        assert hq_uc.created_at == MIGRATION_DEFAULT  # HQ untouched

    def test_int_opportunity_id_matches_string_slug(self, connect_issuer, tmp_path):
        uc = make_user_credential(connect_issuer, slug="1997")
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        record = export_record(uc, issued_on)
        record["opportunity_id"] = 1997  # int, as Connect exports it
        path = write_export(tmp_path, [record])

        run(path, "--apply")

        uc.refresh_from_db()
        assert uc.created_at == issued_on

    def test_pid_rows_absent_from_export_are_reported_and_untouched(self, connect_issuer, tmp_path):
        in_export = make_user_credential(connect_issuer, slug="1997")
        staging_only = make_user_credential(connect_issuer, slug="2044")  # no export record
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(in_export, issued_on)])

        output = run(path, "--apply")

        staging_only.refresh_from_db()
        assert staging_only.created_at == MIGRATION_DEFAULT
        assert "pid_unmatched_by_export: 1" in output

    def test_null_issued_on_is_skipped(self, connect_issuer, tmp_path):
        uc = make_user_credential(connect_issuer)
        record = export_record(uc, datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc))
        record["issued_on"] = None
        path = write_export(tmp_path, [record])

        output = run(path, "--apply")

        uc.refresh_from_db()
        assert uc.created_at == MIGRATION_DEFAULT
        assert "bad_issued_on: 1" in output

    def test_multiple_issuers_same_key_updates_all(self, connect_issuer, tmp_path):
        """Two CONNECT issuers with the same (type, level, slug) for one user -> both updated."""
        username = "multi-issuer-user"
        second_issuer = IssuingAuthorityFactory(
            issuing_authority=IssuingAuthority.IssuingAuthorityTypes.CONNECT,
            issuer_environment=IssuingAuthority.IssuingAuthorityEnvironments.PRODUCTION,
            server_credentials=ServerKeysFactory(),
        )
        user = UserFactory(username=username)
        cred_a = CredentialFactory(
            issuer=connect_issuer, type="LEARN", level="LEARN_PASSED", slug="1997", opportunity_id="1997"
        )
        cred_b = CredentialFactory(
            issuer=second_issuer, type="LEARN", level="LEARN_PASSED", slug="1997", opportunity_id="1997"
        )
        uc_a = UserCredentialFactory(user=user, credential=cred_a)
        uc_b = UserCredentialFactory(user=user, credential=cred_b)
        UserCredential.objects.filter(pk__in=[uc_a.pk, uc_b.pk]).update(created_at=MIGRATION_DEFAULT)

        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        record = {
            "user__username": username,
            "credential_type": "LEARN",
            "level": "LEARN_PASSED",
            "opportunity_id": "1997",
            "issued_on": issued_on.isoformat(),
        }
        path = write_export(tmp_path, [record])

        output = run(path, "--apply")

        uc_a.refresh_from_db()
        uc_b.refresh_from_db()
        assert uc_a.created_at == issued_on
        assert uc_b.created_at == issued_on
        assert "multi_pid_match: 1" in output

    @pytest.mark.parametrize(
        "make_input",
        [
            pytest.param(lambda tp: str(tp / "does-not-exist.json"), id="missing-file"),
            pytest.param(lambda tp: write_raw(tp, "bad.json", "{not valid json"), id="invalid-json"),
            pytest.param(lambda tp: write_export(tp, {"not": "a list"}), id="non-list"),
        ],
    )
    def test_bad_input_raises(self, tmp_path, make_input):
        with pytest.raises(CommandError):
            run(make_input(tmp_path), "--apply")

    @pytest.mark.parametrize("answer,applied", [("y", True), ("n", False)])
    def test_confirmation_prompt(self, connect_issuer, tmp_path, monkeypatch, answer, applied):
        uc = make_user_credential(connect_issuer)
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(uc, issued_on)])
        monkeypatch.setattr("builtins.input", lambda *a: answer)

        out = StringIO()
        call_command(COMMAND, "--input", path, "--apply", stdout=out)  # no --no-input -> prompts

        uc.refresh_from_db()
        assert uc.created_at == (issued_on if applied else MIGRATION_DEFAULT)
        if not applied:
            assert "Aborted" in out.getvalue()


@pytest.mark.django_db
class TestFixIssuer:
    def test_off_by_default(self, connect_issuer, prod_issuer, tmp_path):
        uc = make_user_credential(connect_issuer, slug="1997")
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(uc, issued_on)])

        run(path, "--apply")  # no --fix-issuer

        uc.refresh_from_db()
        assert uc.credential.issuer_id == connect_issuer.id
        assert not Credential.objects.filter(issuer=prod_issuer).exists()

    def test_repoints_to_prod_issuer(self, connect_issuer, prod_issuer, tmp_path):
        uc = make_user_credential(connect_issuer, slug="1997")
        staging_cred_id = uc.credential_id
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(uc, issued_on)])

        run(path, "--apply", "--fix-issuer")

        uc.refresh_from_db()
        # Repointed to a new prod-issuer credential with the same identity.
        assert uc.credential.issuer_id == prod_issuer.id
        assert uc.credential_id != staging_cred_id
        assert (uc.credential.type, uc.credential.level, uc.credential.slug) == ("LEARN", "LEARN_PASSED", "1997")
        # created_at backfill applied in the same run.
        assert uc.created_at == issued_on
        # Both the original staging credential and the new prod credential exist.
        assert Credential.objects.filter(pk=staging_cred_id, issuer=connect_issuer).exists()
        assert Credential.objects.filter(issuer=prod_issuer, slug="1997").exists()

    def test_dry_run_makes_no_changes(self, connect_issuer, prod_issuer, tmp_path):
        uc = make_user_credential(connect_issuer, slug="1997")
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(uc, issued_on)])

        output = run(path, "--fix-issuer")  # no --apply

        uc.refresh_from_db()
        assert uc.credential.issuer_id == connect_issuer.id
        assert not Credential.objects.filter(issuer=prod_issuer).exists()
        assert "issuer_repoints: 1" in output

    def test_shared_credential_is_split(self, connect_issuer, prod_issuer, tmp_path):
        """A staging credential held by a prod user and a staging-only user: only the prod row moves."""
        shared = CredentialFactory(
            issuer=connect_issuer, type="LEARN", level="LEARN_PASSED", slug="1997", opportunity_id="1997"
        )
        prod_user = UserFactory(username="prod-user")
        staging_user = UserFactory(username="staging-only-user")
        prod_uc = UserCredentialFactory(user=prod_user, credential=shared)
        staging_uc = UserCredentialFactory(user=staging_user, credential=shared)
        UserCredential.objects.filter(pk__in=[prod_uc.pk, staging_uc.pk]).update(created_at=MIGRATION_DEFAULT)

        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(prod_uc, issued_on)])  # only the prod user

        run(path, "--apply", "--fix-issuer")

        prod_uc.refresh_from_db()
        staging_uc.refresh_from_db()
        assert prod_uc.credential.issuer_id == prod_issuer.id
        assert staging_uc.credential_id == shared.id  # staging-only holder untouched
        assert staging_uc.credential.issuer_id == connect_issuer.id
        # Shared staging credential survives because staging_uc still references it (not orphaned).
        assert Credential.objects.filter(pk=shared.id).exists()

    def test_idempotent(self, connect_issuer, prod_issuer, tmp_path):
        uc = make_user_credential(connect_issuer, slug="1997")
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(uc, issued_on)])

        run(path, "--apply", "--fix-issuer")
        prod_cred_count = Credential.objects.filter(issuer=prod_issuer).count()

        output = run(path, "--apply", "--fix-issuer")  # second run

        assert "issuer_already_prod: 1" in output
        assert "issuer_repoints: 0" in output
        assert Credential.objects.filter(issuer=prod_issuer).count() == prod_cred_count  # no new rows

    def test_requires_prod_issuer(self, connect_issuer, tmp_path):
        uc = make_user_credential(connect_issuer, slug="1997")
        issued_on = datetime(2026, 6, 13, 1, 0, 0, tzinfo=timezone.utc)
        path = write_export(tmp_path, [export_record(uc, issued_on)])

        with pytest.raises(CommandError):
            run(path, "--apply", "--fix-issuer")  # no CONNECT/production issuer exists
