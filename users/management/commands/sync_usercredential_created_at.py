"""
Reconcile PersonalID UserCredential records against Connect's prod issuance.

Two things, both driven by a JSON export of Connect prod UserCredential.issued_on
(format described below):

1. created_at backfill (always): UserCredential.created_at (migration 0032) was added
   with auto_now_add, so existing rows hold the migration run time rather than the date
   the credential was issued to the user. Credential.created_at is not a substitute (it is
   per-credential, shared across holders and environments). The per-user source of truth is
   Connect's UserCredential.issued_on, which this command writes onto created_at.

2. issuer fix (--fix-issuer, opt-in): because Connect prod historically pushed credentials
   using the generic (staging) client, prod-issued credentials are attributed to the
   CONNECT/staging IssuingAuthority. For each prod-matched UserCredential this repoints it to
   a Credential under the CONNECT/production IssuingAuthority (get_or_create on
   issuer+level+type+slug), leaving the staging Credential in place for any staging-only
   co-holders. Staging Credentials left with no holders are reported (not deleted).

Expected --input format: a JSON list of objects, one per issued Connect credential:

    [
      {
        "user__username": "052c3dcec085d7689cbe",
        "credential_type": "LEARN",
        "level": "LEARN_PASSED",
        "opportunity_id": "1997",
        "issued_on": "2026-06-13T01:00:00.591117+00:00"
      },
      ...
    ]

Produced on the Connect side with:

    data = list(
        UserCredential.objects.filter(issued_on__isnull=False).values(
            "user__username", "credential_type", "level", "opportunity_id", "issued_on"
        )
    )
    for d in data:
        d["issued_on"] = d["issued_on"].isoformat()
    json.dump(data, open("connect_issued_on_export.json", "w"))

Field notes: issued_on must be an ISO 8601 string (records with a missing/unparseable
issued_on are counted as bad_issued_on and skipped); opportunity_id may be an int or a
string (it is compared as a string against Credential.slug).

Matching key: (username, credential type, level, slug==opportunity_id), restricted to
CONNECT-issued credentials. Records present in PersonalID but absent from the export
(e.g. staging-only credentials) are left untouched and reported.

Defaults to a DRY RUN. Pass --apply to write changes.
"""

import datetime
import json
from collections import Counter, defaultdict

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from users.models import Credential, IssuingAuthority, UserCredential

CONNECT = "CONNECT"
PRODUCTION = IssuingAuthority.IssuingAuthorityEnvironments.PRODUCTION
EXPORT_FIELDS = ("user__username", "credential_type", "level", "opportunity_id", "issued_on")


class Command(BaseCommand):
    help = (
        "Sync PersonalID UserCredential.created_at from a Connect prod export of "
        "issued_on dates. Expects --input pointing at a JSON list of objects with keys: "
        f"{', '.join(EXPORT_FIELDS)}. Dry run unless --apply is given."
    )

    def add_arguments(self, parser):
        parser.add_argument("--input", required=True, help="Path to the Connect issued_on JSON export.")
        parser.add_argument("--apply", action="store_true", help="Persist changes. Omit for a dry run.")
        parser.add_argument("--batch-size", type=int, default=500, help="bulk_update batch size.")
        parser.add_argument(
            "--fix-issuer",
            action="store_true",
            help="Also repoint prod-matched UserCredentials to the CONNECT/production issuer.",
        )
        parser.add_argument(
            "--no-input",
            action="store_true",
            help="Skip the interactive confirmation prompt before applying (for scripted runs).",
        )

    def handle(self, *args, **options):
        apply = options["apply"]
        fix_issuer = options["fix_issuer"]
        prod_issuer = self._get_prod_issuer() if fix_issuer else None

        export = self._load_export(options["input"])
        self.stdout.write(f"Loaded {len(export)} exported issued_on records from {options['input']}")

        index = self._index_connect_credentials()
        indexed_count = sum(len(ucs) for ucs in index.values())
        self.stdout.write(f"Indexed {indexed_count} CONNECT UserCredentials on PersonalID")

        stats = Counter()
        to_update = []  # (UserCredential[with old created_at], new_created_at)
        matched = {}  # user_cred.id -> UserCredential (dedup across export rows)

        for rec in export:
            issued_on = self._parse_issued_on(rec)
            if issued_on is None:
                stats["bad_issued_on"] += 1
                continue

            matches = index.get(self._export_key(rec), [])
            if not matches:
                stats["no_pid_match"] += 1
                continue
            if len(matches) > 1:
                stats["multi_pid_match"] += 1  # still update all; logged for awareness

            for user_cred in matches:
                matched[user_cred.id] = user_cred
                if user_cred.created_at == issued_on:
                    stats["already_correct"] += 1
                else:
                    to_update.append((user_cred, issued_on))

        # PersonalID CONNECT credentials never seen in the export (e.g. staging-only).
        # matched keys are a subset of indexed User Creds, so a plain subtraction is correct.
        stats["pid_unmatched_by_export"] = indexed_count - len(matched)

        to_repoint = []
        if fix_issuer:
            for user_cred in matched.values():
                if user_cred.credential.issuer_id == prod_issuer.id:
                    stats["issuer_already_prod"] += 1
                else:
                    to_repoint.append(user_cred)
            stats["issuer_repoints"] = len(to_repoint)

        self._report(stats, to_update, to_repoint, fix_issuer)

        if not to_update and not to_repoint:
            self.stdout.write(self.style.WARNING("Nothing to update."))
            return
        if not apply:
            self.stdout.write(
                self.style.WARNING(
                    f"DRY RUN — {len(to_update)} created_at and {len(to_repoint)} issuer changes "
                    "would be applied. Re-run with --apply."
                )
            )
            return

        if not options["no_input"] and not self._confirm(to_update, to_repoint):
            self.stdout.write(self.style.WARNING("Aborted; no changes made."))
            return

        created = orphaned = 0
        with transaction.atomic():
            # Reassign credentials in memory first (creating prod Credential rows as needed),
            # then write created_at + credential for every touched row in a single bulk_update.
            source_cred_ids = set()
            if to_repoint:
                created, source_cred_ids = self._reassign_to_prod_issuer(to_repoint, prod_issuer)
            for user_cred, issued_on in to_update:
                user_cred.created_at = issued_on

            # to_update and to_repoint are distinct (overlapping) row sets referencing the SAME
            # user_cred objects from `index`, so each object already carries both mutations. Merge by pk
            # to write every touched row exactly once.
            dirty = {user_cred.id: user_cred for user_cred, _ in to_update}
            dirty.update({user_cred.id: user_cred for user_cred in to_repoint})
            update_fields = ["created_at"] + (["credential"] if to_repoint else [])
            UserCredential.objects.bulk_update(list(dirty.values()), update_fields, batch_size=options["batch_size"])

            if source_cred_ids:
                orphaned = Credential.objects.filter(id__in=source_cred_ids, usercredential__isnull=True).count()

        if to_update:
            self.stdout.write(self.style.SUCCESS(f"Updated created_at on {len(to_update)} UserCredential rows."))
        if to_repoint:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Repointed {len(to_repoint)} UserCredentials to the prod issuer "
                    f"({created} prod Credential rows created, {orphaned} staging Credentials now orphaned)."
                )
            )

    # --- helpers ---------------------------------------------------------

    @staticmethod
    def _confirm(to_update, to_repoint):
        answer = input(
            f"\nAbout to apply {len(to_update)} created_at and {len(to_repoint)} issuer changes. "
            "Type 'y' to continue: "
        )
        return answer.strip().lower() == "y"

    @staticmethod
    def _get_prod_issuer():
        try:
            return IssuingAuthority.objects.get(issuing_authority=CONNECT, issuer_environment=PRODUCTION)
        except IssuingAuthority.DoesNotExist:
            raise CommandError("No CONNECT/production IssuingAuthority found; cannot --fix-issuer.")
        except IssuingAuthority.MultipleObjectsReturned:
            raise CommandError("Multiple CONNECT/production IssuingAuthorities found; resolve before --fix-issuer.")

    @staticmethod
    def _load_export(path):
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise CommandError(f"Could not read export {path}: {e}")
        if not isinstance(data, list):
            raise CommandError("Export must be a JSON list of records.")
        return data

    @staticmethod
    def _index_connect_credentials():
        index = defaultdict(list)
        qs = UserCredential.objects.filter(credential__issuer__issuing_authority=CONNECT).select_related(
            "user", "credential", "credential__issuer"
        )
        for user_cred in qs.iterator(chunk_size=2000):
            index[Command._pid_key(user_cred)].append(user_cred)
        return index

    @staticmethod
    def _parse_issued_on(rec):
        try:
            return datetime.datetime.fromisoformat(rec["issued_on"])
        except (KeyError, TypeError, ValueError):
            return None

    @staticmethod
    def _export_key(rec):
        return (
            rec.get("user__username"),
            rec.get("credential_type"),
            rec.get("level"),
            str(rec.get("opportunity_id")),
        )

    @staticmethod
    def _pid_key(user_cred):
        return (
            user_cred.user.username,
            user_cred.credential.type,
            user_cred.credential.level,
            str(user_cred.credential.slug),
        )

    @staticmethod
    def _reassign_to_prod_issuer(user_creds, prod_issuer):
        """Point each uc at a prod-issuer Credential *in memory* (not saved; the caller's
        bulk_update persists it). Creates prod Credential rows as needed.
        Returns (prod_creds_created, source_staging_credential_ids)."""
        cache = {}
        created = 0
        source_ids = set()
        for user_cred in user_creds:
            staging_cred = user_cred.credential
            source_ids.add(staging_cred.id)
            key = (staging_cred.level, staging_cred.type, staging_cred.slug)
            prod_cred = cache.get(key)
            if prod_cred is None:
                prod_cred, was_created = Credential.objects.get_or_create(
                    issuer=prod_issuer,
                    level=staging_cred.level,
                    type=staging_cred.type,
                    slug=staging_cred.slug,
                    defaults={
                        "title": staging_cred.title,
                        "app_id": staging_cred.app_id,
                        "opportunity_id": staging_cred.opportunity_id,
                    },
                )
                cache[key] = prod_cred
                created += int(was_created)
            user_cred.credential = prod_cred
        return created, source_ids

    def _report(self, stats, to_update, to_repoint, fix_issuer):
        self.stdout.write("\n=== Reconciliation summary ===")
        for key in ("no_pid_match", "multi_pid_match", "already_correct", "bad_issued_on", "pid_unmatched_by_export"):
            self.stdout.write(f"  {key}: {stats[key]}")
        self.stdout.write(f"  to_update: {len(to_update)}")
        if fix_issuer:
            self.stdout.write(f"  issuer_already_prod: {stats['issuer_already_prod']}")
            self.stdout.write(f"  issuer_repoints: {len(to_repoint)}")
        if to_update:
            self.stdout.write("\n  Sample planned created_at changes (created_at -> issued_on):")
            for uc, issued_on in to_update:
                cred = uc.credential
                self.stdout.write(
                    f"    uc#{uc.id} {uc.user.username} {cred.type}/{cred.level}/{cred.slug}: "
                    f"{uc.created_at.isoformat()} -> {issued_on.isoformat()}"
                )
