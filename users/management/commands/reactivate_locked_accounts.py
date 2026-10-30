from django.core.management.base import BaseCommand
from django.db import IntegrityError, transaction
from django.db.models import Exists, OuterRef

from users.models import ConnectUser


def plan_reactivations():
    """Split the accounts locked under the old scheme into those to reactivate and those to skip.

    Candidates are taken newest first, so the newest account wins both per phone number and
    when two candidates share an email address.
    """
    newer_on_phone = ConnectUser.objects.filter(
        phone_number=OuterRef("phone_number"), date_joined__gt=OuterRef("date_joined")
    )
    candidates = list(
        ConnectUser.objects.filter(is_active=False, is_locked=True)
        .annotate(has_newer_account=Exists(newer_on_phone))
        .order_by("-date_joined", "-pk")
    )
    active = ConnectUser.objects.filter(is_active=True)
    taken_phones = {
        str(phone)
        for phone in active.filter(phone_number__in=[c.phone_number for c in candidates]).values_list(
            "phone_number", flat=True
        )
    }
    taken_emails = set(
        active.filter(email__in=[c.email for c in candidates if c.email]).values_list("email", flat=True)
    )

    to_reactivate = []
    skipped = []
    seen_phones = set()
    planned_emails = set()
    for user in candidates:
        phone = str(user.phone_number)
        if phone in seen_phones:
            skipped.append((user, "not the newest locked account on this phone number"))
        elif phone in taken_phones:
            skipped.append((user, "phone number is in use by an active account"))
        elif user.has_newer_account:
            skipped.append((user, "a newer account on this phone number was deactivated"))
        elif user.email and user.email in taken_emails:
            skipped.append((user, "email is in use by an active account"))
        elif user.email and user.email in planned_emails:
            skipped.append((user, "email is in use by a newer account being reactivated"))
        else:
            to_reactivate.append(user)
            if user.email:
                planned_emails.add(user.email)
        seen_phones.add(phone)
    return to_reactivate, skipped


class Command(BaseCommand):
    help = (
        "Reactivate accounts deactivated by a backup code lock before CCCT-2918. "
        "They stay locked, so they can use email recovery."
    )

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="Print the planned changes without writing")

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        to_reactivate, skipped = plan_reactivations()

        reactivated = []
        for user in to_reactivate:
            if dry_run:
                reactivated.append(user)
                continue
            user.is_active = True
            try:
                with transaction.atomic():
                    user.save(update_fields=["is_active"])
            except IntegrityError:
                user.is_active = False
                skipped.append((user, "phone number or email was taken by an active account during the run"))
            else:
                reactivated.append(user)

        verb = "Would reactivate" if dry_run else "Reactivated"
        self.stdout.write(f"{verb} {len(reactivated)} account(s):")
        for user in reactivated:
            self.stdout.write(f"  {self._describe(user)}")
        self.stdout.write(f"Skipped {len(skipped)} account(s):")
        for user, reason in skipped:
            self.stdout.write(f"  {self._describe(user)}: {reason}")

    @staticmethod
    def _describe(user):
        return f"id={user.pk} username={user.username} phone={user.phone_number} email={user.email or '-'}"
