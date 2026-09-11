# SMS vendor routing — design

| Field | Value |
|---|---|
| **Author** | Charl Smit |
| **Epic / Ticket** | [CCCT-2732](https://dimagi.atlassian.net/browse/CCCT-2732) (Design), under epic [CCCT-2734](https://dimagi.atlassian.net/browse/CCCT-2734) "Add additional logic to change SMS vendor by country to increase reliability" |

## 1. Problem

A user signing up for PersonalID requests an OTP and no SMS arrives. Tapping resend goes
through the same vendor that just failed, so the user cannot finish registration or
recovery.

We also have no record of which vendor was used for a send, so we cannot tell whether a
vendor is failing in a particular country, or answer that question after a user reports a
problem.

## 2. Goals

We want to use different SMS vendors for different countries. Each country has a default
vendor plus additional vendors as fallbacks, in a predefined but configurable order. The
country is taken from the phone number's country calling code.

1. A country's vendor order lives in the database and is editable in Django admin, so it
   can be changed without a deploy.
2. A vendor that errors mid-send is followed by the next vendor in that country's chain.
3. An OTP resend goes to a vendor that has not already been tried for this number,
   preferring the highest-ranked one available. A repeat of any other message moves off a
   vendor only if its last attempt failed.
4. Every send attempt is recorded, so per-country/per-vendor reliability is reportable.
5. An empty routing table reproduces today's behaviour exactly, i.e. Twilio as the global
   default.

## 3. Solution

### 3.1 Today

```
sms/__init__.py       send_sms()  — the only public entry point
sms/base.py           SmsMessage, SendResult, SmsSendError, BaseSmsVendor
sms/registry.py       VENDORS, DEFAULT_VENDOR, get_vendor()
sms/vendors/twilio.py TwilioVendor
```

`send_sms` skips test numbers, then sends through `DEFAULT_VENDOR`, which was stubbed when
`sms/` was added in [#292](https://github.com/dimagi/connect-id/pull/292):

```python
vendor = DEFAULT_VENDOR  # in future work the vendor will be determined based on the country code
```

This spec covers the work in that comment.

### 3.2 Proposal

#### Overview

We'll add two tables, `VendorRoute` and `SmsLog`. `VendorRoute` is configuration: it maps
an ISO-3166 alpha-2 country (e.g. `MW` for Malawi) to an ordered list of vendors, editable
in Django admin. `SmsLog` is history: one row per vendor attempt, recording which vendor was
used, its rank at the time, which `SessionPhoneDevice` asked for it, and whether it worked.

On each send, `phonenumbers` (an existing python package used in the code) attributes the
number to a country, and that country's chain is read from the `VendorRoute` table.
`SmsLog` then gives the vendors this number has already tried for the same purpose inside a
fixed retry window — every attempt for an OTP, only failed attempts for anything else. The
remaining vendors are ranked by their **current** `vendor_rank` and the best one is tried
first, falling through to the next on error. A country with no configured `VendorRoute` rows
falls back to Twilio as the global default, so an empty table reproduces today's behaviour.

The rule: use the highest-ranked vendor for the country that this number has not tried
recently. An OTP counts a vendor as tried if it was attempted at all; every other purpose
counts it as tried only if the attempt failed.

#### Data model changes

`sms/models.py:VendorRoute` — configuration:

| Field | Type | Purpose |
|---|---|---|
| `country` | `CharField(max_length=2)` | ISO-3166 alpha-2, uppercased in `save()` |
| `vendor` | `CharField(max_length=50)` | `choices` from a callable reading `registry.VENDORS`, so admin gets a dropdown and adding a vendor needs no migration. |
| `vendor_rank` | `PositiveSmallIntegerField(default=1)` | try lowest number first |
| `is_active` | `BooleanField(default=True)` | Pulls a vendor from a chain without deleting the row |

Two unique constraints — `(country, vendor)`, and `(country, vendor_rank)` conditioned on
`is_active` — plus `Meta.ordering = ["country", "vendor_rank", "vendor"]`. `clean()` rejects a
`country` absent from `phonenumbers.SUPPORTED_REGIONS`.

```python
models.UniqueConstraint(
    fields=["country", "vendor_rank"],
    condition=models.Q(is_active=True),
    name="unique_active_country_vendor_rank",
)
```

Ranks need not be contiguous; `vendor_rank` only defines an ordering.

`sms/models.py:SmsLog` — history, one row per **vendor attempt** (not per send, so
failover is visible):

| Field | Type | Purpose |
|---|---|---|
| `session_phone_device` | `ForeignKey("users.SessionPhoneDevice", null=True, blank=True, on_delete=SET_NULL, related_name="sms_logs")` | traces an OTP send back to the flow that asked for it; `NULL` on every non-OTP send. Not read by routing |
| `user` | `ForeignKey("users.ConnectUser", null=True, blank=True, on_delete=SET_NULL, related_name="sms_logs")` | per-user reporting as a join rather than a phone-number match; `NULL` on session OTP sends |
| `phone_number` | `PhoneNumberField()` | the number the message went to; always populated |
| `country` | `CharField(max_length=2, blank=True)` | `""` when the number is not routable |
| `vendor` | `CharField(max_length=50)` | which vendor was attempted |
| `vendor_rank` | `PositiveSmallIntegerField(null=True)` | the vendor's rank **at send time**; `NULL` means the send went via `DEFAULT_VENDOR` because the country had no rows |
| `purpose` | `CharField(choices=Purpose)` | `otp` / `deactivation` / `hq_invite` / `credential_invite` |
| `status` | `CharField(choices=Status)` | `success` / `vendor_error` / `config_error` |
| `vendor_message_id` | `CharField(max_length=100, blank=True)` | from `SendResult` |
| `vendor_error_code` | `CharField(max_length=50, blank=True)` | from `SmsSendError` |
| `created_at` | `DateTimeField(auto_now_add=True)` | |

Neither FK is present on every row, and they are near-inverses. `ConfigurationSession` has
no user FK, and `send_session_otp` never populates `SessionPhoneDevice.user`, so there is no
`ConnectUser` in scope at session-OTP send time; during registration the account does not
exist yet. The three non-OTP call sites all hold a `ConnectUser` and have no session OTP
device. The legacy `PhoneDevice` flows are the one case with both, since `PhoneDevice.user`
is non-nullable.

`phone_number` is therefore denormalised onto the row rather than reached through either FK:
it is the only identifier present on all rows.

`Meta.ordering = ["-created_at"]`, and three indexes:

| Index | Serves |
|---|---|
| `(phone_number, purpose, created_at)` | the "already tried" lookup on every send |
| `(country, vendor, created_at)` | per-country/per-vendor reporting |
| `(created_at)` | the retention sweep |

`status` distinguishes `config_error` (an `ImproperlyConfigured` from `get_vendor`: a
missing `SMS_VENDORS` entry or bad credentials) from `vendor_error` (the vendor's API
rejected the send). Collapsing the two would count a deployment mistake against a vendor's
measured reliability. Routing treats them alike, since both mean the vendor did not send,
and reads `status` only for non-OTP purposes.

`SmsLog.vendor_rank` is for reporting only; routing never reads it. It is a historical
snapshot, so a row stays interpretable after the chain is re-ordered, and reporting can
compare a vendor's performance at rank 1 with its performance at rank 3. Vendor selection
always ranks by the `vendor_rank` currently held in `VendorRoute`.

#### Vendor resolution

New module `sms/routing.py`. `ChainEntry` is a frozen dataclass, matching the style of
`sms/base.py`:

```python
@dataclass(frozen=True)
class ChainEntry:
    vendor: str
    vendor_rank: int | None   # None => DEFAULT_VENDOR fallback, no VendorRoute row


def resolve_chain(phone_number) -> list[ChainEntry]:
    """Active, registered vendors for the number's country, lowest rank first.

    Returns [ChainEntry(DEFAULT_VENDOR, None)] when the number has no region, the
    country has no active rows, or no active row names a registered vendor.
    """


# Purposes where a successful send still counts the vendor as tried: "success"
# means the vendor accepted the message, not that it was delivered, and a
# request for another OTP implies the previous one did not arrive.
ESCALATE_ON_SUCCESS = frozenset({SmsLog.Purpose.OTP})


def tried_vendors(phone_number, purpose) -> set[str]:
    """Vendor names to skip for this number and purpose, inside the retry window."""
    recent = SmsLog.objects.filter(
        phone_number=phone_number,
        purpose=purpose,
        created_at__gt=now() - settings.SMS_VENDOR_RETRY_WINDOW,
    )
    if purpose in ESCALATE_ON_SUCCESS:
        return set(recent.values_list("vendor", flat=True))

    latest_per_vendor = recent.order_by("vendor", "-created_at").distinct("vendor")
    return {log.vendor for log in latest_per_vendor if log.status != SmsLog.Status.SUCCESS}


def candidates(chain: list[ChainEntry], tried: set[str]) -> list[ChainEntry]:
    """The chain minus what has already been tried, best rank first."""
    untried = [e for e in chain if e.vendor not in tried]
    return untried or chain   # every vendor tried -> start over at rank 1
```

The send walks the `candidates` list in order, falling through to the next entry when one
errors.

Ranking is always against the live table. `tried_vendors` contributes vendor names only, so
chain edits — re-ordering, insertion, deletion, deactivation — are absorbed by re-reading
`VendorRoute`. A vendor is skipped by name, never by the rank it used to hold.

Scope is the phone number and the purpose, bounded by a time window. "Already tried" means
by this number, for this purpose, within the last `SMS_VENDOR_RETRY_WINDOW` — a new setting,
`timedelta(hours=4)`, matching the `ConfigurationSession` lifetime the OTP flow already runs
on. The tried-set describes the number's reachability, so a vendor failing this number
escalates regardless of which flow made the attempt.

Purpose is part of the key. A vendor counts as tried only for the message type it was tried
on. Without purpose in the key, a successful `hq_invite` would push the user's next OTP down
to vendor 2 for four hours.

Purpose also decides what counts as trying a vendor. There are two modes, declared per
purpose in `ESCALATE_ON_SUCCESS`:

| Purpose | A vendor is skipped when | Why |
|---|---|---|
| `otp` | it was attempted at all in the window, success or failure | A resend implies the first OTP never arrived. Without delivery webhooks, a `success` row only means the vendor accepted the message |
| everything else | its **most recent** attempt in the window was not a `success` | Nothing in these flows signals non-delivery, so acceptance is the best information available. A working vendor should not be sidelined over a failure we cannot observe |

An exclusion holds until the window passes. Reading the latest row per vendor rather than
"any failure in the window" is not a re-probe mechanism: an excluded vendor is not selected,
so it produces no newer row, so nothing overwrites its failure. The one exception is when
every vendor in the chain is excluded: `candidates` falls through to `untried or chain`, the
full chain is walked from rank 1, the excluded vendor is retried there, and a success
rewrites its latest row. Otherwise an errored non-OTP vendor stays out for the remainder of
the window.

That is intended — a vendor that just failed this number should not be tried first again
minutes later — but it means `SMS_VENDOR_RETRY_WINDOW` is also how long a single non-OTP
failure sidelines a vendor for that number.

Keying on the number also survives an app restart. `start_device_configuration` is
unauthenticated and takes only a phone number, so relaunching the app creates a fresh
`ConfigurationSession` and a fresh `SessionPhoneDevice`. Keying on the device would give
that user an empty tried-set and send them back to the vendor that had just failed. Keyed on
the number, the earlier attempts are still inside the window, so they still count.

Routing does not read `session_phone_device`. It is on the row only for tracing an OTP send
back to the flow that requested it.


#### Log durability

`SmsLog` rows are written by the chain walk, which runs inside `_attempt_send`'s
`transaction.atomic()` block. If every vendor errors, `AllVendorsFailed` propagates out of
that block and Postgres rolls it back, discarding the rows. The rows are therefore buffered
in memory during the walk and flushed after the block exits.

`send_sms` gains a `purpose` argument and returns a `SendOutcome` carrying the result and
the unsaved rows. `AllVendorsFailed` carries them too, so the total-failure path still
persists them:

```python
# sms/base.py
@dataclass(frozen=True)
class SendOutcome:
    result: SendResult
    log_rows: list[SmsLog]


class AllVendorsFailed(Exception):
    """Every vendor in the chain errored. Carries the buffered rows so the caller
    can persist them after the enclosing transaction has rolled back."""

    def __init__(self, message: str, log_rows: list[SmsLog]):
        super().__init__(message)
        self.log_rows = log_rows


# sms/__init__.py
def send_sms(
    to: PhoneNumber,
    body: str,
    purpose: str,
    device: SessionPhoneDevice | None = None,
    user: ConnectUser | None = None,
) -> SendOutcome: ...
```

`device` and `user` are stored on each logged row for tracing and reporting. Neither is read
by routing, which keys on `to` and `purpose` alone. The three non-OTP call sites pass `user`
only.

`_send_otp` lives on `BasePhoneDevice`, which `PhoneDevice` also uses, so it cannot pass
`self` unconditionally. A property hook keeps the base class generic:

```python
# users/models.py
class BasePhoneDevice(BaseOTPDevice):
    @property
    def sms_log_device(self):
        """The SessionPhoneDevice to log sends against; None for models without one."""
        return None

    def _send_otp(self):
        return send_sms(
            self.phone_number,
            self.otp_message,
            purpose=SmsLog.Purpose.OTP,
            device=self.sms_log_device,
            user=self.user,   # None on SessionPhoneDevice, set on PhoneDevice
        )


class SessionPhoneDevice(BasePhoneDevice):
    @property
    def sms_log_device(self):
        return self
```

`_attempt_send` performs the flush:

```python
def _attempt_send(self, valid_secs):
    try:
        with transaction.atomic():
            locked = self.__class__.objects.select_for_update().get(pk=self.pk)
            ...
            if self.is_otp_close_to_expiry:
                self.otp_last_sent = None
                self.generate_token(valid_secs=valid_secs)
                self.attempts = 0
            wait_time = 2**self.attempts
            if self.otp_last_sent is None or now() - self.otp_last_sent >= timedelta(minutes=wait_time):
                outcome = self._send_otp()
                self.otp_last_sent = now()
                self.attempts += 1
                self.save()
            else:
                raise RateLimitedError(retry_after)
    except AllVendorsFailed as e:
        SmsLog.objects.bulk_create(e.log_rows)   # device state rolled back; the log survives
        raise
    else:
        SmsLog.objects.bulk_create(outcome.log_rows)
```

#### Retention

`SmsLog` grows by roughly one row per SMS attempt and is trimmed to 90 days, mirroring
`messaging.tasks.delete_old_messages`. Rows whose session has been cleaned up in the
meantime carry a `NULL` device and are trimmed on the same schedule.

#### UX / UI changes

Django admin only.

`VendorRouteAdmin` sets `list_editable = ("vendor_rank", "is_active")`, so re-ranking or
disabling a country's vendors happens on one screen without opening each row.

#### Failure modes

| Scenario | What the system does | What the user sees |
|---|---|---|
| Vendor 1 errors, vendor 2 accepts | Failover; vendor 1's exception is logged and the next candidate is tried. Two `SmsLog` rows: `vendor_error` then `success` | OTP arrives |
| A vendor accepts an OTP it never delivers | Nothing; not detectable without delivery webhooks. The row reads `success`, but `otp` counts a vendor as tried on success too | No SMS; the resend goes to an untried vendor |
| A vendor accepts a non-OTP message it never delivers | Nothing detects it. The `success` row leaves the vendor in play | A repeat send goes back to the same vendor |
| Every vendor in the chain errors | `AllVendorsFailed`, uncaught, Sentry error; `transaction.atomic()` rolls back `attempts` and `otp_last_sent`, but the buffered `SmsLog` rows are flushed from the exception and persist | The generic error a Twilio failure gives today; resend allowed at once, no backoff advance |
| Nothing routable — no region, no active rows (day one, every unconfigured country), or only unregistered vendors | Falls to `DEFAULT_VENDOR`, logged with `vendor_rank = NULL` | Today's behaviour |
| A routed vendor has no `settings.SMS_VENDORS` entry, or bad credentials | `ImproperlyConfigured` caught, logged as `config_error`; next candidate tried | No effect if a later candidate succeeds |
| Every configured vendor already tried inside the retry window | Candidate list is empty, so the full chain is reused and rank 1 is tried again | A repeat of the best vendor rather than an error |
| `VendorRoute` edited between two sends | The chain is re-read and ranking uses the new ranks; the tried-set is by name | Correct escalation regardless of the edit |
| Process killed mid-send | Buffered rows are lost; device state is rolled back too, so nothing is half-recorded | Resend allowed at once |
| A user changes their phone number — legacy path only, since `change_phone` refuses a validated number | Historical rows keep the number each message went to; `user` still ties them to the person | Nothing; per-person and per-number history both stay accurate |
| Two overlapping flows on the same number, same purpose | They share a tried-set, so one flow's failures escalate the other | A flow may start further down the chain than its own history implies |
| The user kills and relaunches the app after no SMS arrives | New session and new device, but the earlier attempts are still inside the window, so they still count | The resend reaches an untried vendor rather than resetting to rank 1 |
| The window has passed with no send | Nothing matches, tried-set empty, chain walked from rank 1 | A fresh start after four idle hours |
| A send with no session device — non-OTP purpose, or a legacy `PhoneDevice` flow | `session_phone_device = NULL`, but the lookup does not use it: the tried-set is still keyed on number and purpose | A repeated deactivation link goes to a different vendor if the last one errored, the same one if it was accepted |
| A non-OTP vendor errors, and the chain still has untried vendors | It stays excluded for the rest of the window; nothing selects it, so nothing clears it | Later sends in the window start at the next vendor down |
| Every vendor for a non-OTP purpose is excluded | `candidates` falls back to the full chain, so rank 1 is retried; a success rewrites its latest row | The chain resets rather than erroring |
| The `ConfigurationSession` behind a logged device is deleted | `SET_NULL` blanks the FK; `phone_number`, `country`, `vendor`, `vendor_rank` and `status` survive | Nothing; reporting is unaffected |
| Two resends racing on one device | `select_for_update` serialises them as today, but the lock is now held across the whole chain walk rather than a single vendor call | The second request blocks for up to `len(chain) × SMS_VENDOR_TIMEOUT_SECONDS` before receiving its `RateLimitedError`, where today it returns almost at once. The `retry_after` value is unaffected |


### 3.3 Example workflow

Malawi is the only configured country; everywhere else falls to `DEFAULT_VENDOR`.

`VendorRoute` table looks like this:
| `country` | `vendor` | `vendor_rank` | `is_active` |
|---|---|---|---|
| `MW` | `twilio` | 1 | ✓ |
| `MW` | `vendorB` | 2 | ✓ |

**Send 1 — a user on `+265991234567` requests their first OTP.**

- No token exists, so `is_otp_close_to_expiry` is true
- `tried_vendors` returns `{}` — no OTP has been sent to this number in the last four hours
- `resolve_chain` returns `[twilio(rank 1), vendorB(rank 2)]`
- `candidates` is the whole chain, so `get_vendor` is handed `"twilio"`
- Twilio request succeeds
- One buffered row — `twilio`, rank 1, `otp`, `success`, linked to this
  `SessionPhoneDevice` — is flushed after the atomic block commits, alongside the existing
  `attempts` and `otp_last_sent` write

The backoff schedule is unchanged. The gate reads only `attempts` and `otp_last_sent`, and
the whole chain walk sits inside the single `_send_otp()` call, so `attempts` advances once
per send, not once per vendor tried. (see *Open questions*)

**Send 2 — no SMS arrives, and the user taps resend.** Twilio accepted the message but did
not deliver it.

- Two minutes have passed, clearing the `2**attempts` gate
- `tried_vendors` returns `{"twilio"}` — the row logged two minutes ago for this number
  and purpose
- `resolve_chain` returns the same two entries — it reads config, not history
- `candidates` drops twilio, leaving `[vendorB(rank 2)]`
- vendorB succeeds; a row for `vendorB`, rank 2, `success` is written
- Net effect: the resend reached a different vendor. Only `SmsLog` records the first
  attempt; the view, the user and `VendorRoute` are unchanged

**Send 2b — an admin re-orders the chain mid-flow.** Suppose between Send 1 and Send 2 the
chain had become `vendorB(rank 1), twilio(rank 2)`. Nothing changes: the tried-set is still
`{"twilio"}` by name, so `candidates` is `[vendorB(rank 1)]` and vendorB is still chosen.
The same holds if a vendor is inserted, deleted or deactivated, since ranking always
re-reads the live table.

**Send 3 — the same user returns a week later.**

- The week-old rows are outside the retry window, so the tried-set is empty. They remain on
  file for reporting
- The token has long expired anyway, so `is_otp_close_to_expiry` is true, the token is
  regenerated and `attempts` resets
- The send goes to twilio, `vendor_rank` 1 for Malawi

**Edge paths.**

- **A vendor errors mid-send** — the next candidate is tried, and the user sees one OTP.
  Both attempts are logged, so the next resend for this number skips both
- **A four-vendor chain, reshuffled mid-flow** — `v1` and `v2` have been tried, then an
  admin swaps `v2` and `v4` so the chain reads `v1(1) v4(2) v3(3) v2(4)`. The untried set is
  `{v3, v4}`, ranked by current `vendor_rank`, so `v4` is tried next
- **An unconfigured country** — no rows match, so the chain is `[DEFAULT_VENDOR]` and the
  row logs `vendor_rank = NULL`
- **A test number** — returns before any database read or vendor call, and logs nothing

#### Who owns what

| Question | Answered by | Read | Written |
|---|---|---|---|
| Which vendors serve this country, in what order? | `VendorRoute` rows | Every send | Django admin only |
| Which vendors has this number already tried? | `SmsLog.vendor` for this number and purpose, inside `SMS_VENDOR_RETRY_WINDOW` — every attempt for `otp`, only latest-attempt failures otherwise | Every send | Once per vendor attempt, flushed after the transaction |
| How is a vendor performing, by country? | `SmsLog` aggregates | Reporting | Once per vendor attempt |
| What if the country has no rows? | `settings.DEFAULT_VENDOR` | When resolution yields nothing | Deploy only |

## 4. Open questions

Should we increase `attempts` based on vendor-tries, or user-tries?
  - A user-try is a user hitting "Send OTP" button
  - A vendor-try is a single vendor attempt
  - Multiple vendors can be tried for a single user-try
