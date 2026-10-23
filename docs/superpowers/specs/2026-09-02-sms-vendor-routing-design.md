# SMS vendor routing — design

| Field | Value |
|---|---|
| **Author** | Charl Smit |
| **Epic / Ticket** | [CCCT-2732](https://dimagi.atlassian.net/browse/CCCT-2732) (Design), under epic [CCCT-2734](https://dimagi.atlassian.net/browse/CCCT-2734) "Add additional logic to change SMS vendor by country to increase reliability" |

## 1. Overview

### The problem

PersonalID sends SMS messages through a single provider, Twilio. Every message for every
country goes through it, because that is the only provider the code knows about.

When a message does not arrive, the user is stuck. Someone signing up requests a one-time
password (OTP), no SMS arrives, and tapping "resend" sends the same message through the
same provider that just failed. They cannot finish registration, and they cannot recover
an existing account.

We also keep no record of which provider sent which message. So we cannot answer "is this
provider failing in Malawi?" either from a dashboard or after a user reports a problem.

Throughout this document, *vendor* means an SMS provider — a company such as Twilio whose
API we call to deliver a text message.

### The solution

Two changes.

**First, route by country.** Each country gets an ordered list of vendors: a first choice,
then fallbacks. The list lives in a database table that an administrator edits in Django
admin, so changing a country's vendor order does not require a code deploy. The country
comes from the international dialling code at the front of the phone number, so we know it
before we send anything.

When we send, we read that country's list and try the first vendor. If that vendor's API
returns an error, we try the next one, and so on down the list. The user sees one message
attempt; the failover happens inside it.

**Second, record every attempt.** We write one database row per vendor attempt — which
vendor, for which phone number, for which kind of message, and whether it worked. That
record does two jobs:

- It is the reliability data. We can now report on how each vendor performs in each
  country.
- It is what makes "resend" go somewhere new. Before choosing a vendor, we read the recent
  attempts for this phone number and skip the vendors it has already been through. A resend
  therefore lands on a vendor that has not been tried, rather than repeating the one that
  just failed.

The one-line rule: **use the best-ranked vendor for this country that this phone number has
not already tried recently.**

"Already tried" means something slightly different depending on the kind of message:

- For a **one-time password**, any attempt counts — success or failure. A vendor accepting
  a message is not the same as the message arriving. We have no delivery confirmation from
  any vendor, so if the user is asking for another OTP, the only sensible reading is that
  the previous one never showed up, and we should move on regardless of what the first
  vendor reported.
- For **every other kind of message**, only a failure counts. Nothing in those flows tells
  us the message did not arrive, so we should not sideline a vendor that reported success.

If a country has no vendor configuration configured, we fall back to Twilio exactly as today. An empty
table therefore reproduces current behaviour, which makes this safe to deploy before any
configuration exists.

## 2. Goals

1. A country's vendor order lives in the database and is editable in Django admin, so it can
   be changed without a deploy.
2. A vendor whose API errors mid-send is followed by the next vendor for that country.
3. A resend of a one-time password goes to a vendor that has not already been tried for this
   number, preferring the best-ranked one still available. A repeat of any other kind of
   message moves off a vendor only if its last attempt failed.
4. Every send attempt is recorded, so reliability per country and per vendor is reportable.
5. An empty routing table reproduces today's behaviour exactly: Twilio for everything.

## 3. Technical details

### 3.1 System architecture

#### What exists today

The `sms` package was added in [#292](https://github.com/dimagi/connect-id/pull/292) and is
the only way the codebase sends a text message:

```
sms/__init__.py        send_sms()  — the only public entry point
sms/base.py            SmsMessage, SendResult, SmsSendError, BaseSmsVendor
sms/registry.py        VENDORS, DEFAULT_VENDOR, get_vendor()
sms/vendors/twilio.py  TwilioVendor
```

`send_sms` returns early for test phone numbers, then sends through `DEFAULT_VENDOR`. Vendor
selection was deliberately left as a stub:

```python
vendor = DEFAULT_VENDOR  # in future work the vendor will be determined based on the country code
```

This document covers the work described in that comment.

There are four places in the codebase that call `send_sms`, and this design calls each of
them a *purpose*:

| Purpose | Call site | Message |
|---|---|---|
| `otp` | `BasePhoneDevice._send_otp` (`users/models.py`) | The verification code for sign-up and recovery |
| `deactivation` | `ConnectUser.initiate_deactivation` (`users/models.py`) | Confirmation token for deleting an account |
| `credential_invite` | `UserCredential.add_credential` (`users/models.py`) | Link to accept a credential |
| `hq_invite` | `users/views.py` | Invitation from CommCare HQ |

#### What we add

| Component | Responsibility |
|---|---|
| `sms/models.py` → `VendorRoute` | **Configuration.** Maps a country to an ordered list of vendors. Read on every send, written only through Django admin. |
| `sms/models.py` → `SmsLog` | **History.** One row per vendor attempt: which vendor, which number, which purpose, did it work. Read on every send and by reporting; written by the send path. |
| `sms/routing.py` | **Decision logic.** Pure functions that turn a phone number plus a purpose into an ordered list of vendors to try. Knows nothing about how to send. |
| `sms/__init__.py` → `send_sms` | **Orchestration.** Asks `sms/routing.py` for the candidate list, walks it, calls each vendor in turn until one succeeds, and collects the log rows. |
| `sms/admin.py` → `VendorRouteAdmin` | The only user interface: an administrator screen for editing the routing table. |

The split matters for testing: `sms/routing.py` is decision logic with no side effects, so
it can be tested against database fixtures without touching a vendor API.

#### How a send works, end to end

1. **Test numbers return immediately.** A number starting with `TEST_NUMBER_PREFIX` returns
   before any database read or vendor call, and logs nothing. Unchanged from today.
2. **Work out the country.** The `phonenumbers` library (already a dependency) turns the
   phone number into an ISO-3166 alpha-2 country code — the two-letter country code, such as
   `MW` for Malawi.
3. **Read that country's vendor list.** `resolve_chain()` reads the active `VendorRoute` rows
   for the country, drops any naming a vendor the code does not have registered, and returns
   them best rank first. If nothing survives — no country could be determined, no rows exist,
   or no row names a registered vendor — it returns a single-entry list holding
   `DEFAULT_VENDOR`.
4. **Read what this number has already tried.** `tried_vendors()` reads `SmsLog` for this
   phone number and this purpose inside the retry window, and returns the vendor names to
   skip.
5. **Subtract one from the other.** `candidates()` removes the tried vendors from the list. If
   that empties the list — every vendor has been tried — it returns the full list instead, so
   we start over at the best vendor rather than failing.
6. **Walk the list.** Call each vendor in turn. Buffer a log row for each attempt. Stop at the
   first success. If every vendor errors, raise `AllVendorsFailed`.
7. **Write the log rows.**

Throughout this document, **chain** is shorthand for "the ordered list of vendors configured
for a country".

#### Vendor selection rules

A new module, `sms/routing.py`. `ChainEntry` is a frozen dataclass, matching the style of
`sms/base.py`:

```python
@dataclass(frozen=True)
class ChainEntry:
    vendor: str
    vendor_rank: int | None   # None => DEFAULT_VENDOR fallback, no VendorRoute row


def resolve_chain(phone_number) -> list[ChainEntry]:
    """Active, registered vendors for the number's country, best rank first.

    Returns [ChainEntry(DEFAULT_VENDOR, None)] when the number has no country, the
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

Four properties of these rules are worth spelling out.

**Ranking always uses the live configuration.** `tried_vendors` returns vendor *names* only,
never ranks. Ordering comes from re-reading `VendorRoute` on every send. So an administrator
can re-order, insert, delete or deactivate a vendor mid-flow and the next send absorbs the
change: a vendor is skipped because of its name, never because of a rank it used to hold.

**The lookup key is the phone number plus the purpose, bounded by time.** "Already tried"
means by this number, for this purpose, in the last `SMS_VENDOR_RETRY_WINDOW` — a new
setting, `timedelta(hours=4)`, chosen to match the four-hour lifetime of a
`ConfigurationSession` that the OTP flow already runs on.

- *Why the phone number rather than the session or device?* `start_device_configuration` is
  unauthenticated and takes only a phone number. If a user force-quits the app and relaunches
  it, they get a brand-new `ConfigurationSession` and a brand-new `SessionPhoneDevice`. Keyed
  on the device, that user would start with an empty tried-set and be sent straight back to
  the vendor that had just failed them. Keyed on the number, the earlier attempts are still
  inside the window and still count. The tried-set describes whether we can reach *this
  number*, so it should not reset because a different part of the system asked.
- *Why include the purpose?* Without it, a successful credential invitation would push the
  user's next OTP down to the second vendor for the following four hours, for no reason. A
  vendor counts as tried only for the kind of message it was tried on.

**The purpose also decides what counts as "tried".** Two modes, declared per purpose in
`ESCALATE_ON_SUCCESS`:

| Purpose | A vendor is skipped when | Why |
|---|---|---|
| `otp` | it was attempted at all inside the window, success or failure | A resend implies the first OTP never arrived. With no delivery confirmation from the vendor, a `success` row only means the vendor accepted the message for sending |
| everything else | its **most recent** attempt inside the window was not a success | Nothing in these flows tells us a message failed to arrive, so acceptance is the best information we have. A working vendor should not be sidelined over a failure we cannot observe |

**An exclusion lasts until the window passes.** For non-OTP purposes we read the latest row
per vendor rather than "any failure in the window", but this is not a mechanism for
re-testing an excluded vendor: an excluded vendor is not selected, so it writes no newer row,
so nothing overwrites its failure. The one exception is when every vendor in the chain is
excluded — `candidates` falls through to `untried or chain`, the full chain is walked from
the top, the excluded vendor is retried there, and a success rewrites its latest row.
Otherwise a non-OTP vendor that errored stays out for the rest of the window.

That is intended: a vendor that just failed this number should not be first in line again
minutes later. But it does mean `SMS_VENDOR_RETRY_WINDOW` doubles as "how long a single
non-OTP failure sidelines a vendor for this number".

#### Backoff is unchanged

`BaseOTPDevice._attempt_send` already rate-limits resends with exponential backoff: the gate
is `2 ** attempts` minutes since `otp_last_sent`.

**`attempts` continues to count user taps, not vendor attempts.** The entire chain walk
happens inside the single `self._send_otp()` call, and the gate reads only `attempts` and
`otp_last_sent`. So a tap that fails over through three vendors before succeeding still
advances `attempts` by one, and the user's wait between taps stays 2, 4, 8, 16 minutes as it
is today. Counting vendor attempts instead would make the user wait longer the flakier our
vendors are, which punishes them for a problem they did not cause.

#### Writing the log when everything fails

`SmsLog` rows are written by the chain walk, which runs inside the `transaction.atomic()`
block in `_attempt_send`. If every vendor errors, `AllVendorsFailed` propagates out of that
block, Postgres rolls the transaction back, and the log rows go with it — exactly the case we
most want recorded.

So the rows are **buffered in memory** during the walk and written after the transaction
block has finished, on both the success and the failure path. `send_sms` gains a `purpose`
argument and returns a `SendOutcome` carrying the result and the unsaved rows;
`AllVendorsFailed` carries them too:

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

`device` and `user` are stored on each logged row for tracing and reporting only. Neither is
read by the selection logic, which uses `to` and `purpose` alone. The three non-OTP call
sites pass `user` only.

`_send_otp` is defined on `BasePhoneDevice`, which `PhoneDevice` also inherits, so it cannot
pass `self` as the device unconditionally. A property hook keeps the base class generic:

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

`_attempt_send` performs the write. Note that it lives on `BaseOTPDevice`, which the email
OTP devices also inherit, and `BaseEmailOTPDevice._send_otp` sends email and returns `None`.
The write is therefore guarded so the email path is unaffected:

```python
def _attempt_send(self, valid_secs):
    outcome = None
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
                outcome = self._send_otp()     # None for email devices
                self.otp_last_sent = now()
                self.attempts += 1
                self.save()
            else:
                raise RateLimitedError(retry_after)
    except AllVendorsFailed as e:
        SmsLog.objects.bulk_create(e.log_rows)   # device state rolled back; the log survives
        raise
    else:
        if outcome is not None:
            SmsLog.objects.bulk_create(outcome.log_rows)
```

#### Retention

`SmsLog` grows by roughly one row per SMS attempt, so it needs trimming. A new Celery beat
task deletes rows older than 90 days, using the same pattern as
`messaging.tasks.delete_old_messages` (which runs every 24 hours and trims `Message` rows
after 7 days). Rows whose configuration session has already been cleaned up carry a `NULL`
device and are trimmed on the same schedule.


### 3.2 Data model changes

Both new models live in a new `sms/models.py`.

#### `VendorRoute` — configuration

| Field | Type | Purpose |
|---|---|---|
| `country` | `CharField(max_length=2)` | ISO-3166 alpha-2 country code, uppercased in `save()` |
| `vendor` | `CharField(max_length=50)` | `choices` supplied by a callable that reads `registry.VENDORS`, so admin renders a dropdown and adding a vendor to the registry needs no migration |
| `vendor_rank` | `PositiveSmallIntegerField(default=1)` | Try the lowest number first |
| `is_active` | `BooleanField(default=True)` | Removes a vendor from a country's chain without deleting the row and losing its history |

**Data integrity and validation:**

- Unique on `(country, vendor)` — a vendor appears at most once per country.
- Unique on `(country, vendor_rank)`, conditioned on `is_active` — two *active* vendors in one
  country cannot share a rank, but a deactivated row may keep the rank it had.

  ```python
  models.UniqueConstraint(
      fields=["country", "vendor_rank"],
      condition=models.Q(is_active=True),
      name="unique_active_country_vendor_rank",
  )
  ```

- `clean()` rejects a `country` that is not in `phonenumbers.SUPPORTED_REGIONS`.
- `Meta.ordering = ["country", "vendor_rank", "vendor"]`.
- Ranks need not be contiguous. `vendor_rank` only defines an order, so `1, 5, 9` behaves
  identically to `1, 2, 3`, and an administrator can leave gaps to insert vendors later.

#### `SmsLog` — history

One row per **vendor attempt**, not per send, so a failover produces two rows and is visible
in the data.

| Field | Type | Purpose |
|---|---|---|
| `session_phone_device` | `ForeignKey("users.SessionPhoneDevice", null=True, blank=True, on_delete=SET_NULL, related_name="sms_logs")` | Traces an OTP send back to the sign-up or recovery flow that asked for it. `NULL` on every non-OTP send. Not read by vendor selection |
| `user` | `ForeignKey("users.ConnectUser", null=True, blank=True, on_delete=SET_NULL, related_name="sms_logs")` | Lets per-user reporting be a join rather than a phone-number string match. `NULL` on session OTP sends |
| `phone_number` | `PhoneNumberField()` | The number the message went to. Always populated |
| `country` | `CharField(max_length=2, blank=True)` | `""` when the number could not be attributed to a country |
| `vendor` | `CharField(max_length=50)` | Which vendor was attempted |
| `vendor_rank` | `PositiveSmallIntegerField(null=True)` | The vendor's rank **at the time of sending**. `NULL` means the send went through `DEFAULT_VENDOR` because the country had no rows |
| `purpose` | `CharField(choices=Purpose)` | `otp` / `deactivation` / `hq_invite` / `credential_invite` |
| `status` | `CharField(choices=Status)` | `success` / `vendor_error` / `config_error` |
| `vendor_message_id` | `CharField(max_length=100, blank=True)` | From `SendResult` |
| `vendor_error_code` | `CharField(max_length=50, blank=True)` | From `SmsSendError` |
| `created_at` | `DateTimeField(auto_now_add=True)` | |

**Indexes** — `Meta.ordering = ["-created_at"]`, plus three:

| Index | Serves |
|---|---|
| `(phone_number, purpose, created_at)` | The "already tried" lookup, which runs on every send |
| `(country, vendor, created_at)` | Reliability reporting per country and per vendor |
| `(created_at)` | The retention sweep |

**Why both foreign keys, and why the phone number as well.** Neither foreign key is present
on every row, and in practice they are near-opposites:

- `ConfigurationSession` has no user foreign key, and `send_session_otp` never populates
  `SessionPhoneDevice.user`, so there is no `ConnectUser` in scope when a session OTP is sent.
  During registration the account does not exist yet.
- The three non-OTP call sites all hold a `ConnectUser` and have no session OTP device.
- The legacy `PhoneDevice` flows are the one case that has both, since `PhoneDevice.user` is
  non-nullable.

`phone_number` is therefore stored directly on the row rather than reached through either
foreign key: it is the only identifier present on every row, and it is the key the selection
logic looks up.

**Why three statuses rather than success/failure.** `config_error` is an
`ImproperlyConfigured` raised by `get_vendor` — a missing `SMS_VENDORS` entry or credentials
that do not build a client. `vendor_error` is the vendor's own API rejecting the send.
Collapsing the two would charge a deployment mistake against a vendor's measured reliability.
Vendor selection treats them identically, since both mean the vendor did not send, and it
reads `status` at all only for non-OTP purposes.

**Why `vendor_rank` is stored on the log.** It is for reporting only; vendor selection never
reads it. It is a snapshot, so a row stays interpretable after the chain is re-ordered, and
reporting can compare a vendor's performance while it was first choice against its
performance while it was third. Selection always ranks using the `vendor_rank` currently held
in `VendorRoute`.

### 3.3 Failure modes

| Scenario | What the system does | What the user sees |
|---|---|---|
| Vendor 1 errors, vendor 2 accepts | Failover; vendor 1's exception is logged and the next candidate is tried. Two `SmsLog` rows: `vendor_error`, then `success` | The OTP arrives |
| A vendor accepts an OTP it never delivers | Nothing detects it; we have no delivery confirmation. The row reads `success`, but `otp` counts a vendor as tried on success too | No SMS, and the resend goes to an untried vendor |
| A vendor accepts a non-OTP message it never delivers | Nothing detects it. The `success` row leaves the vendor in play | A repeat send goes back to the same vendor |
| Every vendor in the chain errors | `AllVendorsFailed` is raised and left uncaught, producing a Sentry error. `transaction.atomic()` rolls back `attempts` and `otp_last_sent`, but the buffered `SmsLog` rows are taken off the exception and written | The same generic error a Twilio failure gives today. Resend is allowed immediately, with no backoff advance |
| Nothing routable — no country, no active rows (day one, and every unconfigured country), or only rows naming unregistered vendors | Falls through to `DEFAULT_VENDOR`, logged with `vendor_rank = NULL` | Today's behaviour |
| A routed vendor has no `settings.SMS_VENDORS` entry, or bad credentials | `ImproperlyConfigured` is caught and logged as `config_error`; the next candidate is tried | No effect at all if a later candidate succeeds |
| Every configured vendor already tried inside the retry window | The candidate list is empty, so the full chain is reused and rank 1 is tried again | A repeat of the best vendor rather than an error |
| `VendorRoute` edited between two sends | The chain is re-read and ranking uses the new ranks; the tried-set is matched by name | Correct escalation regardless of the edit |
| Process killed mid-send | The buffered rows are lost, but device state is rolled back too, so nothing is half-recorded | Resend allowed immediately |
| A user changes their phone number — legacy path only, since `change_phone` refuses an already-validated number | Historical rows keep the number each message actually went to; `user` still ties them to the person | Nothing. Per-person and per-number history both stay accurate |
| Two overlapping flows on the same number, same purpose | They share a tried-set, so one flow's failures escalate the other | A flow may start further down the chain than its own history implies |
| The user force-quits and relaunches the app after no SMS arrives | A new session and new device, but the earlier attempts are still inside the window, so they still count | The resend reaches an untried vendor rather than resetting to rank 1 |
| The retry window passes with no send | Nothing matches, the tried-set is empty, the chain is walked from rank 1 | A fresh start after four idle hours |
| A send with no session device — a non-OTP purpose, or a legacy `PhoneDevice` flow | `session_phone_device` is `NULL`, but the lookup does not use it: the tried-set is still keyed on number and purpose | A repeated deactivation message goes to a different vendor if the last one errored, the same one if it was accepted |
| A non-OTP vendor errors while the chain still has untried vendors | It stays excluded for the rest of the window; nothing selects it, so nothing clears it | Later sends inside the window start at the next vendor down |
| Every vendor for a non-OTP purpose is excluded | `candidates` falls back to the full chain, so rank 1 is retried; a success rewrites its latest row | The chain resets rather than erroring |
| The `ConfigurationSession` behind a logged device is deleted | `SET_NULL` blanks the foreign key; `phone_number`, `country`, `vendor`, `vendor_rank` and `status` all survive | Nothing; reporting is unaffected |
| Two resends racing on the same device | `select_for_update` serialises them as it does today, but the lock is now held across the whole chain walk rather than one vendor call | The second request blocks until the first has walked its chain before receiving its `RateLimitedError`, where today it returns almost at once. The `retry_after` value it receives is unaffected |

### 3.4 User interface changes

**No mobile or API changes.** No endpoint gains a parameter, changes its response shape, or
changes its authentication. `send_sms` is called entirely from server-side code, and its new
`purpose`, `device` and `user` arguments are supplied at the four internal call sites listed
in 3.1. The API contract for `start_device_configuration`, OTP resend, deactivation,
credential invitations and HQ invitations is unchanged.

**Django admin is the only new interface.** `VendorRouteAdmin` manages the routing table,
authenticated by the existing Django admin staff login. It sets:

- `list_editable = ("vendor_rank", "is_active")`, so re-ranking or disabling a country's
  vendors is done on one list screen without opening each row.
- `vendor` rendered as a dropdown, populated from `registry.VENDORS` via a callable, so the
  choices track the registered vendors without a migration.

`SmsLog` is read-only history. Registering it in admin is optional and, if done, should be
list-and-filter only — no add, change or delete — since editing history would corrupt both the
reliability reporting and vendor selection.

### 3.5 Assumptions and dependencies

**Assumptions about how vendors behave**

- **No vendor gives us delivery confirmation.** A `success` means the vendor's API accepted
  the message, not that it reached the handset. This is the single assumption the OTP rule
  rests on: it is why a successful OTP send still counts the vendor as tried. If delivery
  webhooks are added later, `ESCALATE_ON_SUCCESS` is the one place that would need revisiting.
- **A vendor error means that vendor did not send.** We treat any exception from the vendor's
  API as a reason to try the next one. A vendor that errors *after* having queued the message
  would cause a duplicate SMS. We accept that: a duplicate OTP is a far better outcome than no
  OTP.
- **The country is derivable from the phone number.** Routing uses the international dialling
  code, not the user's physical location. `ConfigurationSession.country_code()` — which derives
  a country from GPS coordinates via Mapbox — exists but is deliberately **not** used here: it
  requires a GPS fix and a `MAPBOX_ACCESS_TOKEN`, is unavailable on non-session sends, and can
  return `None`. The number's dialling code is always present and is what determines which
  network actually has to deliver the message.

**Library and platform dependencies**

- **`phonenumberslite` 9.0.32** (already a dependency, via `django-phonenumber-field`) supplies
  both the country attribution and `SUPPORTED_REGIONS` for validation. No new package.
- **PostgreSQL.** Two pieces of this design are Postgres-specific and have no portable
  equivalent: `.distinct("vendor")` compiles to `DISTINCT ON`, and the conditional unique
  constraint compiles to a partial index. The project runs PostgreSQL 15 in CI and in
  production, so this is a constraint we already live with, but it does rule out a SQLite test
  database.
- **Celery beat** runs the retention sweep, alongside the existing scheduled tasks in
  `connectid/celery_app.py`.
- **Django admin** is the configuration interface. There is no API or management command for
  editing routes, so anyone changing a country's routing needs a staff account.

**Operational constraints**

- **Only Twilio is implemented today.** `registry.VENDORS` has a single entry. This design is
  correct and deployable with a one-entry registry — every chain is length one and behaves
  exactly as today — but the user-facing benefit only arrives once a second vendor is
  implemented, which is separate work under the same epic.
- **The chain walk is synchronous and inside a database lock.** A send that fails over calls
  several vendor APIs in sequence while holding the device row lock, which lengthens the
  request. No explicit HTTP timeout is configured for the Twilio client today, so the worst
  case is bounded only by that library's own defaults. If the chains grow beyond two or three
  vendors, setting explicit per-vendor timeouts should be revisited.
- **`SMS_VENDOR_RETRY_WINDOW` is a new setting**, defaulting to `timedelta(hours=4)`. It is
  tied to the four-hour `ConfigurationSession` lifetime, which is currently hard-coded in
  `ConfigurationSession.save()`. If that lifetime changes, this setting should change with it.
- **`SmsLog` grows with SMS volume** — roughly one row per attempt, more when chains fail over.
  The 90-day retention window and the three indexes are sized for that; a large jump in SMS
  volume would be a reason to revisit both.
