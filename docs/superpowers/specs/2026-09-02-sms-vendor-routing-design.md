# SMS vendor routing — design

| Field | Value |
|---|---|
| **Author** | Charl Smit |
| **Epic / Ticket** | [CCCT-2732](https://dimagi.atlassian.net/browse/CCCT-2732) (Design), under epic [CCCT-2734](https://dimagi.atlassian.net/browse/CCCT-2734) "Add additional logic to change SMS vendor by country to increase reliability" |

Throughout this document, **vendor** means an SMS provider (Twilio is our only one
today), and **OTP** means the one-time passcode we text to a user to prove they control
a phone number.

## Abstract

PersonalID sends every SMS through a single vendor, Twilio. When an OTP does not reach
the user, tapping "resend" sends it through Twilio again, so a user hitting a Twilio
problem cannot finish registration or account recovery. We also keep no record of which
vendor sent which message, so we cannot tell whether a vendor is failing in a particular
country, or investigate after a user reports a problem. This spec adds two database
tables: one holding an ordered list of vendors per country that staff can edit in Django
admin, and one recording every individual send attempt. On each send the system works out
the country from the recipient's phone number, loads that country's vendor list, removes
any vendor already tried for that number recently, and sends through the best-ranked one
that remains, moving on to the next if a vendor returns an error. A country with no
configuration falls back to Twilio, so the change does nothing until someone configures a
country.

## Problem Statement

Two problems, one of which hides the other.

**Users get stuck.** A user requests an OTP and no SMS arrives. Resend goes through the
same vendor that just failed, so the retry is no more likely to work than the first
attempt. There is no way for the user to get out of this, and registration and recovery
both depend on receiving that OTP.

**We are blind to it.** We do not record which vendor handled a send, so we cannot answer
"is Twilio failing in Malawi this week?" or check what happened to a specific user's
messages. Without that record we cannot justify adding a second vendor, choose which
countries need one, or confirm that adding one helped.

Solving the first without the second means changing routing on guesswork and having no
way to tell whether it worked. Both are in scope here.

The change must also be safe to deploy before any second vendor exists or any country is
configured: on the day it ships, behaviour must be identical to today.

## Proposed solution

### Overview

Think of it as two separate things: a **routing table** that staff configure, and a
**history log** that the system writes.

The routing table, `VendorRoute`, answers "which vendors serve this country, and in what
order?". Each row ties a country to a vendor and gives it a rank — rank 1 is tried first.
Staff edit it in Django admin, so changing a country's vendor order does not need a code
deploy.

The history log, `SmsLog`, answers "what have we already tried, and did it work?". One
row is written per *vendor attempt*, not per message, so when a message falls through two
vendors you see two rows.

On each send, three steps run in order:

1. Work out the recipient's country from the phone number, using the `phonenumbers`
   package the codebase already depends on, and read that country's ranked vendor list.
   We call that list the **chain**.
2. Ask `SmsLog` which vendors this number has already tried recently, for this same kind
   of message, and remove those from the chain.
3. Send through the best-ranked vendor left. If it errors, try the next one down.

The one-sentence rule: **use the highest-ranked vendor for this country that this number
has not already tried recently.** If a country has no rows in the routing table, the
chain is just Twilio, which is exactly what happens today.

### Data model changes

Both tables live in a new `sms/models.py`.

#### `VendorRoute` — the routing table

| Field | Type | Purpose |
|---|---|---|
| `country` | `CharField(max_length=2)` | ISO-3166 alpha-2 code, e.g. `MW` for Malawi. Uppercased in `save()` |
| `vendor` | `CharField(max_length=50)` | The vendor's registered name. `choices` comes from a callable reading `registry.VENDORS`, so admin shows a dropdown and adding a vendor needs no migration |
| `vendor_rank` | `PositiveSmallIntegerField(default=1)` | Lower number is tried first |
| `is_active` | `BooleanField(default=True)` | Takes a vendor out of a country's chain without deleting the row and losing its rank |

Two unique constraints: `(country, vendor)` stops the same vendor being listed twice for
one country, and `(country, vendor_rank)` limited to active rows stops two active vendors
claiming the same position. Limiting the second to active rows means a deactivated row
can keep its old rank while a replacement takes that position.

```python
models.UniqueConstraint(
    fields=["country", "vendor_rank"],
    condition=models.Q(is_active=True),
    name="unique_active_country_vendor_rank",
)
```

`Meta.ordering = ["country", "vendor_rank", "vendor"]`. `clean()` rejects any `country`
not in `phonenumbers.SUPPORTED_REGIONS`. Ranks do not have to be consecutive — `1, 5, 9`
works the same as `1, 2, 3`, because rank only decides the order.

#### `SmsLog` — the history log

One row per vendor attempt.

| Field | Type | Purpose |
|---|---|---|
| `phone_number` | `PhoneNumberField()` | The number the message went to. Always set |
| `country` | `CharField(max_length=2, blank=True)` | `""` when the number could not be attributed to a country |
| `vendor` | `CharField(max_length=50)` | Which vendor was attempted |
| `vendor_rank` | `PositiveSmallIntegerField(null=True)` | The rank that vendor held **at the time of sending**. `NULL` means there was no routing row and the send used the default vendor |
| `purpose` | `CharField(choices=Purpose)` | `otp` / `deactivation` / `hq_invite` / `credential_invite` |
| `status` | `CharField(choices=Status)` | `success` / `vendor_error` / `config_error` |
| `vendor_message_id` | `CharField(max_length=100, blank=True)` | The vendor's own ID for the message, from `SendResult` |
| `vendor_error_code` | `CharField(max_length=50, blank=True)` | The vendor's own error code, from `SmsSendError` |
| `session_phone_device` | `FK("users.SessionPhoneDevice", null=True, on_delete=SET_NULL, related_name="sms_logs")` | Traces an OTP back to the registration or recovery flow that asked for it. `NULL` on every non-OTP send. Not used for routing |
| `user` | `FK("users.ConnectUser", null=True, on_delete=SET_NULL, related_name="sms_logs")` | Lets per-user reporting be a join instead of a phone-number string match. `NULL` on session OTP sends. Not used for routing |
| `created_at` | `DateTimeField(auto_now_add=True)` | |

**Why the phone number is stored on the row rather than read through one of the foreign
keys.** Neither foreign key is set on every row, and they are close to opposites of each
other. `ConfigurationSession` has no link to a user, and `send_session_otp` never fills in
`SessionPhoneDevice.user`, so at the moment a session OTP is sent there is no
`ConnectUser` available — during registration the account does not exist yet. The three
non-OTP send sites all have a `ConnectUser` and no session device. Only the legacy
`PhoneDevice` flows have both, because `PhoneDevice.user` cannot be null. The phone number
is the one identifier present on every row, so it is copied onto the row and the routing
lookup uses it.

`Meta.ordering = ["-created_at"]`, plus three indexes:

| Index | Serves |
|---|---|
| `(phone_number, purpose, created_at)` | The "already tried" lookup, which runs on every send |
| `(country, vendor, created_at)` | Per-country, per-vendor reporting |
| `(created_at)` | The retention cleanup task |

**Why there are two kinds of error.** `config_error` means we could not build the vendor
at all — an `ImproperlyConfigured` from `get_vendor`, caused by a missing `SMS_VENDORS`
entry or bad credentials. `vendor_error` means the vendor's API was reached and rejected
the send. Recording both as one status would make our own deployment mistakes look like
poor vendor reliability. Routing treats them the same, since either way the message did
not go out.

**Why the rank is copied onto the log row.** `SmsLog.vendor_rank` is for reporting only;
routing never reads it. Storing the rank as it was at send time keeps old rows readable
after someone re-orders a chain, and lets reporting compare how a vendor performs when it
is first choice against when it is third. Vendor selection always sorts by the rank
currently in `VendorRoute`.

### How a send picks a vendor

A new module, `sms/routing.py`. `ChainEntry` is a frozen dataclass, matching the style
already used in `sms/base.py`.

```python
@dataclass(frozen=True)
class ChainEntry:
    vendor: str
    vendor_rank: int | None   # None => no VendorRoute row; this is the DEFAULT_VENDOR fallback


def resolve_chain(phone_number) -> list[ChainEntry]:
    """Active, registered vendors for the number's country, lowest rank first.

    Returns [ChainEntry(DEFAULT_VENDOR, None)] when the number has no region, the
    country has no active rows, or no active row names a registered vendor.
    """


# Purposes where even a successful send counts the vendor as tried. "success"
# only means the vendor accepted the message, not that it was delivered, and a
# request for another OTP implies the previous one never arrived.
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
    return untried or chain   # everything tried -> start over at rank 1
```

The send walks the `candidates` list in order and moves to the next entry whenever one
errors.

**Ranking always uses the live table.** `tried_vendors` returns vendor *names* only, never
ranks or positions. That means any edit to a chain — re-ordering, inserting, deleting,
deactivating — is picked up automatically, because the ranks are re-read from
`VendorRoute` on the next send. A vendor is skipped because of its name, never because of
a position it used to hold.

**What "already tried" is scoped to.** It is scoped to the phone number and the message
purpose, within the last `SMS_VENDOR_RETRY_WINDOW`. That is a new setting, set to
`timedelta(hours=4)` to match the `ConfigurationSession` lifetime the OTP flow already
runs on. The scope is the number rather than the user or the session, because what we are
tracking is whether messages are reaching that number — so a vendor failing this number
should be skipped no matter which flow made the earlier attempt.

Scoping to the number also survives the user restarting the app.
`start_device_configuration` needs no authentication and takes only a phone number, so
relaunching the app creates a brand new `ConfigurationSession` and a brand new
`SessionPhoneDevice`. Had we scoped to the device, that user would start again with an
empty history and be sent straight back to the vendor that had just failed them. Scoped to
the number, the earlier attempts are still inside the window and still count.

**Why purpose is part of the scope.** A vendor counts as tried only for the kind of
message it was tried on. Without this, a successful `hq_invite` sent to a user would push
their next OTP down to the second-choice vendor for four hours, for no reason.

**Purpose also decides what counts as "tried".** There are two modes, declared per purpose
in `ESCALATE_ON_SUCCESS`:

| Purpose | A vendor is skipped when | Why |
|---|---|---|
| `otp` | it was attempted at all inside the window, whether it succeeded or failed | A resend tells us the first OTP never arrived. We have no delivery webhooks, so a `success` row only means the vendor accepted the message, not that the user got it |
| everything else | its **most recent** attempt inside the window was not a success | Nothing in these flows tells us a message failed to arrive, so acceptance is the best signal we have. A vendor that is working should not be pushed aside over a failure we cannot see |

Once a vendor is excluded it stays excluded until the window passes. Looking at the latest
row per vendor, rather than "any failure in the window", is not a way of re-testing a
vendor: an excluded vendor is never selected, so it never produces a newer row, so nothing
replaces its failure. The single exception is when every vendor in the chain is excluded —
`candidates` returns `untried or chain`, the full chain is walked from rank 1, the
excluded vendor is retried there, and a success replaces its latest row. Otherwise a
non-OTP vendor that errored stays out for the rest of the window.

That is deliberate — a vendor that just failed this number should not be first choice
again minutes later — but it does mean `SMS_VENDOR_RETRY_WINDOW` doubles as "how long a
single non-OTP failure sidelines a vendor for that number".

### Vendor call timeout

A new setting, `SMS_VENDOR_TIMEOUT_SECONDS = 5`, caps how long any single vendor API call
may take. For Twilio this is passed through as
`Client(..., http_client=TwilioHttpClient(timeout=settings.SMS_VENDOR_TIMEOUT_SECONDS))`;
today `sms/vendors/twilio.py` builds the client with no timeout at all.

This is needed because failover changes how long the database row lock is held.
`_attempt_send` takes a `select_for_update` lock on the device row and, until now, made a
single vendor call inside it. With failover it can make up to one call per vendor in the
chain. Without a per-call cap, one unresponsive vendor could hold that lock indefinitely
and block every concurrent resend for the same device. With the cap, the worst case is
bounded at `len(chain) × SMS_VENDOR_TIMEOUT_SECONDS` — 15 seconds for a three-vendor
chain.

The side effect: a vendor that is working but slower than 5 seconds is treated as an
error. We fail over to the next vendor, write a `vendor_error` row, and sideline it for
the rest of the window. Five seconds is generous next to Twilio's normal sub-second
response, so this should be rare, but it is a real behaviour change and the setting is
tunable per environment.

### Making sure log rows survive a failure

`SmsLog` rows are written by the chain walk, which runs inside the `transaction.atomic()`
block in `_attempt_send`. If every vendor errors, `AllVendorsFailed` propagates out of
that block, Postgres rolls the transaction back, and the log rows would be thrown away —
losing exactly the records we most want. So rows are held in memory during the walk and
written after the block has exited.

`send_sms` gains a `purpose` argument and returns a `SendOutcome` carrying both the result
and the unsaved rows. `AllVendorsFailed` carries them too, so the total-failure path can
still save them.

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

`device` and `user` are stored on each row for tracing and reporting only. Routing reads
neither; it uses `to` and `purpose`. The three non-OTP call sites pass `user` only.

`_send_otp` lives on `BasePhoneDevice`, which `PhoneDevice` also inherits from, so it
cannot pass `self` as the session device unconditionally. A property keeps the base class
generic:

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

`_attempt_send` writes the buffered rows once the transaction has finished, on both the
success and the total-failure path:

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

### Resend backoff is unchanged

`_attempt_send` makes the user wait `2**attempts` minutes between OTP requests. `attempts`
advances **once per user request**, not once per vendor attempted, so a send that tries
two vendors advances it by one.

This keeps today's behaviour: right now `_send_otp()` makes exactly one vendor call, so
`attempts` already advances once per tap. The gate reads only `attempts` and
`otp_last_sent`, and the whole chain walk happens inside the single `_send_otp()` call, so
nothing about the schedule changes.

The alternative — advancing once per vendor attempted — was rejected because it would make
a user wait longer purely because their first vendor errored, which is not their fault and
is invisible to them.

### Retention

`SmsLog` grows by roughly one row per SMS attempt. A Celery task trims it to 90 days,
following the same pattern as `messaging.tasks.delete_old_messages` (that task uses a
7-day cut-off for a different kind of data; 90 days is chosen here to give reporting a
useful window). Rows whose session has since been deleted have a `NULL` device and are
trimmed on the same schedule.

### UX / UI changes

Django admin only; nothing in the mobile app changes.

`VendorRouteAdmin` sets `list_editable = ("vendor_rank", "is_active")`, so re-ranking or
disabling a country's vendors is done from one list screen without opening each row.

### Why this solves the problem

The stuck-user problem is solved because the resend path can no longer return to a vendor
that has just been tried for that number. For OTPs specifically, a vendor is excluded even
when it reported success, which is the case that matters: the common failure is a vendor
accepting a message and silently not delivering it, and without delivery webhooks the
user's decision to tap resend is the only evidence we have that the message did not
arrive. Treating that tap as the signal is what makes the retry land somewhere new.

The blindness problem is solved because one row per attempt, with country, vendor, rank
and outcome, is exactly the shape needed to aggregate reliability by country and vendor,
and to answer questions about a single user's messages. Splitting `config_error` from
`vendor_error` keeps our own misconfiguration out of vendor reliability figures.

The change is safe to ship because an empty `VendorRoute` table produces a one-entry chain
containing the default vendor, which is the code path that runs today. Behaviour changes
only for countries someone has explicitly configured, one country at a time, without a
deploy.

It stays correct under configuration change because history is recorded by vendor name and
ordering is always read live. An admin re-ordering a chain between two sends cannot cause
a vendor to be retried or wrongly skipped.

### Worked example

Malawi is the only configured country; every other country falls back to the default
vendor.

| `country` | `vendor` | `vendor_rank` | `is_active` |
|---|---|---|---|
| `MW` | `twilio` | 1 | ✓ |
| `MW` | `vendorB` | 2 | ✓ |

**Send 1 — a user on `+265991234567` requests their first OTP.**

- No token exists yet, so `is_otp_close_to_expiry` is true
- `tried_vendors` returns an empty set — no OTP has gone to this number in the last four hours
- `resolve_chain` returns `[twilio(rank 1), vendorB(rank 2)]`
- `candidates` is the whole chain, so `get_vendor` is handed `"twilio"`
- The Twilio request succeeds
- One buffered row — `twilio`, rank 1, `otp`, `success`, linked to this
  `SessionPhoneDevice` — is written after the atomic block commits, alongside the existing
  `attempts` and `otp_last_sent` update

**Send 2 — no SMS arrives and the user taps resend.** Twilio accepted the message but
never delivered it.

- Two minutes have passed, clearing the `2**attempts` gate
- `tried_vendors` returns `{"twilio"}` — the row written two minutes ago for this number
  and purpose
- `resolve_chain` returns the same two entries; it reads configuration, not history
- `candidates` drops twilio, leaving `[vendorB(rank 2)]`
- vendorB succeeds, and a row for `vendorB`, rank 2, `success` is written
- The resend reached a different vendor. Only `SmsLog` knows about the first attempt — the
  view, the user and `VendorRoute` are all unchanged

**Send 2b — an admin re-orders the chain in between.** Suppose between Send 1 and Send 2
the chain became `vendorB(rank 1), twilio(rank 2)`. Nothing changes: the already-tried set
is still `{"twilio"}` by name, so `candidates` is `[vendorB(rank 1)]` and vendorB is still
chosen. The same holds if a vendor is added, deleted or deactivated, because ranking always
re-reads the live table.

**Send 3 — the same user returns a week later.**

- The week-old rows are outside the four-hour window, so nothing is excluded. They stay on
  file for reporting
- The token expired long ago, so it is regenerated and `attempts` resets
- The send goes to twilio at rank 1 for Malawi

### Situations worth spelling out

| Scenario | What the system does | What the user sees |
|---|---|---|
| Vendor 1 errors, vendor 2 accepts | Fails over; vendor 1's exception is logged and the next candidate tried. Two `SmsLog` rows: `vendor_error` then `success` | The OTP arrives |
| A vendor accepts an OTP it never delivers | Nothing detects it — we have no delivery webhooks. The row reads `success`, but `otp` counts a vendor as tried even on success | No SMS, but the resend goes to a different vendor |
| A vendor accepts a non-OTP message it never delivers | Nothing detects it, and the `success` row leaves the vendor in play | A repeat send goes to the same vendor |
| Every vendor in the chain errors | `AllVendorsFailed` is raised and not caught, so Sentry records it. The transaction rolls back `attempts` and `otp_last_sent`, but the buffered `SmsLog` rows are taken off the exception and saved | The same generic error a Twilio failure gives today. Resend is allowed immediately, with no backoff increase |
| Nothing routable — the number has no country, the country has no active rows (which is every country on day one), or its rows name only unregistered vendors | Falls back to the default vendor, logged with `vendor_rank = NULL` | Exactly today's behaviour |
| A routed vendor has no `settings.SMS_VENDORS` entry, or bad credentials | `ImproperlyConfigured` is caught and logged as `config_error`; the next candidate is tried | No effect, as long as a later candidate succeeds |
| A vendor takes longer than `SMS_VENDOR_TIMEOUT_SECONDS` | The call is aborted and treated as a `vendor_error`; the next candidate is tried | Usually nothing, but a healthy-but-slow vendor is sidelined for the window |
| Every configured vendor has already been tried inside the window | The candidate list is empty, so the full chain is reused and rank 1 is tried again | The best vendor is retried rather than the send failing |
| `VendorRoute` is edited between two sends | The chain is re-read and the new ranks are used; the already-tried set is matched by name | Correct behaviour regardless of the edit |
| The process is killed mid-send | Buffered rows are lost, but device state is rolled back too, so nothing is half-recorded | Resend allowed immediately |
| A four-vendor chain is reshuffled mid-flow | `v1` and `v2` have been tried, then an admin swaps `v2` and `v4` so the chain reads `v1(1) v4(2) v3(3) v2(4)`. The untried set `{v3, v4}` is ranked by current rank, so `v4` is next | The next best untried vendor, as intended |
| A user changes their phone number (legacy path only — `change_phone` refuses a validated number) | Old rows keep the number each message actually went to, and `user` still ties them to the person | Nothing; both per-person and per-number history stay accurate |
| Two flows run at once on the same number and purpose | They share one already-tried set, so one flow's failures push the other down the chain | A flow may start further down than its own history suggests |
| The user force-quits and relaunches the app after no SMS arrives | A new session and device are created, but the earlier attempts are still inside the window and still count | The resend reaches an untried vendor instead of resetting to rank 1 |
| A send with no session device — any non-OTP message, or a legacy `PhoneDevice` flow | `session_phone_device` is `NULL`, but routing does not use it; the lookup is still by number and purpose | A repeated deactivation SMS goes to a different vendor if the last one errored, the same one if it was accepted |
| A non-OTP vendor errors while untried vendors remain | It stays excluded for the rest of the window; nothing selects it, so nothing clears it | Later sends in the window start one vendor further down |
| Every vendor for a non-OTP purpose is excluded | `candidates` falls back to the full chain and rank 1 is retried; a success replaces its latest row | The chain resets rather than erroring |
| The `ConfigurationSession` behind a logged device is deleted | `SET_NULL` blanks the foreign key; `phone_number`, `country`, `vendor`, `vendor_rank` and `status` all survive | Nothing; reporting is unaffected |
| A test number | Returns before any database read or vendor call, and logs nothing | Unchanged |

### Who owns what

| Question | Answered by | Read | Written |
|---|---|---|---|
| Which vendors serve this country, in what order? | `VendorRoute` rows | Every send | Django admin only |
| Which vendors has this number already tried? | `SmsLog.vendor` for this number and purpose inside `SMS_VENDOR_RETRY_WINDOW` — every attempt for `otp`, only latest-attempt failures otherwise | Every send | Once per vendor attempt, after the transaction |
| How is a vendor performing, by country? | `SmsLog` aggregates | Reporting | Once per vendor attempt |
| What happens if a country has no rows? | `settings.DEFAULT_VENDOR` | When resolution finds nothing | Deploy only |

### Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Concurrent resends on one device now wait behind a longer lock, because the `select_for_update` lock is held across the whole chain walk instead of one vendor call | A second request can block for up to `len(chain) × SMS_VENDOR_TIMEOUT_SECONDS` before getting its `RateLimitedError`, where today it returns almost immediately. The `retry_after` value itself is unaffected | `SMS_VENDOR_TIMEOUT_SECONDS = 5` bounds it at 15s for a three-vendor chain. Chains are expected to be 2–3 vendors |
| A 5-second cap may cut off a vendor that is slow but working | An unnecessary failover, a misleading `vendor_error` row, and that vendor sidelined for the window | The cap is a setting and can be raised per environment. `SmsLog` makes the pattern visible — a spike in timeouts for one vendor is reportable |
| We cannot tell "accepted" from "delivered" without delivery webhooks | Reliability figures overstate how well vendors do, and non-OTP messages that vanish are never detected | Accepted as a known limitation. For OTPs the user's resend acts as the missing signal. Delivery webhooks are separate future work |
| Admin edits change live routing with no deploy or review step | A bad rank or an accidental deactivation misroutes real traffic immediately | Database constraints block duplicate vendors and duplicate active ranks, and `clean()` blocks invalid countries. An empty or broken chain falls back to the default vendor rather than failing |
| Buffered log rows are lost if the process dies mid-send | A gap in reliability data | Device state is rolled back in the same case, so nothing is left half-recorded. Losing a row in a crash is preferable to holding the whole send open for a separate write |
| A single non-OTP failure sidelines a vendor for that number for four hours | A working vendor is skipped for longer than needed | Deliberate. The fallback to the full chain when everything is excluded means it can never block a send outright |
| `SmsLog` grows with SMS volume, and three indexes grow with it | Table and index bloat | 90-day retention sweep on a `created_at` index, following the existing `delete_old_messages` pattern |
