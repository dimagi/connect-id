# SMS vendor routing — design

| Field | Value |
|---|---|
| **Author** | Charl Smit |
| **Epic / Ticket** | [CCCT-2732](https://dimagi.atlassian.net/browse/CCCT-2732) (Design), under epic [CCCT-2734](https://dimagi.atlassian.net/browse/CCCT-2734) "Add additional logic to change SMS vendor by country to increase reliability" |

## 1. Problem

A user wanting to sign up for PersonalID requests an OTP and no SMS arrives.
Their only recourse is to tap resend, which goes through the same vendor that just failed
them so they cannot finish registration or recovery as a result.

We also have no record of which vendor was used for any given send, so there is no way to
tell whether a vendor is failing in a particular country, or to answer that question
retrospectively when a user reports a problem.

## 2. Goals

We want to be able to make use of different SMS vendors for different countries. Each country should have a default vendor and use additional vendors as fallbacks in a predefined, but configurable, vendor order. To decide which country a user is operating from we will look at the country calling code from phone number.

1. A country's vendor order lives in the database and is editable in Django admin, so a
   developer changes it without a deploy.
2. A vendor that errors mid-send is followed by the next vendor in that country's chain.
3. A resend goes to a vendor that has not already been tried for this OTP, preferring the
   highest-priority one available.
4. Every send attempt is recorded, so per-country/per-vendor reliability is reportable.
5. An empty routing table reproduces today's behaviour exactly (i.e. default to Twilio as the global default).

## 3. Solution

### 3.1 Today

```
sms/__init__.py       send_sms()  — the only public entry point
sms/base.py           SmsMessage, SendResult, SmsSendError, BaseSmsVendor
sms/registry.py       VENDORS, DEFAULT_VENDOR, get_vendor()
sms/vendors/twilio.py TwilioVendor
```

`send_sms` skips test
numbers, then sends through `DEFAULT_VENDOR` — a choice deliberately stubbed when `sms/`
landed in [#292](https://github.com/dimagi/connect-id/pull/292):

```python
vendor = DEFAULT_VENDOR  # in future work the vendor will be determined based on the country code
```

This spec builds out the work in the comment.

### 3.2 Proposal

#### Overview

Two tables. `VendorRoute` is configuration: it maps an ISO-3166 alpha-2 country (e.g. `MW`
for Malawi) to an ordered list of vendors, editable in Django admin. `SmsLog` is history:
one row per vendor attempt, recording which vendor was used, where it sat in the chain at
the time, and whether it worked.

On each send, `phonenumbers` (an existing python package used in the code) attributes the
number to a country, and that country's chain is constructed from the `VendorRoute` table.
`SmsLog` then answers *which of those vendors this number has already burned through for
the current OTP*; the remainder are ranked by their **current** priority and the best one
is tried first, falling through to the next on error. A country with no configured
`VendorRoute` falls back to Twilio as the global default, which is why an empty table
reproduces today's behaviour exactly.

The guiding rule is: **always use the vendor we currently believe is most reliable, among
those this number has not already tried.**

#### Data model changes

`sms/models.py:VendorRoute` — configuration:

| Field | Type | Purpose |
|---|---|---|
| `country` | `CharField(max_length=2)` | ISO-3166 alpha-2, uppercased in `save()` |
| `vendor` | `CharField(max_length=50)` | `choices` from a callable reading `registry.VENDORS`, so admin gets a dropdown and adding a vendor churns no migration. |
| `priority` | `PositiveSmallIntegerField(default=1)` | try lowest number first |
| `is_active` | `BooleanField(default=True)` | Pulls a vendor from a chain without deleting the row |

Two unique constraints — `(country, vendor)`, and `(country, priority)` conditioned on
`is_active` — plus `Meta.ordering = ["country", "priority", "vendor"]`. `clean()` rejects a
`country` absent from `phonenumbers.SUPPORTED_REGIONS`.

```python
models.UniqueConstraint(
    fields=["country", "priority"],
    condition=models.Q(is_active=True),
    name="unique_active_country_priority",
)
```

Priorities need not be contiguous - `priority` is only meant to provide
an ordering structure.

`sms/models.py:SmsLog` — history, one row per **vendor attempt** (not per send, so
failover is visible):

| Field | Type | Purpose |
|---|---|---|
| `phone_number` | `PhoneNumberField()` | keys the "already tried" lookup |
| `country` | `CharField(max_length=2, blank=True)` | `""` when the number is not routable |
| `vendor` | `CharField(max_length=50)` | which vendor was attempted |
| `priority` | `PositiveSmallIntegerField(null=True)` | the vendor's priority **at send time**; `NULL` means the send went via `DEFAULT_VENDOR` because the country had no rows |
| `purpose` | `CharField(choices=Purpose)` | `otp` / `deactivation` / `hq_invite` / `credential_invite` |
| `status` | `CharField(choices=Status)` | `success` / `vendor_error` / `config_error` |
| `vendor_message_id` | `CharField(max_length=100, blank=True)` | from `SendResult` |
| `vendor_error_code` | `CharField(max_length=50, blank=True)` | from `SmsSendError` |
| `created_at` | `DateTimeField(auto_now_add=True)` | |

`Meta.ordering = ["-created_at"]`, and three indexes:

| Index | Serves |
|---|---|
| `(phone_number, purpose, created_at)` | the "already tried" lookup on every OTP send |
| `(country, vendor, created_at)` | per-country/per-vendor reporting |
| `(created_at)` | the retention sweep |

`status` distinguishes `config_error` (an `ImproperlyConfigured` from `get_vendor` — a
missing `SMS_VENDORS` entry or bad credentials) from `vendor_error` (the vendor's API
rejected the send). Collapsing the two would depress a vendor's measured reliability for
what is actually a deployment mistake.

`priority` is **reporting only** — routing never reads it. It is a historical snapshot, so
a row stays interpretable after the chain is re-ordered and reporting can ask whether a
vendor performs differently at p1 than at p3. Vendor selection always ranks by the
priority held in `VendorRoute` *now*.

#### Vendor resolution

New module `sms/routing.py`. `ChainEntry` is a frozen dataclass, matching the style of
`sms/base.py`:

```python
@dataclass(frozen=True)
class ChainEntry:
    vendor: str
    priority: int | None   # None => DEFAULT_VENDOR fallback, no VendorRoute row


def resolve_chain(phone_number) -> list[ChainEntry]:
    """Active, registered vendors for the number's country, lowest priority first.

    Returns [ChainEntry(DEFAULT_VENDOR, None)] when the number has no region, the
    country has no active rows, or no active row names a registered vendor.
    """


def tried_vendors(phone_number, since) -> set[str]:
    """Vendor names already attempted for this number's OTP since `since`."""
    return set(
        SmsLog.objects.filter(
            phone_number=phone_number,
            purpose=SmsLog.Purpose.OTP,
            created_at__gte=since,
        ).values_list("vendor", flat=True)
    )


def candidates(chain: list[ChainEntry], tried: set[str]) -> list[ChainEntry]:
    """The chain minus what has already been tried, best priority first."""
    untried = [e for e in chain if e.vendor not in tried]
    return untried or chain   # every vendor exhausted -> start over at p1
```

The send walks the `candidates` list in order, falling through to the next entry when one
errors.

**Ranking is always against the live table.** `tried_vendors` contributes names only. This
is what makes the design immune to chain edits: re-ordering, insertion, deletion and
deactivation are all absorbed by re-reading `VendorRoute`, and a vendor is skipped because
of *what it is*, never because of where it used to sit in the chain.

**The window.** "Already tried" means *since the current OTP token was generated*.
`_attempt_send` owns that boundary, and `valid_secs` is one of its own parameters:

```python
window_start = self.valid_until - timedelta(seconds=valid_secs)
```

`generate_token(valid_secs)` sets `valid_until = now() + valid_secs`, so subtracting it back
recovers the moment the token was made.
Without a boundary the tried-set would be all-time, and any user who had once cycled through
every vendor would fall back to p1 forever.

It also resets itself. `window_start` is computed *after* the regeneration branch, so an
expired token gives `window_start == now()`, no rows can match, and the send starts at p1.
Non-OTP sends pass no window at all, so their tried-set is empty and `candidates` is just the chain in priority order.

**Scope is the phone number, not the device.** The lookup keys on `phone_number` alone, so
a `PhoneDevice` and a `SessionPhoneDevice` for the same number in overlapping windows share
a tried-set. This is deliberate: the
tried-set describes *the number's reachability*, and the same SIM failing on a vendor
should escalate regardless of which flow asked. Scoping per device would need a
`(device_type, device_id)` pair on `SmsLog` that is dead weight on the four non-OTP call
sites.

#### Log durability

`SmsLog` rows are written by the chain walk, which runs inside `_attempt_send`'s
`transaction.atomic()` block. If every vendor errors, `AllVendorsFailed` propagates out of
that block and Postgres rolls it back — which would discard exactly the rows worth keeping. 
So the rows are **buffered in memory during the walk and flushed after the block exits**.

`send_sms` gains a `purpose` argument and returns a `SendOutcome` carrying both the result
and the unsaved rows; `AllVendorsFailed` carries them too, so the total-failure path still
persists:

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
def send_sms(to: PhoneNumber, body: str, purpose: str) -> SendOutcome: ...
```

`_attempt_send` owns the flush:

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
`messaging.tasks.delete_old_messages`

#### UX / UI changes

Django admin only.

`VendorRouteAdmin` sets `list_editable = ("priority", "is_active")` — that is the whole
point: re-prioritising or disabling a country's vendors happens on one screen, without
opening each row.

#### Failure modes

| Scenario | What the system does | What the user sees |
|---|---|---|
| Vendor 1 errors, vendor 2 accepts | Failover; vendor 1's exception is logged and the next candidate is tried. Two `SmsLog` rows: `vendor_error` then `success` | OTP arrives; nothing unusual |
| A vendor accepts a message it never delivers | Nothing — undetectable without delivery webhooks. The row reads `success` | No SMS; the resend goes to an untried vendor |
| Every vendor in the chain errors | `AllVendorsFailed`, uncaught, Sentry error; `transaction.atomic()` rolls back `attempts` and `otp_last_sent`, but the buffered `SmsLog` rows are flushed from the exception and persist | The generic error a Twilio failure gives today; resend allowed at once, no backoff advance |
| Nothing routable — no region, no active rows (day one, every unconfigured country), or only unregistered vendors | Falls to `DEFAULT_VENDOR`, logged with `priority = NULL` | Today's behaviour |
| A routed vendor has no `settings.SMS_VENDORS` entry, or bad credentials | `ImproperlyConfigured` caught, logged as `config_error`; next candidate tried | No effect if a later candidate succeeds |
| Every configured vendor already tried this window | Candidate list is empty, so the full chain is reused and p1 is tried again | A repeat of the best vendor rather than an error |
| `VendorRoute` edited between two sends | Absorbed: the chain is re-read and ranking uses the new priorities, while the tried-set is by name | Correct escalation regardless of the edit |
| Process killed mid-send | Buffered rows are lost; device state is rolled back too, so nothing is half-recorded | Resend allowed at once |
| Two resends racing on one device | `select_for_update` serialises them as today, but the lock is now held across the whole chain walk rather than a single vendor call | The second request blocks for up to `len(chain) × SMS_VENDOR_TIMEOUT_SECONDS` before receiving its `RateLimitedError`, where today it returns almost at once. The `retry_after` value itself is unaffected |

Because the row lock spans the whole send, no competing resend for the same device can read
the tried-set mid-flight, so flushing the log after the block does not expose a stale view.

### 3.3 Example workflow

Malawi is the only configured country; everywhere else falls to `DEFAULT_VENDOR`.

`VendorRoute` table looks like this:
| `country` | `vendor` | `priority` | `is_active` |
|---|---|---|---|
| `MW` | `twilio` | 1 | ✓ |
| `MW` | `vendorB` | 2 | ✓ |

**Send 1 — a user on `+265991234567` requests their first OTP.**

- No token exists, so `is_otp_close_to_expiry` is true
- `tried_vendors` returns `{}` — nothing has been sent in a window that just opened
- `resolve_chain` returns `[twilio(p1), vendorB(p2)]`
- `candidates` is the whole chain, so `get_vendor` is handed `"twilio"`
- Twilio request succeeds
- One buffered row — `twilio`, p1, `otp`, `success` — is flushed after the atomic block
  commits, alongside the existing `attempts` and `otp_last_sent` write

**The backoff schedule is unchanged.** The gate reads only `attempts` and `otp_last_sent`,
and the whole chain walk sits inside the single `_send_otp()` call — so `attempts` advances
once per *send*, never once per vendor tried. (see *Open questions*)

**Send 2 — no SMS arrives, and the user taps resend.** Twilio accepted the message, but
acceptance is not delivery. This is the failure the design exists for.

- Two minutes have passed, clearing the `2**attempts` gate
- `tried_vendors` returns `{"twilio"}`
- `resolve_chain` returns the same two entries — it reads config, not history
- `candidates` drops twilio, leaving `[vendorB(p2)]`
- vendorB succeeds; a row for `vendorB`, p2, `success` is written
- **Net effect:** the resend reached a different vendor, with nothing but the log
  knowing the first attempt happened — not the view, not the user, not `VendorRoute`

**Send 2b — an admin re-orders the chain mid-flow.** Suppose between Send 1 and Send 2 the
chain had become `vendorB(p1), twilio(p2)`. Nothing changes: the tried-set is still
`{"twilio"}` by name, so `candidates` is `[vendorB(p1)]` and vendorB is still chosen. The
same holds if a vendor is inserted, deleted or deactivated — ranking always re-reads the
live table.

**Send 3 — the same user returns a week later.**

- The token has long expired, so `is_otp_close_to_expiry` fires true, the token is
  regenerated and `attempts` resets
- The send goes to twilio — priority 1, the vendor configured as best for Malawi

**Edge paths.**

- **A vendor errors mid-send** — the next candidate is tried, and the user sees one OTP.
  Both attempts are logged, so the next resend skips both
- **A four-vendor chain, reshuffled mid-flow** — `v1` and `v2` have been tried, then an
  admin swaps `v2` and `v4` so the chain reads `v1(1) v4(2) v3(3) v2(4)`. The untried set is
  `{v3, v4}`, ranked by current priority, so `v4` is tried next
- **An unconfigured country** — no rows match, so the chain is `[DEFAULT_VENDOR]` and the
  row logs `priority = NULL`
- **A test number** — returns before any database read or vendor call, and logs nothing

#### Who owns what

| Question | Answered by | Read | Written |
|---|---|---|---|
| Which vendors serve this country, in what order? | `VendorRoute` rows | Every send | Django admin only |
| Which vendors has this number already burned through? | `SmsLog.vendor` over the current token window | Every OTP send | Once per vendor attempt, flushed after the transaction |
| How is a vendor performing, by country? | `SmsLog` aggregates | Reporting | Once per vendor attempt |
| What if the country has no rows? | `settings.DEFAULT_VENDOR` | When resolution yields nothing | Deploy only |

## 4. Open questions

1. The backoff mechanism of today is untouched, so a user will still have to wait `2**attempts` minutes before trying the next vendor. Should the backoff time be made vendor-specific?
2. Should we increase `attempts` based on vendor-tries, or user-tries?
  - A user-try is a user hitting "Send OTP" button
  - A vendor-try is a single vendor attempt
  - Multiple vendors can be tried for a single user-try

## 5. Alternatives considered

#### Store the cursor on the device (`last_sms_vendor`)

An earlier draft added a `last_sms_vendor` column to `BasePhoneDevice`, recording the
vendor that last succeeded, and rotated the chain past that name. It was rejected on
review: a single denormalised field cannot answer any reporting question. `SmsLog`
subsumes it — what has been tried is a read of history rather than a separate piece of
state to keep in sync.

#### Rotate on a position cursor

Two variants were worked through, both keeping a single "where were we" pointer and
stepping one position forward:

- **By logged priority** — read the `priority` recorded on the newest OTP row and take the
  next priority up.
- **By logged vendor** — resolve the logged *vendor* to its `VendorRoute` row at send time
  and step past whatever priority it holds now.

Both were rejected. A position cursor cannot express "we have tried these two, try
something else", which is the actual requirement.

Tracking the tried *set* removes the concept of position altogether: names identify what to
exclude, and the live table ranks what is left.

#### Derive vendor based on attempts
We could derive which vendor should be tried next based on the number of attempts the user has made already, but that approach runs into trouble if a country has 3 vendors configured and during the user's first OTP attempt the first vendor did not succeed, so the algorithm automatically proceeded to the 2nd vendor and succeeded. Assuming the 2nd vendor's SMS did not land, the user hits "Resend OTP" (user's second attempt), so now the algorithm sees that only 1 attempt has been made previously and thus tries the 2nd vendor again, which is exactly what we don't want.

You might think we could just increase `attempts` on a vendor-attempt basis, but that penalizes a user who hit the "Send OTP" button for the first time for up to `2**len(vendors)` minutes in case the whole vendor list is tried during this attempt.

#### Store vendors as ArrayField
Vendors could be stored as an ArrayField against a `country` instead of one record per `(country, vendor)` combination, but the spec outlines some future goals where we want to be able to track success metrics on a per country-vendor basis. Having a model that stores information on the level outlined in this spec (`(country, vendor)` combination) seems like the right move at the moment to best set us up for that future world.
