# SMS vendor routing — design

| Field | Value |
|---|---|
| **Author** | Charl Smit |
| **Epic / Ticket** | [CCCT-2732](https://dimagi.atlassian.net/browse/CCCT-2732) (Design), under epic [CCCT-2734](https://dimagi.atlassian.net/browse/CCCT-2734) "Add additional logic to change SMS vendor by country to increase reliability" |

## 1. Problem

A user wanting to sign up for PersonalID requests an OTP and no SMS arrives.
Their only recourse is to tap resend, which goes through the same vendor that just failed
them so they cannot finish registration or recovery as a result. 

## 2. Goals

We want to be able to make use of different SMS vendors for different countries. Each country should have a default vendor and use additional vendors as fallbacks in a predefined, but configurable, vendor order. To decide which country a user is operating from we will look at the country calling code from phone number.

1. A country's vendor order lives in the database and is editable in Django admin, so a
   developer changes it without a deploy.
2. A vendor that errors mid-send is followed by the next vendor in that country's chain.
3. A resend starts at the vendor *after* the one that was last used.
4. An empty routing table reproduces today's behaviour exactly (i.e. default to Twilio as the global default).

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
We add a vendor routing table (`VendorRoute`) which resolves the vendor "chain" based on the phone number. `VendorRoute` maps an ISO-3166 alpha-2 country (e.g. `MW` for Malawi) to an ordered
list of vendors, editable in Django admin. 

On each send, `phonenumbers` (an existing python package used in the code) attributes the number
to a country, that country's chain is constructed from the `VendorRoute` table, and the vendors are tried in order
until one succeeds (i.e. does not return an error code). The OTP device table (`BasePhoneDevice`) records which vendor last succeeded (`last_sms_vendor`), so a resend begins at the
*next* one (**escalation**). A country with no configured `VendorRoute` falls back to Twilio as the global default, which is
why an empty table reproduces today's behaviour exactly.

#### Data model changes

`sms/models.py:VendorRoute`:

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


Two migrations will be needed:
1. `sms/0001_initial` creates `sms_vendorroute`, empty
2. One in `users/migrations/` adds `last_sms_vendor` to `phonedevice` and `sessionphonedevice`
(`BasePhoneDevice` is abstract, so each concrete table gets its own column; email tables are
untouched). **No backfill** — an empty table is the correct day-one state, and the field
defaults to `""`, which `_rotate` reads as "start at priority 1".


#### UX / UI changes

Django admin only.

`VendorRouteAdmin` sets `list_editable = ("priority", "is_active")` — that is the whole
point: re-prioritising or disabling a country's vendors happens on one screen, without
opening each row.

#### Failure modes

| Scenario | What the system does | What the user sees |
|---|---|---|
| Vendor 1 errors, vendor 2 accepts | Failover; vendor 1's exception is logged and the next vendor is tried | OTP arrives; nothing unusual |
| A vendor accepts a message it never delivers | Nothing — undetectable without webhooks or user retries | No SMS; the resend starts at the next vendor |
| Every vendor in the chain errors | `AllVendorsFailed`, uncaught, Sentry error; `transaction.atomic()` rolls back `attempts`, `otp_last_sent` and `last_sms_vendor` | The generic error a Twilio failure gives today; resend allowed at once, no backoff advance |
| Nothing routable — no region, no active rows (day one, every unconfigured country), or only unregistered vendors | Falls to `DEFAULT_VENDOR`; | Today's behaviour |
| A routed vendor has no `settings.SMS_VENDORS` entry, or bad credentials | `ImproperlyConfigured` caught; next vendor tried | No effect if a later vendor succeeds |
| Two resends racing on one device | `select_for_update` serialises them as today, but the lock is now held across the whole chain walk rather than a single vendor call | The second request blocks for up to `len(chain) × SMS_VENDOR_TIMEOUT_SECONDS` before receiving its `RateLimitedError`, where today it returns almost at once. The `retry_after` value itself is unaffected |

### 3.3 Example workflow

Assume the following functions exist:
```
def resolve_chain(phone_numer) -> List[Vendor]
   """Determine the vendor chain for a given phone_number based on the country calling code"""

def _rotate(vendors: List[Vendor], previous_vendor: str| None) -> List[Vendor]
   """Rotates the list so the next vendor takes priority based on the previous vendor"""
```

Malawi is the only configured country; everywhere else falls to `DEFAULT_VENDOR`.

`VendorRoute` table looks like this:
| `country` | `vendor` | `priority` | `is_active` |
|---|---|---|---|
| `MW` | `twilio` | 1 | ✓ |
| `MW` | `vendorB` | 2 | ✓ |

**Send 1 — a user on `+265991234567` requests their first OTP.**

- `last_sms_vendor` on the OTP device is empty
- `resolve_chain` is invoked to get the vendor chain in priority → `["twilio", "vendorB"]`
- `_rotate` is called to see which vendor should be tried, but does nothing to the chain since `previous_vendor` is empty (`last_sms_vendor` is empty)
- `get_vendor` is handed the head of the chain (i.e. `"twilio"`)
- Twilio request succeeds
- `last_sms_vendor` becomes `"twilio"`, and the existing commit persists it alongside `attempts` and `otp_last_sent`

**The backoff schedule is unchanged.** The gate reads only `attempts` and `otp_last_sent`,
and the whole chain walk sits inside the single `_send_otp()` call — so `attempts` advances
once per *send*, never once per vendor tried. (see *Open questions*)

**Send 2 — no SMS arrives, and the user taps resend.** Twilio accepted the message, but
acceptance is not delivery. This is the failure the design exists for.

- Two minutes have passed, clearing the `2**attempts` gate
- `last_sms_vendor = "twilio"`
- `resolve_chain` returns the same two vendors — it reads config, not history
- `_rotate` gets passed `previous_vendor="twilio"` and moves the chain past twilio → `["vendorB", "twilio"]`
- vendorB succeeds, and `last_sms_vendor` becomes `"vendorB"`
- **Net effect:** the resend reached a different vendor, with nothing but that one field
  knowing the first attempt happened — not the view, not the user, not `VendorRoute`

**Send 3 — the same user returns a week later.**

- The token has long expired, so the `is_otp_close_to_expiry` fires true and clears `last_sms_vendor`
- `previous_vendor` is `None` again, so the chain is not rotated
- The send goes to twilio — priority 1, the vendor configured as best for Malawi
- **Why it matters:** without the reset the user would start at vendorB and
  `priority` would stop meaning anything for first sends

**Edge paths.**

- **A vendor errors mid-send** — the next vendor in the chain is tried, and the user sees one
  OTP. `last_sms_vendor` records the vendor that *succeeded*, so the next resend moves past it
  rather than retrying it
- **An unconfigured country** — no rows match, so the chain is `[DEFAULT_VENDOR]`
- **A test number** — returns before any database read or vendor call

#### Who owns what

| Question | Answered by | Read | Written |
|---|---|---|---|
| Which vendors serve this country, in what order? | `VendorRoute` rows | Every send | Django admin only |
| Where is this device in the chain? | `BasePhoneDevice.last_sms_vendor` | Every send | After each attempt that returns a result; cleared when a new token is generated |
| What if the country has no rows? | `settings.DEFAULT_VENDOR` | When resolution yields nothing | Deploy only |

### 4. Open questions

1. The backoff mechanism of today is untouched, so a user will still have to wait `2**attempts` minutes before trying the next vendor. Should the backoff time be made vendor-specific?
2. Should we increase `attempts` based on vendor-tries, or user-tries?
  - A user-try is a user hitting "Send OTP" button
  - A vendor-try is a single vendor attempt
  - Multiple vendors can be tried for a single user-try 

### 5. Alternatives considered

#### Derive vendor based on attempts
We could derive which vendor should be tried next based on the number of attempts the user has made already, but that approach runs into trouble if a country has 3 vendors configured and during the user's first OTP attempt the first vendor did not succeed, so the algortihm automatically proceeded to the 2nd vendor and succeeded. Assuming the 2nd vendor's SMS did not land, the user hits "Resend OTP" (user's second attempt), so now the algorithm sees that only 1 attempt has been made previously and thus tries the 2nd vendor again, which is exactly what we don't want.

You might think we could just increase `attempts` on a vendor-attempt basis, but that penalizes a user who hit the "Send OTP" button for the first time for up to `2**len(vendors)` minutes in case the whole vendor list is tried during this attempt.  

#### Store vendors as ArrayField
Vendors could be stored as an ArrayField against a `country` instead of one record per `(country, vendor)` combination, but the spec outlines some future goals where we want to be able to track success metrics on a per country-vendor basis. Having a model that stores information on the level outlined in this spec (`(country, vendor)` combination) seems like the right move at the moment to best set us up for that future world.
