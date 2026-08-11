# SMS vendor service layer

**Ticket:** CCCT-2716
**Status:** for review

## Why

All our SMS goes through Twilio, called directly from four places in the code. We want to add
more vendors, because different vendors are needed for delivery in different countries, for
failover, for cost, and because some countries require a local sender.

This change does not add a second vendor. It puts a service layer between our code and Twilio so
that adding one later is a small, contained change.

## What we send today

Nine flows send SMS. They fall into two groups:

| Group | Flows | Content |
| --- | --- | --- |
| Verification codes | 6 OTP flows + the account deactivation token | A short code |
| Links | Credential invite, CommCare HQ invite | A URL the user taps |

All nine go through one function, `utils.send_sms`, and one Twilio messaging service.

## Scope

In scope:

- A vendor interface, with Twilio as the first vendor behind it.
- Moving sender-ID lookup and test-number skipping into the layer.
- No change to when or why any SMS is sent.

Out of scope, to be designed separately:

- **Choosing a vendor by country.** For now one vendor is active, set in settings.
- **Falling back to another vendor when one fails.** A failure stays a failure.
- **Firebase.** The mobile app calls Firebase Phone Auth itself and Firebase sends its own SMS. We
  only see the resulting token. Our Twilio OTP is the fallback when Firebase fails. None of that
  changes.
- **Carrier lookup.** `utils/twilio.py` looks up a phone number's carrier for payment profiles.
  It is not sending, has one caller, and not every SMS vendor offers it. Left as is.
- **Sending in the background.** Sends stay synchronous, in the web request, as they are today.

## Where the code lives

```
messaging/
  __init__.py           stays empty
  sms/
    __init__.py         send_sms()
    base.py             SmsMessage, SendResult, SmsSendError, BaseSmsVendor
    senders.py          get_sms_sender()
    registry.py         get_vendor()
    vendors/
      twilio.py         TwilioVendor
```

`send_sms` and `get_sms_sender` are deleted from `utils/__init__.py`.

`base.py` needs `TEST_NUMBER_PREFIX`, which it imports from `users/const.py`. That file imports
nothing itself, so `users` and `messaging` do not end up importing each other.

## The interface

```python
@dataclass(frozen=True)
class SmsMessage:
    to: PhoneNumber
    body: str
    sender: str | None = None   # filled in by the layer, not by callers


@dataclass(frozen=True)
class SendResult:
    vendor: str
    vendor_message_id: str | None
    skipped: bool = False       # true for test numbers


class SmsSendError(Exception):
    def __init__(self, vendor: str, message: str):
        super().__init__(message)
        self.vendor = vendor


class BaseSmsVendor(ABC):
    name: str

    def send(self, message: SmsMessage) -> SendResult:
        if message.to.raw_input.startswith(TEST_NUMBER_PREFIX):
            return SendResult(vendor=self.name, vendor_message_id=None, skipped=True)

        resolved = message.sender or get_sms_sender(message.to.country_code)
        try:
            return self._send(replace(message, sender=resolved))
        except SmsSendError:
            raise
        except Exception as e:
            raise SmsSendError(self.name, str(e)) from e

    @abstractmethod
    def _send(self, message: SmsMessage) -> SendResult:
        """Call the vendor's API. Raise anything; send() converts it."""
```

`send()` handles the parts every vendor needs: skipping test numbers, working out the sender ID,
and converting vendor errors into one error type. A new vendor only writes `_send()`.

`to` is a `PhoneNumber`, not a string. The layer needs `raw_input` to spot test numbers and
`country_code` to pick the sender, and a string gives us neither. `.as_e164` is applied in one
place only: inside the vendor, when calling the API.

The public function callers use:

```python
def send_sms(to: PhoneNumber, body: str) -> SendResult:
    return get_vendor().send(SmsMessage(to=to, body=body))
```

## Settings

```python
SMS_VENDORS = {
    "twilio": {
        "account_sid": env("TWILIO_ACCOUNT_SID", default=None),
        "auth_token": env("TWILIO_AUTH_TOKEN", default=None),
        "messaging_service": env("TWILIO_MESSAGING_SERVICE", default=None),
    },
}
SMS_DEFAULT_VENDOR = env("SMS_DEFAULT_VENDOR", default="twilio")
```

Credentials are grouped per vendor and passed into the vendor when it is built, so each vendor
does not reach into settings itself. The existing `TWILIO_*` variable names are reused, so
nothing needs to change in `.env` or in the Kamal secrets to deploy this.

The flat `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` settings must stay, because the carrier
lookup in `utils/twilio.py` still reads them.

`get_vendor()` builds the vendor once per process and caches it, instead of building a new Twilio
client on every send. When a test overrides either setting, Django's `setting_changed` signal
clears the cache so the next send picks up the new config.

An unknown vendor name, or a vendor with no entry in `SMS_VENDORS`, raises
`ImproperlyConfigured`.

## What changes at the call sites

Four places call `send_sms`. Each one loses the test-number check and the sender lookup, and
passes the phone number object instead of the E.164 string.

| Where | Flow |
| --- | --- |
| `users/models.py:90-92` | Deactivation token |
| `users/models.py:196-198` | `BasePhoneDevice._send_otp`, used by all 6 OTP flows |
| `users/models.py:298-299` | Credential invite |
| `users/views.py:802-803` | HQ invite |

Before:

```python
if not self.phone_number.raw_input.startswith(TEST_NUMBER_PREFIX):
    sender = get_sms_sender(self.phone_number.country_code)
    send_sms(self.phone_number.as_e164, self.otp_message, sender)
```

After:

```python
send_sms(self.phone_number, self.otp_message)
```

Existing tests that patch `users.models.send_sms` keep working, because that module still imports
the name. Only where it comes from changes.

## Behaviour changes

Two, both intended:

1. **Credential invites and HQ invites now skip test numbers.** Today only the OTP and
   deactivation flows check for the `+7426` prefix, so the two invite flows send real SMS to test
   numbers. Moving the check into the layer fixes that.
2. **Errors now arrive as `SmsSendError`** instead of `TwilioRestException`. Nothing catches
   either one, so both end up as a 500 and a Sentry event. The new error names the vendor and
   keeps the original exception attached, so Sentry reports are more useful.

Nothing else changes. In particular, a failed send must keep rolling back the way it does now:
`BaseOTPDevice._attempt_send` calls the send inside `transaction.atomic()` and only then records
`otp_last_sent` and `attempts`. Because a vendor failure raises, the block rolls back and the user
is not rate-limited out of retrying. A test number returns a result instead of raising, so the
attempt is still recorded, which also matches today.

## Testing

- Test numbers return a skipped result and never reach the vendor.
- Sender ID is `ConnectID` for country codes 265, 258, 232 and 44, and unset otherwise.
- A vendor error is converted to `SmsSendError`, with the original error attached.
- The Twilio vendor passes the expected arguments to `Client()` and `messages.create()`. This
  keeps the existing check that a major Twilio upgrade fails CI. It also asserts `to` is a string,
  which is the mistake that broke the earlier attempt at this work.
- A failed send leaves `otp_last_sent`, `attempts` and `token` unchanged in the database.
- The two invite flows make no vendor call for a test number. These fail on `main` today.

New tests go in `messaging/test_sms.py`. `utils/tests/test_sms.py` is removed and its Twilio
checks move across.

## Earlier attempt

Commit `2bb227f` (May 2025) moved SMS sending into `messaging` and was reverted the next morning
by `2164f36`. Two things went wrong, and this design avoids both:

- `send_sms` was typed to take a `PhoneNumber` but every caller passed `phone_number.as_e164`, a
  string. Every send would have failed with `AttributeError`. Hence the test above that pins the
  types at the boundary.
- The function lived in `messaging/__init__.py`, the app's own init file, and imported
  `phonenumber_field` at startup. That risks Django app-loading errors and makes `users` and
  `messaging` import each other. The new code goes in `messaging/sms/`, and
  `messaging/__init__.py` stays empty.

Leftover `__pycache__` directories from that revert still sit in `messaging/providers/` and
`messaging/tests/`. They are not in git but are worth deleting locally, as they look like real
code.

## Decisions worth a second opinion

- **No `sender` argument on `send_sms`.** After this change no caller passes one, so it was
  dropped. Adding it back later is a one-line change.
- **No `retryable` flag on `SmsSendError`.** Only failover would use it, and failover is out of
  scope. Deciding which Twilio errors are worth retrying is better done alongside the failover
  work, where it can be tested.
- **`SendResult` is returned but not used yet.** Kept deliberately, so that recording which vendor
  sent which message does not mean changing the interface again.
- **Carrier lookup left in `utils/twilio.py`.** Revisit if a second vendor ever needs to serve it.

## Follow-up work this enables

- Choosing a vendor per destination country, and per message type.
- Trying a second vendor when the first fails.
- Storing each send, so delivery and cost can be reported on.
- A known inconsistency to fix separately: `start_configuration` returns `otp_fallback: true` for
  every v2 session (commit `88348ec`), but `send_session_otp` still rejects sessions that are not
  invited users (`users/views.py:972-974`). Those sessions are told the fallback exists but cannot
  use it.
