# SMS vendor service layer

**Ticket:** CCCT-2716
**Status:** for review

Sending an SMS today can happen either through Firebase or PersonalID (using Twilio). This spec will cover only PersonalID SMS.

## Why
PersonalID SMS today uses Twilio, called directly from four places in the code. We want to add
more vendors, because different vendors are needed for delivery in different countries, for failover and cost.

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
- Moving test-number skipping into the layer, and sender-ID lookup onto the vendor.
- No change to when or why any SMS is sent.

Out of scope, to be designed separately:

- **Choosing a vendor by country.** Callers can name a vendor, but none do. They all take the
  default, which is Twilio.
- **Falling back to another vendor when one fails.** A failure stays a failure.
- **Firebase.** The mobile app calls Firebase Phone Auth itself and Firebase sends its own SMS. We
  only see the resulting token. Our Twilio OTP is the fallback when Firebase fails. None of that
  changes.
- **Carrier lookup.** `utils/twilio.py` looks up a phone number's carrier for payment profiles.
  It is not sending, has one caller, and not every SMS vendor offers it. Left as is.
- **Sending in the background.** Sends stay synchronous, in the web request, as they are today.

## Where the new code lives

```
messaging/
  __init__.py           stays empty
  sms/
    __init__.py         send_sms()
    base.py             SmsMessage, SendResult, SmsSendError, BaseSmsVendor
    registry.py         VENDORS, DEFAULT_VENDOR, get_vendor()
    vendors/
      __init__.py       stays empty
      twilio.py         TwilioVendor
```

`send_sms` and `get_sms_sender` are deleted from `utils/__init__.py`. Sender IDs are vendor-specific, so the map moves onto the vendor that registered them.


## The interface

```python
# messaging/sms/base.py

@dataclass(frozen=True)
class SmsMessage:
    to: PhoneNumber
    body: str


@dataclass(frozen=True)
class SendResult:
    vendor: str
    vendor_message_id: str | None
    skipped: bool = False       # true for test numbers


class SmsSendError(Exception):
    def __init__(self, vendor: str, message: str, vendor_error_code: str | None = None):
        super().__init__(f"{vendor}: {message}")
        self.vendor = vendor
        self.vendor_error_code = vendor_error_code


class BaseSmsVendor(ABC):
    name: str

    def send(self, message: SmsMessage) -> SendResult:
        try:
            return self._send(message, self.get_sender(message))
        except SmsSendError:
            raise
        except Exception as e:
            raise SmsSendError(self.name, str(e), self.error_code(e)) from e

    def get_sender(self, message: SmsMessage) -> str | None:
        """Sender ID to send from. None means the vendor picks its own."""
        return None

    def error_code(self, exc: Exception) -> str | None:
        """The vendor's own code for a failure. None if it does not have one."""
        return None

    @abstractmethod
    def _send(self, message: SmsMessage, sender: str | None) -> SendResult:
        """Call the vendor's API. Raise anything; send() converts it."""
```

`send()` does what every vendor needs: resolve the sender ID, and turn whatever the vendor's SDK
raises into one error type. Around that are two hooks a vendor overrides only if it has something to
say — `get_sender()` and `error_code()` — both of which default to "nothing". A new vendor must write
`_send()`; the other two are optional, and a vendor with no registered sender IDs simply ignores the
`sender` argument.

Twilio, which uses both, in full:

```python
# messaging/sms/vendors/twilio.py

class TwilioVendor(BaseSmsVendor):
    name = "twilio"

    # Alphanumeric sender IDs registered with Twilio, by country calling code.
    SENDER_IDS = {"265": "ConnectID", "258": "ConnectID", "232": "ConnectID", "44": "ConnectID"}

    def __init__(self, account_sid: str, auth_token: str, messaging_service: str):
        self._client = Client(account_sid, auth_token)
        self._messaging_service = messaging_service

    def get_sender(self, message: SmsMessage) -> str | None:
        return self.SENDER_IDS.get(str(message.to.country_code))

    def error_code(self, exc: Exception) -> str | None:
        return str(exc.code) if isinstance(exc, TwilioRestException) else None

    def _send(self, message: SmsMessage, sender: str | None) -> SendResult:
        sent = self._client.messages.create(
            body=message.body,
            to=message.to.as_e164,
            from_=sender,
            messaging_service_sid=self._messaging_service,
        )
        return SendResult(vendor=self.name, vendor_message_id=sent.sid)
```

**Sender IDs belong to the vendor, not to the layer.** `"ConnectID"` is an alphanumeric sender ID
registered with *Twilio*. Handing it to a second vendor that has not registered it means the send
is rejected or silently undelivered, which is exactly the kind of failure this layer is supposed to
prevent.

`error_code()` captures the vendor's own failure code — for Twilio, `TwilioRestException.code`
(`21610` unsubscribed, `21614` not a mobile number, `30003` unreachable, and so on). Nothing reads
it yet. It is worth carrying now because it costs one line, it is the input the deferred failover
work needs, and it keeps failures separable in Sentry once every vendor error shares one exception
type.

`to` is a `PhoneNumber`, not a string. The layer needs `raw_input` to spot test numbers and
`country_code` to pick the sender, and a string gives us neither. `.as_e164` is applied in one
place only: inside the vendor, when calling the API.

The public function callers use:

```python
# messaging/sms/__init__.py

def send_sms(to: PhoneNumber, body: str) -> SendResult:
    if (to.raw_input or "").startswith(TEST_NUMBER_PREFIX):
        return SendResult(vendor=None, vendor_message_id=None, skipped=True)
    
    vendor = DEFAULT_VENDOR  # in future work the vendor will be determined based on the country code
    return get_vendor(vendor).send(SmsMessage(to=to, body=body))
```

The test-number check happens here, before any vendor is built.

## Settings

```python
SMS_VENDORS = {
    "twilio": {
        "account_sid": env("TWILIO_ACCOUNT_SID", default=None),
        "auth_token": env("TWILIO_AUTH_TOKEN", default=None),
        "messaging_service": env("TWILIO_MESSAGING_SERVICE", default=None),
    },
}
```

Credentials are grouped per vendor and passed into the vendor when it is built, so each vendor
does not reach into settings itself. The existing `TWILIO_*` variable names are reused, so
nothing needs to change in `.env` or in the Kamal secrets to deploy this.

The flat `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` settings must stay, because the carrier
lookup in `utils/twilio.py` still reads them.

## Building the vendor

`registry.py` maps vendor names to classes, and builds them from the settings above.

```python
# messaging/sms/registry.py

VENDORS: dict[str, type[BaseSmsVendor]] = {
    TwilioVendor.name: TwilioVendor,
}

DEFAULT_VENDOR = TwilioVendor.name


def get_vendor(name: str) -> BaseSmsVendor:
    if name not in VENDORS:
        raise ImproperlyConfigured(f"Unknown SMS vendor {name!r}. Known vendors: {sorted(VENDORS)}")

    config = settings.SMS_VENDORS.get(name)
    if config is None:
        raise ImproperlyConfigured(f"No SMS_VENDORS entry for vendor {name!r}")

    try:
        return VENDORS[name](**config)
    except Exception as e:
        raise ImproperlyConfigured(f"Could not build SMS vendor {name!r} from SMS_VENDORS[{name!r}]: {e}") from e
```

## Adding a new vendor
Adding any new vendor means
1. Adding the vendor's configs to settings, with keys matching its `__init__` arguments
2. Writing its vendor class: `__init__` and `_send`, plus `get_sender` if it has registered sender
   IDs and `error_code` if its SDK reports codes worth keeping
3. Adding one line to `VENDORS` to enable usage


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

## Behaviour changes

Two, both intended:

1. **Credential invites and HQ invites now skip test numbers.** Today only the OTP and
   deactivation flows check for the `+7426` prefix, so the two invite flows send real SMS to test
   numbers. Moving the check into the layer results in these not being sent.
2. **Send failures now arrive as `SmsSendError`** instead of `TwilioRestException`. Nothing catches
   either one, so both end up as a 500 and a Sentry event. Wrapping does collapse every vendor
   failure into a single exception type, which on its own would make Sentry grouping coarser; the
   vendor name and `vendor_error_code` are in the message to keep the distinct failures apart, and
   the original exception stays on `__cause__`.


Nothing else changes. In particular, a failed send must keep rolling back the way it does now:
`BaseOTPDevice._attempt_send` calls the send inside `transaction.atomic()` and only then records
`otp_last_sent` and `attempts`. Because a vendor failure raises, the block rolls back and the user
is not rate-limited out of retrying. A test number returns a result instead of raising, so the
attempt is still recorded, which also matches today.


## Decisions worth a second opinion

- **`vendor_error_code` is captured but not interpreted.** No `retryable` flag: only failover would
  use it, and failover is out of scope. Deciding which Twilio codes are worth retrying is better
  done alongside that work, where it can be tested. Recording the raw code now is what makes that
  decision possible later without a second pass over every vendor.
- **Sender IDs live on the vendor class, not in settings.**
- **Carrier lookup left in `utils/twilio.py`.** Revisit if a second vendor ever needs to serve it.

## Follow-up work this enables

- Choosing a vendor per destination country, and per message type.
- Trying a second vendor when the first fails.
- Storing each send, so delivery and cost can be reported on.