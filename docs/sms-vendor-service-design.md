# SMS vendor service layer

**Ticket:** CCCT-2716
**Status:** for review

## Why

All our server-side SMS today goes through Twilio, called directly from four places in the code. We want to add
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
- Moving sender-ID lookup and test-number skipping into the layer.
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
    senders.py          get_sms_sender()
    registry.py         get_vendor()
    vendors/
      twilio.py         TwilioVendor
```

`send_sms` and `get_sms_sender` are deleted from `utils/__init__.py`.


## The interface

```python
# messaging/sms/base.py

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
        # Exit early for test numbers
        if message.to.raw_input.startswith(TEST_NUMBER_PREFIX):
            return SendResult(vendor=self.name, vendor_message_id=None, skipped=True)

        # Determine message sender
        msg_sender = message.sender or get_sms_sender(message.to.country_code)
        try:
            return self._send(replace(message, sender=msg_sender))
        except SmsSendError:
            raise
        except Exception as e:
            raise SmsSendError(self.name, str(e)) from e

    @abstractmethod
    def _send(self, message: SmsMessage) -> SendResult:
        """Call the vendor's API. Raise anything; send() converts it."""
```

`send()` handles the parts every vendor needs: skipping test numbers, working out the sender ID,
and converting vendor errors into one error type. A new vendor only writes `_send()`. Twilio in
full:

```python
# messaging/sms/vendors/twilio.py

class TwilioVendor(BaseSmsVendor):
    name = "twilio"

    def __init__(self, account_sid: str, auth_token: str, messaging_service: str):
        self._client = Client(account_sid, auth_token)
        self._messaging_service = messaging_service

    def _send(self, message: SmsMessage) -> SendResult:
        sent = self._client.messages.create(
            body=message.body,
            to=message.to.as_e164,
            from_=message.sender,
            messaging_service_sid=self._messaging_service,
        )
        return SendResult(vendor=self.name, vendor_message_id=sent.sid)
```

It takes its credentials as arguments and holds one client. It does not check for test numbers,
look up a sender ID, or catch errors, because `send()` has already dealt with those. That is all a
second vendor has to write.

`to` is a `PhoneNumber`, not a string. The layer needs `raw_input` to spot test numbers and
`country_code` to pick the sender, and a string gives us neither. `.as_e164` is applied in one
place only: inside the vendor, when calling the API.

The public function callers use:

```python
# messaging/sms/__init__.py

def send_sms(to: PhoneNumber, body: str, vendor: str | None = None) -> SendResult:
    return get_vendor(vendor).send(SmsMessage(to=to, body=body))
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


def get_vendor(name: str) -> BaseSmsVendor:
    if name is None:
        # Use twilio as default vendor
        name = "twilio"

    if name not in VENDORS:
        raise ImproperlyConfigured(f"Unknown SMS vendor {name!r}. Known vendors: {sorted(VENDORS)}")

    config = settings.SMS_VENDORS.get(name)
    if config is None:
        raise ImproperlyConfigured(f"No SMS_VENDORS entry for vendor {name!r}")

    return VENDORS[name](**config)
```
## Adding a new vendor
Adding any new vendor means
1. Adding the vendor's configs to settings
2. Writing its vendor class (`init` and `_send`)
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
2. **Errors now arrive as `SmsSendError`** instead of `TwilioRestException`. Nothing catches
   either one, so both end up as a 500 and a Sentry event. The new error names the vendor and
   keeps the original exception attached, so Sentry reports are more useful.

Nothing else changes. In particular, a failed send must keep rolling back the way it does now:
`BaseOTPDevice._attempt_send` calls the send inside `transaction.atomic()` and only then records
`otp_last_sent` and `attempts`. Because a vendor failure raises, the block rolls back and the user
is not rate-limited out of retrying. A test number returns a result instead of raising, so the
attempt is still recorded, which also matches today.


## Decisions worth a second opinion

- **No `retryable` flag on `SmsSendError`.** Only failover would use it, and failover is out of
  scope. Deciding which Twilio errors are worth retrying is better done alongside the failover
  work, where it can be tested.
- **Carrier lookup left in `utils/twilio.py`.** Revisit if a second vendor ever needs to serve it.

## Follow-up work this enables

- Choosing a vendor per destination country, and per message type.
- Trying a second vendor when the first fails.
- Storing each send, so delivery and cost can be reported on.