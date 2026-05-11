# Email OTP Verification — Tech Spec

**Epic:** CCCT-2203
**Ticket:** CCCT-2371
**Feature Release Path:** Path 3 — Iterative Product Area
**Release Switch:** Required (django-waffle flag)

---

## Introduction

PersonalID users currently have no way to associate a verified email address with their account. This feature adds two new API endpoints — `POST /users/send_email_otp` and `POST /users/verify_email_otp` — that allow a logged-in user to verify ownership of an email address via a one-time code. Once verified, the email is stored on the user's account. The `POST /users/start_configuration` endpoint is updated to surface any previously verified email to the mobile client so it can be pre-filled or displayed during configuration flows.

---

## Solution

### Current Solution

There is no email verification flow in the system today. The `ConnectUser` model inherits an `email` field from Django's `AbstractUser`, but it is not used anywhere in the application. All identity verification is phone-based (Twilio SMS OTP). The `start_configuration` response does not include any email data.

### Proposed Solution

#### Overview

Two new authenticated endpoints are added to the `users` app. They serve two distinct flows:

- **Sign-up flow** — the user optionally verifies an email during onboarding, before a `ConnectUser` account exists. Authentication uses a `ConfigurationSession` Bearer token (the same token returned by `start_configuration` and used by `complete_profile`), via `SessionTokenAuthentication`.
- **Post-registration flow** — an already-registered user verifies or updates their email. Authentication uses an OAuth2 Bearer token, via `OAuth2Authentication` (already the default in `REST_FRAMEWORK` settings).

Both flows use identical request/response payloads. The feature is gated behind a django-waffle flag (`email_otp_verification`) to allow a phased rollout.

Email delivery uses **`django-anymail[amazon-ses]`** with Amazon SES as the backend in production — the same setup used by commcare-connect. In local/dev environments the backend falls back to Django's console email backend. Since connect-id already uses AWS (S3 for photo storage), SES reuses the same AWS credentials and IAM role without additional vendor setup. A new `send_email_otp_message()` utility will wrap Django's `send_mail()`, called inline within `generate_challenge()` so that delivery failures surface immediately as a request error rather than silently succeeding.

The OTP mechanism mirrors the existing phone OTP pattern: a new `EmailOTPDevice` model extends `django-otp`'s `SideChannelDevice`, reusing its token generation and verification logic. Rate limiting follows the same exponential backoff strategy used by `BasePhoneDevice`.

In the sign-up flow, the verified email is held on `ConfigurationSession.verified_email` until `complete_profile` creates the `ConnectUser` and copies it across. In the post-registration flow, it is stored directly on `ConnectUser.email` (the currently unused `AbstractUser` field) with `email_verified = True`.

#### Model Changes

**`ConnectUser`** — add one new field:

```python
email_verified = models.BooleanField(default=False)
```

The existing `email` field from `AbstractUser` (max 254 chars, blank by default) is used to persist the verified address. A `UniqueConstraint` on `email` filtered to `is_active=True` will be added, consistent with how `phone_number` uniqueness is enforced on `ConnectUser`.

**`ConfigurationSession`** — add one new field to hold a verified email during the sign-up flow:

```python
verified_email = models.EmailField(blank=True, null=True)
```

**New model — `EmailOTPDevice`**:

Mirrors `SessionPhoneDevice`, which has both a nullable `user` and a `session` FK to handle the pre-user registration case:

```python
class EmailOTPDevice(SideChannelDevice):
    user = models.ForeignKey(ConnectUser, on_delete=models.CASCADE, null=True, blank=True)
    session = models.ForeignKey(ConfigurationSession, on_delete=models.CASCADE, null=True, blank=True)
    email = models.EmailField()
    otp_last_sent = models.DateTimeField(null=True, blank=True)
    attempts = models.IntegerField(default=1)
```

Exactly one of `user` or `session` will be set at any time. `generate_challenge()` will follow the same pattern as `BasePhoneDevice.generate_challenge()`: regenerate token if within 5 minutes of expiry, apply exponential backoff (`wait_time = 2**attempts` minutes) on resend requests, call `send_mail()` inline through the anymail/SES backend, and update `otp_last_sent` + `attempts`.

Token validity is controlled by a Django setting:

```python
EMAIL_OTP_VALIDITY_SECONDS = int(os.environ.get("EMAIL_OTP_VALIDITY_SECONDS", 1800))  # default: 30 minutes
```

`generate_challenge()` passes this value to `generate_token(valid_secs=settings.EMAIL_OTP_VALIDITY_SECONDS)`, mirroring the hardcoded `1800` in `BasePhoneDevice`.

For sign-up flow devices (session is set, user is null), test-number detection uses the session's `phone_number` field to decide whether to skip actual email delivery.

#### Django View Changes

**New view — `send_email_otp`**:

- Accepts both `SessionTokenAuthentication` (sign-up flow) and `OAuth2Authentication` (post-registration flow); set `authentication_classes` explicitly on the view.
- Gated by `email_otp_verification` waffle flag; returns 404 if flag is inactive.
- Validates `email` field in request body (uses `django.core.validators.validate_email`).
- Gets or creates an `EmailOTPDevice` keyed on `(session, email)` or `(user, email)` depending on which auth type was used.
- Calls `device.generate_challenge()` which sends the OTP email inline via `send_mail()`.
- Returns HTTP 200 on success, 400 on invalid/missing email, 429 if rate-limited (backoff not yet elapsed).

**New view — `verify_email_otp`**:

- Same dual authentication as `send_email_otp`.
- Gated by `email_otp_verification` waffle flag; returns 404 if flag is inactive.
- Validates `email` and `otp` fields in request body.
- Retrieves the `EmailOTPDevice` for `(session, email)` or `(user, email)`; returns 400 if none found.
- Calls `device.verify_token(otp)`; returns 401 with `INCORRECT_OTP` error code on failure.
- On success (sign-up flow): sets `session.verified_email = email`, saves session, deletes `EmailOTPDevice` record.
- On success (post-registration flow): sets `user.email = email`, `user.email_verified = True`, saves user, deletes `EmailOTPDevice` record.
- Returns HTTP 200 on success.

**Modified view — `complete_profile`**:

- After creating the new `ConnectUser`, check `session.verified_email`; if set, copy it to `user.email` and `user.email_verified = True` before saving. No payload change required.

**Modified view — `start_configuration`**:

- After building `response_data`, looks up whether a `ConnectUser` with this phone number has `email_verified = True`.
- If so, adds `"email": user.email` to `response_data`.
- If no such user exists (new registration flow) or `email_verified` is False, the key is omitted entirely.

#### Frontend Changes

None — this is a backend-only change. The mobile client consumes the updated `start_configuration` payload.

#### Email Template

A simple plain-text email is sent:

```text
Subject: Your CommCare Connect verification code
Body:   Your email verification code is: {token}
        This code expires in {validity_minutes} minutes.
```

An HTML template can be added in a follow-up; plain text is sufficient for MVP.

---

### Monitoring and Alerting Plan

- Log `INFO` when an OTP email is dispatched (user id, masked email e.g. `u***@example.com`) and when verification succeeds or fails.
- Log `WARNING` when the backoff rate limit is hit — indicates a potential abuse pattern.
- Sentry will capture any `send_mail()` exceptions automatically (Django integration already active).
- Add a Sentry alert for email delivery failures exceeding a threshold (e.g. >5% error rate in 5 minutes).
- No new analytics events are required at MVP; the verified-email field itself provides a countable metric via the admin or DB query.

---

### Deployment and Release

1. The feature is gated behind a **django-waffle flag** (`email_otp_verification`), defaulting to inactive.
2. Add `django-anymail[amazon-ses]` to `requirements.txt`. New settings needed: `DJANGO_EMAIL_BACKEND` (production: `anymail.backends.amazon_ses.EmailBackend`, local: `django.core.mail.backends.console.EmailBackend`) and `DEFAULT_FROM_EMAIL` — both read from env vars following the commcare-connect pattern. `DEFAULT_FROM_EMAIL` will reuse commcare-connect's verified SES sender address to avoid domain verification work. If a connect-id-specific sending address is desired in future, the new domain/address will need to be verified in SES before use.
3. Migrations for the new `EmailOTPDevice` model and `ConnectUser.email_verified` field are applied as part of normal deployment.
4. The flag is enabled per-environment once email credentials are confirmed working.
5. Rollback: disable the flag — no data migration required. If `ConnectUser.email`/`email_verified` fields were populated, they persist harmlessly.

---

### Alternative Solutions

**Alternative 1 — Dedicated `verified_email` field instead of reusing `AbstractUser.email`**
Avoids any ambiguity with Django admin or future use of `email` for non-verified purposes. Rejected for MVP because it adds an extra field when the existing one suffices; can be refactored later if needed.

**Alternative 2 — Extend `BasePhoneDevice` to be channel-agnostic**
Consolidates OTP logic but requires refactoring existing phone OTP models. Rejected as unnecessary scope increase — a dedicated `EmailOTPDevice` is simpler and keeps the blast radius small.

**Alternative 3 — SMTP relay (SendGrid, Postmark, etc.) instead of SES**
Other providers offer comparable delivery analytics, but SES was chosen to align with commcare-connect and reuse existing AWS infrastructure already in place for S3. No additional vendor account or credential set is needed.

---

## Further Considerations

**Accessibility:** No UI changes in this service. The mobile client team should ensure the email input and OTP entry fields meet accessibility standards.

**Impact on other teams:** The mobile (Android) team needs to consume the new `email` field in `start_configuration` and integrate the two new API endpoints. Coordination is required to agree on the feature flag timeline.

**Related work:** The phone OTP flow (`validate_phone` / `confirm_otp`) is the direct analogue for this feature. The implementation mirrors that pattern closely to reduce review and maintenance overhead.

---

## Success Evaluation

- **Correctness:** Users can successfully verify an email and have it reflected in `start_configuration` within one session.
- **Security:** OTP codes expire after 30 minutes; exponential backoff prevents brute-force. Codes are single-use (device record deleted on success).
- **Performance:** Email sending is done inline via `send_mail()`; SES latency is consistently low and inline sending ensures delivery failures are surfaced immediately to the caller.
- **Metric:** Track `COUNT(ConnectUser WHERE email_verified = TRUE)` over time to confirm adoption.

---

## Open Questions

1. ~~**Email uniqueness:** Should a verified email address be unique across active users (i.e. prevent two users from verifying the same address)? A unique constraint would add integrity but could cause friction if a user re-registers with the same email.~~ **Resolved:** Add a `UniqueConstraint` on `email` filtered to `is_active=True`, consistent with how `phone_number` uniqueness is enforced on `ConnectUser`.
2. **Email re-verification:** Can a user verify a different email address and overwrite their existing verified email?
3. **Test email bypass:** The design skips email delivery for users whose phone starts with `TEST_NUMBER_PREFIX`. Should a hardcoded test OTP (e.g. `"123456"`) be returned for test users, similar to any existing test-number shortcuts?
4. ~~**Rate limit response code:** Should `send_email_otp` return `HTTP 429 Too Many Requests` with a `Retry-After` header when backoff is active, or a `400` with an error code?~~ **Resolved:** Use `429 Too Many Requests` with a `Retry-After` header — more semantically correct and aligns with RFC 6585.

---

## QA Considerations

Key workflows to test:

Sign-up flow (session token):
- Happy path: send OTP (session token) → receive email → verify correct code → `complete_profile` → new user has `email` and `email_verified = True`.
- `start_configuration` returns `email` field on subsequent login.
- Skipping email verification during sign-up creates user without email fields set.

Post-registration flow (OAuth2 token):
- Happy path: send OTP (OAuth2 token) → receive email → verify correct code → user has `email` and `email_verified = True`.
- `start_configuration` returns `email` field after verification.

Both flows:
- Verify OTP with incorrect code returns 401.
- Verify OTP with expired token returns 401.
- OTP resend before backoff window returns rate-limit error.
- OTP resend after backoff window sends a new email.
- `start_configuration` omits `email` key for users with no verified email or `email_verified = False`.
- Endpoints return 404 when the `email_otp_verification` waffle flag is disabled.
- Test-number users skip email delivery (OTP still generated and verifiable).

---

## API Definitions

### POST /users/send_email_otp

**Auth:** `SessionTokenAuthentication` (sign-up/verification flow) or `OAuth2Authentication` (post-registration)

**Request:**
```json
{ "email": "user@example.com" }
```

**Responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 200 | `{}` | OTP email sent (or queued if test user) |
| 400 | `{"error_code": "MISSING_DATA"}` | Missing or invalid email |
| 404 | — | Feature flag disabled |
| 429 | `{"error_code": "RATE_LIMITED", "retry_after_seconds": N}` | Backoff window not elapsed |

---

### POST /users/verify_email_otp

**Auth:** `SessionTokenAuthentication` (sign-up/verification flow) or `OAuth2Authentication` (post-registration)

**Request:**
```json
{ "email": "user@example.com", "otp": "123456" }
```

**Responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 200 | `{}` | Email verified and stored on user |
| 400 | `{"error_code": "MISSING_DATA"}` | Missing email or OTP field |
| 400 | `{"error_code": "INVALID_DATA"}` | No pending OTP found for this email |
| 401 | `{"error_code": "INCORRECT_OTP"}` | Token verification failed |
| 404 | — | Feature flag disabled |

---

### POST /users/start_configuration (updated)

No change to request. Response now conditionally includes `email`:

```json
{
  "required_lock": "pin",
  "demo_user": false,
  "token": "<session_key>",
  "toggles": {},
  "sms_method": "firebase",
  "otp_fallback": false,
  "email": "user@example.com"   // only present if user has email_verified = True
}
```

---

## Implementation Tickets

1. **CCCT-XXXX** — Add `EmailOTPDevice` model, `ConnectUser.email_verified` field, and `ConfigurationSession.verified_email` field + migrations
2. **CCCT-XXXX** — Add `send_email_otp` and `verify_email_otp` views, URL routes, and `send_email_otp_message()` utility
3. **CCCT-XXXX** — Update `complete_profile` to copy `session.verified_email` onto new user, and update `start_configuration` to include verified email in response
4. **CCCT-XXXX** — Add `django-anymail[amazon-ses]`, configure `DJANGO_EMAIL_BACKEND` / `DEFAULT_FROM_EMAIL` env vars, and enable `email_otp_verification` waffle flag per environment
