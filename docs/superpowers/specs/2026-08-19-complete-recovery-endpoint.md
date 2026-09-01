# `complete_recovery` — a single endpoint for account recovery

**Status:** Draft — for team review

**Ticket:** [CCCT-2708](https://dimagi.atlassian.net/browse/CCCT-2708)

**Repo:** `connect-id` (server). Client counterpart lands in `commcare-android`.

**Replaces during recovery (for new clients):**
 * `POST /users/recover/confirm_backup_code`
 * `POST /users/verify_email_otp`
   * Note: Still called during Edit Profile workflow

**Answers:** the "Server Team Request" section of the mobile tech spec
 * [commcare-android#3843](https://github.com/dimagi/commcare-android/pull/3843)
 * [CCCT-2677](https://dimagi.atlassian.net/browse/CCCT-2677)
 * `docs/superpowers/specs/2026-07-28-personalid-backup-code-management-design.md`

**Related code:**
 * `users/views.py:566` (`confirm_backup_code`)
 * `users/views.py:1037` (`verify_email_otp`)
 * `users/auth.py:10` (`SessionTokenAuthentication`)
 * `users/models.py:302` (`ConfigurationSession`)

---

## 1. Summary

 * Add `POST /users/recover/complete_recovery`
 * Only supports `SessionTokenAuthentication`
 * Takes a `method` of either `backup_code` or `email_otp`, runs the verification that method requires
 * On success — completes account recovery and returns the same configuration payload `confirm_backup_code` returns today
   * Username, rotated password, DB key, device info

Both existing endpoints keep working for older clients. `confirm_backup_code` is unchanged apart from
an internal refactor onto the shared completion helper (§7). `verify_email_otp`
picks up one new behaviour it does not have today — a limit on wrong guesses (§6), which every OTP in
the system gains at once.

**And: a wrong OTP is finally counted.** Three wrong email OTPs burn the token; during recovery they
lock the account exactly as three wrong backup codes do. §6 specifies it; it is a prerequisite for
shipping `email_otp` as a recovery factor at all.

### Why

Two things are wrong with the current shape:

1. **Recovery is welded to the backup code.** `confirm_backup_code` is the only endpoint that
   completes recovery. A user who has forgotten their 6-digit backup code has no way back into their
   account, even if they hold a verified email address on the account.
2. **`verify_email_otp` does not complete recovery, and cannot.** It is a general-purpose
   "prove you control this mailbox, then attach it to the account" endpoint, shared by three auth
   classes and two workflows. It returns an empty `200`. In the recovery workflow today it runs
   *after* `confirm_backup_code` has already succeeded, purely to attach an email — see
   `PersonalIdBackupCodeFragment.handleConfirmBackupCodeSuccess()` on the client. It is not a
   recovery factor.

So the new endpoint is not a pure consolidation of two existing behaviours. `backup_code` is a
lift-and-shift of `confirm_backup_code`; `email_otp` is a **new recovery factor** that reuses
`verify_email_otp`'s verification mechanics. §5 and §6 pin down its security properties and are the
parts most worth reviewing.

### 1.1 What this answers from the mobile spec

The mobile tech spec (CCCT-2677) puts two questions to the server team. This document answers both,
and reviewers of that spec should read these as the replies.

**Their Q1 — how does the client complete recovery via email OTP, without a backup code?** Their
options were (a) a new email-only endpoint, e.g. `POST /users/recover/confirm_email_otp`, or
(b) extend `confirm_backup_code` to accept an OTP in place of the code.

*Answer: a variant of (a) — one endpoint covering **both** methods, not an email-only one.* The
verification differs between methods but everything after it — password rotation, backup-code
counter reset, `UserDeviceInfo` bookkeeping, the response payload — is identical, and that shared
tail is where the subtle behaviour lives. An email-only endpoint would duplicate it and let the two
copies drift. (b) is rejected: it would mean one endpoint whose auth semantics change based on which
field is populated, and it would drag the new factor into the legacy endpoint that older clients
still depend on. The client-side cost of the unified shape is one `method` field — the payload they
asked for is returned unchanged either way.

**Their Q2 — how does the client learn the user's email early enough to offer "Forgot backup
code?"** Their options were (a) `start_configuration` returns `email` (their stated preference), or
(b) `check_name` returns it.

*Answer: mostly "you don't need it" — and where you do, (b) masked, not (a).* Because
`complete_recovery` resolves the address from `user.email` rather than accepting one (§5), the
client never needs the address to complete recovery. The only thing still asking for it is
`send_email_otp`'s required `email` parameter. A separate ticket adds a `masked_email` field to the
`check_name` response so the client can label the "Forgot backup code?" option.

Option (a) also has a problem worth being explicit about: `start_device_configuration` is
`@permission_classes([])` (`users/views.py:93-96`), gated only by app integrity. It is the call that
*creates* the session, so there is no phone validation behind it. Returning the account's email
there turns "phone number → email address" into a lookup available to anyone who can produce a valid
Play Integrity token. `check_name` at least sits behind `is_phone_validated` (`users/views.py:943`).

---

## 2. Where this sits in the recovery workflow

 * User completes the configuration workflow through the Name page, and is identified as an existing user (i.e. recovery workflow)
   * Phone page
   * Biometric page
   * Phone Verification page
   * Name page
 * User is now shown the "Confirm Backup Code" page
 * 2 options for completing recovery:
   * Option A: Confirm backup code
     * User enters their backup code and submits
   * Option B: Complete email OTP verification
     * User indicates that they don't remember their backup code
     * An OTP is emailed to the user and they are shown the Email Verification page
       * The OTP always goes to the address on record for the account — the user never types
         one, and never chooses which mailbox is used (§5)
     * User retrieves and enters the OTP and submits
 * On submission of either of the above options:
   * Mobile makes the new `complete_recovery` request with the chosen `method` and associated data

The session token is the only credential. `SessionTokenAuthentication` already rejects:
 * An unknown key (`401 INVALID_TOKEN`)
 * An expired session (`401 TOKEN_EXPIRED`)
 * A phone number belonging to a locked account (`401 LOCKED_ACCOUNT`)

---

## 3. Contract

### Request

```
POST /users/recover/complete_recovery
Authorization: Bearer <ConfigurationSession.key>
Content-Type: application/json
```

| Field | Required | Notes |
|---|---|---|
| `method` | always | `"backup_code"` or `"email_otp"`. Any other value → `400 INVALID_DATA`; absent → `400 MISSING_DATA`. |
| `backup_code` | `method=backup_code` | The user's backup code. Equivalent field to `recovery_pin` in `confirm_backup_code` today. |
| `otp` | `method=email_otp` | The code mailed by `send_email_otp` for this session. |

Fields belonging to the other method are ignored, not rejected.

**The client never sends an email address.** The endpoint resolves it from `user.email` on the
account being recovered — see §5. An `email` key in the request body is ignored, not honoured.

URL name: `complete_recovery` (`users/urls.py`), path under `recover/` alongside the other recovery
endpoints.

### Success response — `200`, identical for both methods

```json
{
  "username": "...",
  "password": "<newly generated, 32 hex chars>",
  "db_key": "...",
  "invited_user": true,
  "email": "user@example.com",
  "previous_device": "Pixel 7",
  "last_accessed": "2026-07-02T10:11:12+00:00"
}
```

Notes:
 * `email` is present only when the account has one
 * `previous_device` / `last_accessed` are present only when the session carries a `device` **and** a *different* device was seen on the account within
`DEVICE_RECENT_ACCESS_THRESHOLD` (30 days)
   * Byte-for-byte the rule in `confirm_backup_code` (`users/views.py:602-626`).

### Wrong-backup-code response — `200`

```json
{ "attempts_left": 2 }
```

A `200` for a wrong code is odd, but it is what `confirm_backup_code` returns today and what the
client's `sessionData.dbKey != null` success test relies on. Kept as is so the old and new paths can
share one handler while both are live.

### Wrong-email-OTP response — `401`

```json
{ "error_code": "INCORRECT_OTP", "attempts_left": 2 }
```

Same `attempts_left` key as the backup-code path, so the client can drive one "N attempts remaining"
string from either method. Only the status code differs; the counter semantics are identical (§6).

### Errors

| Status | `error_code` | When |
|---|---|---|
| 400 | `MISSING_DATA` | `method` absent, or the selected method's fields are absent/blank |
| 400 | `INVALID_DATA` | `method` not one of the two values; no pending email OTP device for this session and the account's email |
| 400 | `NO_RECOVERY_PIN_SET` | `backup_code` and the account has no backup code set |
| 400 | `NO_EMAIL_SET` | `email_otp` and the account has no email on record. New constant, mirroring `NO_RECOVERY_PIN_SET` |
| 401 | `INCORRECT_OTP` | `email_otp` and the code is wrong or expired; body carries `attempts_left` (§6) |
| 401 | `LOCKED_ACCOUNT` | the third consecutive wrong backup code, **or** the third consecutive wrong email OTP (§6) — the account is deactivated and locked |
| 403 | `PHONE_NOT_VALIDATED` | `session.is_phone_validated` is false |
| 403 | `NOT_ALLOWED` | `email_otp` requested while the `email_otp_verification` switch is off (§4.2) |
| 500 | — | no active `ConnectUser` for the session's phone number, as `confirm_backup_code` does today |

`OTP_EXPIRED` — the other outcome of exhausting the attempt limit — is **not** returned by this
endpoint. Recovery locks instead. It is the response the *non-recovery* OTP endpoints return once
the limit is hit; see §6.2.

---

## 4. Behaviour

Validation runs in this order; the first failure returns.

1. **Auth** — `SessionTokenAuthentication` only. No `DeviceBasicAuthentication`, no
   `OAuth2Authentication`: this endpoint exists to recover an account you cannot currently log into,
   so the only meaningful credential is the configuration session.
2. **Phone validated** — `403 PHONE_NOT_VALIDATED` if not. The phone factor is a precondition for
   *both* methods; neither backup code nor email OTP replaces it.
3. **Resolve the user** — `ConnectUser.objects.get(phone_number=session.phone_number, is_active=True)`,
   unguarded as in `confirm_backup_code`: no active user is a `500`, and mobile should never allow it.
4. **Method dispatch** — validate the method's own fields, then run its verification (§4.1 / §4.2).
5. **Complete recovery** — shared, identical for both methods (§4.3).

### 4.1 `method = backup_code`

Lift-and-shift of `confirm_backup_code`:

- `user.check_recovery_pin(data["backup_code"])` — the model method and column keep the older
  `recovery_pin` name; only the wire field is renamed to match the user-facing term.
- `RecoveryPinNotSetError` → `400 NO_RECOVERY_PIN_SET`.
- Wrong code → `user.add_failed_backup_code_attempt()`. If `backup_code_attempts_left` is then `0`
  (`MAX_BACKUP_CODE_ATTEMPTS = 3`), set `is_active = False`, `is_locked = True`, save, and return
  `401 LOCKED_ACCOUNT`. Otherwise return `200 {"attempts_left": n}`.
- Correct → §4.3.

### 4.2 `method = email_otp`

- The `email_otp_verification` waffle switch is checked **inside this branch**, not with
  `@waffle_switch` on the view — that would 404 the `backup_code` path too. Off → `403 NOT_ALLOWED`.
  The switch already reaches the client in `start_configuration`'s `toggles`, so this is a backstop,
  not a UX path.
- `otp` required and non-blank after `.strip()` → else `400 MISSING_DATA`.
- **Resolve the email from the account, not the request:** `email = user.email`. If it is unset,
  `400 NO_EMAIL_SET`
- Look up `SessionEmailOTPDevice.objects.get(session=request.auth, email=user.email)`. Not found →
  `400 INVALID_DATA`
- `device.verify_token(otp)` → false gives `401 INCORRECT_OTP` and logs the masked email, matching
  `verify_email_otp` (`users/views.py:1054-1056`)
- **A wrong OTP is counted (§6).** `verify_token` increments `device.failed_verifications`. The
  response carries `attempts_left`, and on the `MAX_OTP_VERIFY_ATTEMPTS`-th consecutive failure the
  token is burned **and the account is locked** — `is_active = False`, `is_locked = True`, save,
  `401 LOCKED_ACCOUNT`
- Success → resets `device.failed_verifications` to `0`

### 4.3 Shared completion

Exactly what `confirm_backup_code` does today, extracted into one helper so the two endpoints cannot
drift:

1. `password = token_hex(16)`; `user.set_password(password)`.
2. `user.reset_failed_backup_code_attempts()` — **including on the `email_otp` path.**
3. `user.save()`.
4. Device bookkeeping when `session.device` is set: same device → update `UserDeviceInfo` password
   and `last_accessed`; different device → create a new record and, if the old one was accessed
   within 30 days, add `previous_device` / `last_accessed` to the response.
5. Build and return the payload in §3.

The whole of step 1–4 should run inside a single `transaction.atomic()` block. It does not today,
and a failure between the password rotation and the device write leaves the client without the
password that now authenticates the account. Cheap to fix while the code is being extracted.

---

## 5. Security: the email is server-resolved, never client-supplied

**Requirement: `method=email_otp` reads the address from `user.email` on the account being
recovered. The request carries no email at all, and an `email` key in the body is ignored.**

An account with no email on record can never recover by `email_otp` — `400 NO_EMAIL_SET`. The mobile
flow should never reach this, since "Forgot backup code?" is only offered when an email exists, so
treat it as a defensive error rather than a UX path.

---

## 6. Failed-verify limits on OTPs

**Requirement: a wrong OTP is counted, and running out of attempts has a consequence — the same
consequence a wrong backup code has, chosen by what the OTP is being used *for*.**

No OTP in this codebase has a verify-side limit today, phone or email: a 6-digit code is guessable
without limit for its full 30-minute window. The mechanism therefore has to be built, and since it
belongs on `BaseOTPDevice`, every OTP in the system gains it at once — blast radius in §6.3.

### 6.1 The counter

| Piece | Where | What |
|---|---|---|
| `failed_verifications` | `BaseOTPDevice` (`users/models.py:142`) | `IntegerField(default=0)`. Inherited by `PhoneDevice`, `SessionPhoneDevice`, `UserEmailOTPDevice`, `SessionEmailOTPDevice` — one migration, four tables. |
| `MAX_OTP_VERIFY_ATTEMPTS = 3` | `users/const.py` | Mirrors `MAX_BACKUP_CODE_ATTEMPTS = 3`, sitting beside it |
| `verify_attempts_left` | `BaseOTPDevice` | `max(MAX_OTP_VERIFY_ATTEMPTS - self.failed_verifications, 0)`, mirroring `ConnectUser.backup_code_attempts_left` (`users/models.py:106`). |
| `is_exhausted` | `BaseOTPDevice` | `self.verify_attempts_left == 0`. What views branch on to choose a response. |

`BaseOTPDevice` **overrides `verify_token`**, keeping django-otp's `bool` return:

```python
def verify_token(self, token):
    if self.is_exhausted:
        return False
    verified = super().verify_token(token)      # clears self.token on success
    self.failed_verifications = 0 if verified else self.failed_verifications + 1
    if self.is_exhausted:
        self._burn_token()
    self.save()
    return verified
```

Overriding rather than adding a `verify_token_with_limit()` matters: the limit is then on by default,
and no call site can stay unlimited by being forgotten. Views wanting better than a bare `401` read
`is_exhausted` / `verify_attempts_left` afterwards.

`_burn_token` is `self.token = None; self.valid_until = now()` — a burned token cannot be verified
even if the caller then supplies the correct code.

Wrap the override body in `transaction.atomic()` with a `select_for_update()` re-read of
`failed_verifications` and `token`, matching `_attempt_send` (`users/models.py:161-169`). Without it
the read-modify-write means N concurrent wrong guesses count as one — exactly the shape of request an
attacker sends. (`confirm_backup_code` has the same race today on `failed_backup_code_attempts`; not
fixing that here, but a new counter should not be born with it.)

**A fresh token resets the counter, but not the send-side backoff.** `_attempt_send` currently zeroes
the send counter `attempts` whenever it regenerates a token, so resetting `failed_verifications`
alongside it would reopen the hole from the other side: three guesses, new OTP, three more, forever.
So `attempts = 0` **only when the previous token expired on its own**; a token burned by failed
verifications keeps its `2**attempts`-minute backoff. Guesses per token bounded by the counter,
tokens per hour by the backoff. `failed_verifications` resets on every token actually sent.

`self.is_exhausted` is the discriminator inside the `is_otp_close_to_expiry` branch
(`users/models.py:170-173`) — true only for a burned token, since it is cleared on every send:

```python
if self.is_otp_close_to_expiry:
    burned = self.is_exhausted          # read before clearing
    self.otp_last_sent = None
    self.generate_token(valid_secs=valid_secs)
    self.failed_verifications = 0
    if not burned:
        self.attempts = 0               # natural expiry only; a burned token keeps its backoff
```

`failed_verifications` must be read from the locked row alongside `attempts` / `token` /
`valid_until` (`users/models.py:165-169`) or a concurrent verify is lost.

Two properties that are easy to lose in a later refactor:
 * The counter lives on the **device row**, not on `ConnectUser`. Sharing
   `failed_backup_code_attempts` would let wrong email OTPs eat backup-code attempts and corrupt the
   `attempts_left` the client shows.
 * Session-scoped counters (`SessionEmailOTPDevice`, `SessionPhoneDevice`) die with the session; the
   backoff and, in recovery, the account lock are what survive. `PhoneDevice` / `UserEmailOTPDevice`
   counters persist, like the backup-code counter.

### 6.2 What running out costs, by context

The consequence turns on one question: **is the OTP standing in for the account, or merely being
attached to it?**

**(a) Non-recovery (registration, edit profile, everything else) → new `401 OTP_EXPIRED`.** The token
is dumped and the user requests a new one, subject to the resend backoff; nothing about the account
changes. There the OTP proves control of a mailbox or handset being attached to an account the caller
has *already* authenticated to, so guessing wrong gets you a mailbox you don't own on your own
account.

`OTP_EXPIRED` is a **new** `ErrorCodes` constant. Do not reuse `TOKEN_EXPIRED` — the client responds
to that by restarting the whole workflow.

**(b) `complete_recovery` with `method=email_otp` → the account is locked.** `is_active = False`,
`is_locked = True`, save, `401 LOCKED_ACCOUNT` — same lines, same response, same aftermath as the
third wrong backup code (`users/views.py:579-583`). Here the OTP *is* the recovery factor, so it has
to carry the same weight as the factor it substitutes for; anything less and the attacker picks the
cheaper door (§5). The token is burned too — redundant once locked, but it keeps one code path in the
model.

### 6.3 Blast radius, and the one place this should *not* be copied

The override moves every other verify call site from "unlimited guesses" to "three guesses, then the
token is dead":

| Call site | Device | Response after the change |
|---|---|---|
| `users/views.py:995` `confirm_session_otp` | `SessionPhoneDevice` | `401 OTP_EXPIRED` (converted in this ticket) |
| `users/views.py:1054` `verify_email_otp` | `Session`/`UserEmailOTPDevice` | `401 OTP_EXPIRED` (converted in this ticket) |
| `users/views.py:183` `confirm_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `users/views.py:211` `confirm_secondary_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `users/views.py:315` `confirm_recovery_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `users/views.py:358` `confirm_secondary_recovery_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `payments/views.py:41` `confirm_payment_profile_otp` | `PhoneDevice` | unchanged bare `401`; token burned |

The legacy `PhoneDevice` views and the payments one keep their existing response shape — their
clients do not know `OTP_EXPIRED` (§10). They still get the token-burning, which is a real behaviour
change: a client that today retries a wrong code indefinitely will now need a fresh OTP. Intended,
but worth QA time on the payment-profile flow, which is a live non-Connect path.

**Deliberately *not* extended: locking the account on failed phone OTPs.** The backup-code and
recovery-email-OTP lockouts sit *behind* phone validation, so triggering them costs an attacker
control of the number. The session phone OTP sits in front of it — `start_device_configuration` is
`@permission_classes([])` and creates a session from a phone number and a Play Integrity token
(§1.1) — so locking there would let anyone who knows a number deactivate the account in three
requests, undoable only by a management command. Phone OTP gets the counter and the token-burning,
case (a), in every context including recovery.


---

## 7. Implementation sketch

| File | Change |
|---|---|
| `users/urls.py` | `path("recover/complete_recovery", views.complete_recovery, name="complete_recovery")` |
| `users/models.py` | `BaseOTPDevice.failed_verifications` field, `verify_attempts_left` / `is_exhausted` properties, `verify_token` override, `_burn_token`; `_attempt_send` resets `attempts = 0` only for a naturally-expired token (§6.1). |
| `users/migrations/` | One migration adding `failed_verifications` to `PhoneDevice`, `SessionPhoneDevice`, `UserEmailOTPDevice`, `SessionEmailOTPDevice`. Additive, `default=0`, no backfill. |
| `users/views.py` | New `complete_recovery` view. Extract `_complete_recovery_for_user(user, session) -> dict` and `_apply_device_info(user, session, response_data)` from the tail of `confirm_backup_code`. Extract the backup-code verification into a helper the two views share. |
| `users/views.py` | `confirm_backup_code` calls the extracted helpers — **no behaviour change**, so its existing tests must pass untouched. |
| `users/views.py` | `confirm_session_otp` (`:995`) and `verify_email_otp` (`:1054`) return `401 OTP_EXPIRED` when `device.is_exhausted` after a failed verify (§6.3). |
| `users/const.py` | `RECOVERY_METHOD_BACKUP_CODE` / `RECOVERY_METHOD_EMAIL_OTP`; `MAX_OTP_VERIFY_ATTEMPTS = 3`; `OTP_EXPIRED` and `NO_EMAIL_SET` error codes. |
| `users/tests/test_views.py` | New `TestCompleteRecoveryApi` (§8). |
| `users/tests/test_models.py` | Counter, burn, reset, and backoff-preservation tests on `BaseOTPDevice` (§8). |

No new API version — `AcceptHeaderVersioning` defaults to v2.0 and this endpoint behaves the same in
both.

---

## 8. Test plan

`users/tests/test_views.py`, class `TestCompleteRecoveryApi`, using the existing `authed_client_token`
/ `valid_token` / `user` / `session_client` fixtures.

**Auth and preconditions** (parametrised over both methods) — the usual set: no header, expired
session, locked phone number, `is_phone_validated = False`, basic-auth and OAuth2 clients rejected,
no active user → 500, missing/unknown `method`.

**`backup_code`** — mirrors the existing `TestConfirmBackupCodeApi` cases: missing field, no code set,
wrong code (`attempts_left == 2`, counter incremented), third wrong code locks, correct code succeeds
and resets the counter.

**`email_otp`**
- Missing `otp` → 400 `MISSING_DATA`. `user.email` unset → 400 `NO_EMAIL_SET`, `verify_token` never
  called.
- No `SessionEmailOTPDevice` for this session + `user.email` → 400 `INVALID_DATA`; likewise a device
  on a *different* session for the same email (cross-session redemption blocked).
- **A device on this session for a different email, holding a valid OTP → 400 `INVALID_DATA` and
  `verify_token` is never called.** Proves the client cannot nominate the mailbox: the correct code
  for `attacker@evil.com` is not merely rejected, it is never looked at. Assert the account is
  untouched.
- **An `email` key in the body is ignored** — valid device on `user.email` plus
  `"email": "attacker@evil.com"` still succeeds; the mirror case (valid device on the attacker
  address, `email` key naming it) → 400 `INVALID_DATA`. Guards against a refactor reintroducing
  client-supplied addressing.
- Wrong OTP → 401 `INCORRECT_OTP`, `attempts_left` 2 then 1, account still active; **third → 401
  `LOCKED_ACCOUNT`** with the token burned and the same response body as the third wrong backup code
  (`test_views.py:937-941`). After the lock the correct OTP is still refused.
- The two counters are independent (§6.1): wrong OTPs leave `failed_backup_code_attempts` alone and
  vice versa. A successful verify resets `failed_verifications`, and email recovery after two failed
  backup-code attempts leaves `failed_backup_code_attempts == 0`.
- Correct OTP → success payload. With `email_otp_verification` inactive → 403 `NOT_ALLOWED`, while
  `backup_code` still succeeds.

**Shared completion** (parametrised over both methods, to prove the paths identical) — payload fields
and `user.check_password(response["password"])`; `email` present only when set; and the four
`UserDeviceInfo` cases: no session device, same device, different device inside 30 days, different
device outside 30 days.

**Failed-verify limit, model level** (`users/tests/test_models.py`, parametrised over all four device
classes)
- Counter increments, `verify_attempts_left` 3 → 0, third wrong token clears `token` and makes even
  the correct code return `False`; a correct token before exhaustion resets the counter.
- `generate_challenge()` on a naturally-expired token resets `failed_verifications` **and**
  `attempts`; **after exhaustion it resets only `failed_verifications`**, leaving the `2**attempts`
  backoff in place. That second test is what closes the burn-and-resend loop (§6.1).
- Concurrent wrong guesses each count — two racing `verify_token` calls leave
  `failed_verifications == 2`. Needs `@pytest.mark.django_db(transaction=True)` and threads; no
  existing concurrency test to copy (`test_views.py:2493` is the only `transaction=True` test and it
  is not concurrent).

**Mocking — affects most of the above.** Existing OTP tests patch `verify_token` wholesale
(`test_views.py:2495, 2509`, throughout `TestVerifyEmailOtp`), which after §6 patches out the counter
too: a mocked failure leaves `is_exhausted` false, so view logic branching on it is untested or takes
the wrong branch silently. Tests that exercise the counter must drive real tokens
(`device.generate_token()`, then submit a wrong string). Mocks stay fine for anything that only cares
about what happens after a successful verify.

**Non-recovery OTP endpoints** (`OTP_EXPIRED`, §6.2 case (a))
- `verify_email_otp` in registration / edit profile: three wrong OTPs → 401 `OTP_EXPIRED`, account
  **not** locked, `user.email` unwritten, and a fresh OTP then succeeds.
- `confirm_session_otp`: three wrong OTPs → 401 `OTP_EXPIRED`, still not phone-validated, and
  explicitly **no lock** (§6.3).
- `confirm_payment_profile_otp` and the legacy `PhoneDevice` views keep their bare `401` but stop
  accepting guesses on the burned token.

**Regression** — `TestConfirmBackupCodeApi` and `TestVerifyEmailOtp` pass unmodified; that is the
acceptance criterion for the refactor. One expected exception: tests that submit more than
`MAX_OTP_VERIFY_ATTEMPTS` wrong OTPs to one device, or reuse a device across sub-cases after failed
verifies, need a counter reset. Those are the only permitted edits — a changed *assertion* means the
refactor drifted.

---

## 9. Client and rollout impact

*(commcare-android, separate ticket — noted so the two land in the right order.)*

- New `ApiEndPoints.completeRecovery` + `ApiService` method + `PersonalIdApiHandler.completeRecovery`,
  parsing the same payload into `PersonalIdSessionData`.
- `PersonalIdBackupCodeFragment.confirmBackupCode()` switches to `method=backup_code`; downstream
  handling unchanged, including the `sessionData.dbKey != null` success test.
- `PersonalIdEmailVerificationFragment` calls `method=email_otp` in the mobile spec's
  `BACKUP_CODE_RECOVERY_SIGN_IN` workflow, then `PersonalIdRecoveryCompleter.finalizeAccountRecovery`.
  Registration, `EXISTING_USER`, and the profile-graph `BACKUP_CODE_RECOVERY_SET_CODE` flow keep
  `verify_email_otp` — those attach an email, they do not recover an account.
- `complete_recovery` does **not** clear `recovery_pin`, so the account keeps its old, forgotten
  backup code. The mobile spec already routes straight to `SET_NEW_CODE` and calls `set_recovery_pin`
  with the password from this response. Clearing it server-side would strand a client that fails
  between the two calls, so it needs its own decision if wanted.
- `AnalyticsParamValue.CCC_RECOVERY_METHOD_BACKUPCODE` is hardcoded in
  `PersonalIdRecoveryCompleter.logRecoverySuccessResult()`; needs an email variant to make the
  recovery-method split measurable.
- **Two new responses to handle, both from §6:**
  - `401 INCORRECT_OTP` now carries `attempts_left`. The email verification screen should show the
    same "N attempts remaining" and "this will lock your account" language the backup-code screen
    already shows — the consequence is now identical.
  - `401 OTP_EXPIRED` can come from `verify_email_otp` and `confirm_session_otp`, i.e. on
    **registration**, **edit-profile**, and invited-user phone screens, not only recovery. Clear the
    field, tell the user to request a new code, re-enable resend (which may then hit the existing
    `429 RATE_LIMITED`). Falling through to a generic error leaves the user retyping a dead code.
- **Rollout order:** server first (both old and new endpoints live), then the client — except
  `OTP_EXPIRED` handling, which should ship **before or with** the server change since it hits
  existing screens on existing builds. Older builds do not break (generic error, user requests a new
  code) but the UX is poor until the client ships; if that is unacceptable, gate the `OTP_EXPIRED`
  response behind a waffle switch and keep returning the bare `401` — the token is burned either way,
  so the security property does not wait on the client.

---

## 10. Out of scope

- Removing or deprecating `confirm_backup_code` / `verify_email_otp`. That is a later ticket gated on
  min-supported-version.
- Any change to registration or `EXISTING_USER` email attachment, beyond the `OTP_EXPIRED` response
  `verify_email_otp` gains from §6.
- Recovery by secondary phone (`recover/confirm_secondary_otp`) and the `RecoveryStatus` state
  machine — `complete_recovery` is a `ConfigurationSession` flow and never reads or writes
  `RecoveryStatus`. Their `PhoneDevice`s do inherit the failed-verify limit (§6.3); their views and
  responses are otherwise unchanged.
- Any account lockout triggered by phone OTP failures (§6.3).
- The `check_name` masked-email hint — ticketed separately.

Explicitly **not** out of scope, despite being tempting to defer: the failed-verify limit itself
(§6). It may land as its own ticket sequenced before this one, but the `email_otp` path must not go
live without it.


## 11. Proposed Implementation Tickets
Web:
 - Prereq: Add failed verification limits to BaseOTPDevice
 - Add OTP_EXPIRED responses
 - Refactor confirm_backup_code to shared helpers
 - Implement complete_recovery endpoint
 - Add masked_email to check_name response
 
Mobile:
 - Handle 401 OTP_EXPIRED errors (email and phone pages)
 - Show attempts remaining in email OTP after incorrect OTP
 - Implement complete_recovery
 - Change backup code page to user new API call
 - Email OTP recovery flow
 - Analytics (log email usage)
 - Show masked_email in email OTP page during recovery