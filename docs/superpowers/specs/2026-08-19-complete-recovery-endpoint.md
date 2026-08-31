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
(optionally, see §8) an internal refactor onto the same shared completion helper. `verify_email_otp`
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
`verify_email_otp`'s verification mechanics. §5 and §6 are the parts of this document that most need
review, because that is where the new factor's security properties are pinned down.

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

*Answer: mostly "you don't need it" — and where you do, (b) masked, not (a). See D6.* Because
`complete_recovery` resolves the address from `user.email` rather than accepting one (§5), the
client never needs the address to complete recovery. The only thing still asking for it is
`send_email_otp`'s required `email` parameter.

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

### Wrong-backup-code response — `200` (see decision D3)

```json
{ "attempts_left": 2 }
```

### Wrong-email-OTP response — `401`

```json
{ "error_code": "INCORRECT_OTP", "attempts_left": 2 }
```

Same `attempts_left` key as the backup-code path, so the client can drive one "N attempts remaining"
string from either method. The status code differs because the two paths already differ (D3); the
counter semantics are identical. See §6.

### Errors

| Status | `error_code` | When |
|---|---|---|
| 400 | `MISSING_DATA` | `method` absent, or the selected method's fields are absent/blank |
| 400 | `INVALID_DATA` | `method` not one of the two values; no pending email OTP device for this session and the account's email |
| 400 | `NO_RECOVERY_PIN_SET` | `backup_code` and the account has no backup code set |
| 400 | `NO_EMAIL_SET` | `email_otp` and the account has no email on record (decision D4) |
| 401 | `INCORRECT_OTP` | `email_otp` and the code is wrong or expired; body carries `attempts_left` (§6) |
| 401 | `LOCKED_ACCOUNT` | the third consecutive wrong backup code, **or** the third consecutive wrong email OTP (§6) — the account is deactivated and locked |
| 403 | `PHONE_NOT_VALIDATED` | `session.is_phone_validated` is false |
| 403 | `NOT_ALLOWED` | `email_otp` requested while the `email_otp_verification` switch is off (decision D2) |
| 500 | no active `ConnectUser` for the session's phone number (decision D5) |

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
3. **Resolve the user** — `ConnectUser.objects.get(phone_number=session.phone_number, is_active=True)`.
4. **Method dispatch** — validate the method's own fields, then run its verification (§4.1 / §4.2).
5. **Complete recovery** — shared, identical for both methods (§4.3).

### 4.1 `method = backup_code`

Lift-and-shift of `confirm_backup_code`:

- `user.check_recovery_pin(data["backup_code"])` — the model method and column keep the older
  `recovery_pin` name; only the wire field is renamed to match the user-facing term.
- `RecoveryPinNotSetError` → `400 NO_RECOVERY_PIN_SET`.
- Wrong code → `user.add_failed_backup_code_attempt()`. If `backup_code_attempts_left` is then `0`
  (`MAX_BACKUP_CODE_ATTEMPTS = 3`), set `is_active = False`, `is_locked = True`, save, and return
  `401 LOCKED_ACCOUNT`. Otherwise return `{"attempts_left": n}` — see D3 on the status code.
- Correct → §4.3.

### 4.2 `method = email_otp`

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
recovered.

An account with no email on record can never recover by `email_otp` — `400 NO_EMAIL_SET` (D4).
The mobile spec's flow should never reach this, since "Forgot backup code?" is only offered when
an email exists, so treat it as a defensive error rather than a UX path.

---

## 6. Failed-verify limits on OTPs

**Requirement: a wrong OTP is counted, and running out of attempts has a consequence


### 6.1 The counter

| Piece | Where | What |
|---|---|---|
| `failed_verifications` | `BaseOTPDevice` (`users/models.py:142`) | `IntegerField(default=0)`. Inherited by `PhoneDevice`, `SessionPhoneDevice`, `UserEmailOTPDevice`, `SessionEmailOTPDevice` — one migration, four tables. |
| `MAX_OTP_VERIFY_ATTEMPTS = 3` | `users/const.py` | Mirrors `MAX_BACKUP_CODE_ATTEMPTS = 3`, sitting beside it |
| `verify_attempts_left` | `BaseOTPDevice` | `max(MAX_OTP_VERIFY_ATTEMPTS - self.failed_verifications, 0)`, mirroring `ConnectUser.backup_code_attempts_left` (`users/models.py:106`). |
| `is_exhausted` | `BaseOTPDevice` | `self.verify_attempts_left == 0`. What views branch on to choose a response. |

`BaseOTPDevice` **overrides `verify_token`** rather than adding a separate counting method, and keeps
django-otp's `bool` return:

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

The override is the point. A separate `verify_token_with_limit()` would leave every call site that
nobody remembered to convert silently unlimited — including the two legacy recovery views and
`payments/views.py:41`. Overriding means the limit is on by default and a caller has to work to
avoid it. Views that want to say something better than a bare `401` read `is_exhausted` /
`verify_attempts_left` afterwards.

Burning the token (`_burn_token`) is `self.token = None; self.valid_until = now()` — "dump the OTP so
mobile has to request a new one". A burned token cannot be verified even if the caller then supplies
the correct code, which is the property the §9 test asserts.

The increment needs the same row lock `_attempt_send` already takes: the sketch above is
read-modify-write, so N concurrent wrong guesses against one device would otherwise all read the same
`failed_verifications` and count as one. That is exactly the shape of request an attacker sends.
Wrap the body in `transaction.atomic()` with a `select_for_update()` re-read of
`failed_verifications` and `token`, matching `_attempt_send` (`users/models.py:161-169`). Worth
noting that `confirm_backup_code` has this same race today on `failed_backup_code_attempts` and we
are not fixing it here — but a new counter should not be born with it.

**A fresh token resets the counter, but not the send-side backoff.** `_attempt_send`
(`users/models.py:160-182`) already zeroes the send counter `attempts` whenever it regenerates a
token, so a naive `failed_verifications = 0` alongside it would reopen the hole from the other side:
three guesses, request a new OTP, three more guesses, forever — 10⁶ codes at three per email, which
is loud and slow but not bounded. So `_attempt_send` resets `attempts = 0` **only when the previous
token expired on its own**; a token that was burned by failed verifications leaves `attempts` where
it was, and the user waits out the existing `2**attempts`-minute backoff before the next code is
sent. Guesses per token are bounded by the counter, tokens per hour by the backoff, and the product
is a real limit rather than two half-measures. `failed_verifications` itself resets to `0` on every
token that is actually sent.

Concretely, inside the `is_otp_close_to_expiry` branch of `_attempt_send`
(`users/models.py:170-173`), `self.is_exhausted` is the discriminator — it is true only for a burned
token, since it is cleared on every send:

```python
if self.is_otp_close_to_expiry:
    burned = self.is_exhausted          # read before clearing
    self.otp_last_sent = None
    self.generate_token(valid_secs=valid_secs)
    self.failed_verifications = 0
    if not burned:
        self.attempts = 0               # natural expiry only; a burned token keeps its backoff
```

Note this runs under the existing `select_for_update()` lock, and `failed_verifications` must be
read from the locked row alongside `attempts` / `token` / `valid_until` (`users/models.py:165-169`)
or a concurrent verify can be lost.

Two properties worth stating because they are easy to lose in a later refactor:
 * The counter lives on the **device row**, not on `ConnectUser`. Sharing
   `failed_backup_code_attempts` would let wrong email OTPs eat the user's backup-code attempts and
   corrupt the `attempts_left` number the client shows. The two factors count separately.
 * `SessionEmailOTPDevice` and `SessionPhoneDevice` rows are session-scoped, so their counters die
   with the session. That is fine — the backoff and, in recovery, the account lock are what survive.
   `PhoneDevice` and `UserEmailOTPDevice` are user-scoped and their counters persist, like the
   backup-code counter does.

### 6.2 What running out costs, by context

The consequence differs, and it differs on exactly one axis: **is the OTP standing in for the
account, or merely attached to something?**

**(a) Registration, edit profile, and every other non-recovery use → the process fails, the OTP is
dumped, the user asks for a new one.** The response is a new `401 OTP_EXPIRED` error code. Mobile
treats it as it treats any expired OTP: drop the entry field, call `send_email_otp` /
`send_session_otp` again, and start over — subject to the resend backoff above, which is what stops
the retry loop being free. Nothing about the account changes. This is right because in those flows
the OTP proves control of a mailbox or handset that is about to be *attached* to an account the
caller has already authenticated to by other means; guessing it wrong gets you a mailbox you do not
own attached to your own account, not somebody else's account.

`OTP_EXPIRED` is a **new** constant in `ErrorCodes`. Do not reuse `TOKEN_EXPIRED` — that means the
configuration session expired and the client's handling of it (restart the whole workflow) is not
what we want here.

**(b) `complete_recovery` with `method=email_otp` → the account is locked.** `is_active = False`,
`is_locked = True`, save, `401 LOCKED_ACCOUNT` — the same three lines and the same response as the
third wrong backup code (`users/views.py:579-583`), and with the same aftermath:
`SessionTokenAuthentication` then refuses to open any session for that phone number
(`users/auth.py:23-26`) and only `unlock_and_generate_backup_code` can undo it. Here the OTP *is*
the recovery factor — the thing standing between a caller who holds the SIM and somebody else's
account — so it has to carry the same weight as the factor it substitutes for. Anything less and the
attacker simply picks the cheaper door, which is the whole argument of §5.

The token is burned in this case too. Strictly redundant once the account is locked, but it keeps one
code path in the model and means the model is still correct if the locking policy ever changes.

### 6.3 Blast radius, and the one place this should *not* be copied

Putting the override on `BaseOTPDevice` changes six other endpoints. All six move from "unlimited
guesses" to "three guesses, then the token is dead":

| Call site | Device | Response after the change |
|---|---|---|
| `users/views.py:995` `confirm_session_otp` | `SessionPhoneDevice` | `401 OTP_EXPIRED` (converted in this ticket) |
| `users/views.py:1054` `verify_email_otp` | `Session`/`UserEmailOTPDevice` | `401 OTP_EXPIRED` (converted in this ticket) |
| `users/views.py:183` `confirm_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `users/views.py:211` `confirm_secondary_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `users/views.py:315` `confirm_recovery_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `users/views.py:358` `confirm_secondary_recovery_otp` | `PhoneDevice` | unchanged bare `401`; token burned |
| `payments/views.py:41` `confirm_payment_profile_otp` | `PhoneDevice` | unchanged bare `401`; token burned |

The four legacy `PhoneDevice` views and the payments one keep their existing response shape — they
are out of scope (§11) and their clients do not know `OTP_EXPIRED`. They still get the token-burning,
which is a genuine behaviour change for them: a client that today retries a wrong code indefinitely
will, after this, need to request a fresh OTP. That is the intended fix, but it is worth QA time on
the payment-profile flow in particular, since that is a live non-Connect-workflow path.

**What is deliberately *not* extended: locking the account on failed phone OTPs.** It is tempting to
say "wrong phone OTP during recovery locks the account too, for symmetry", and this is the one place
symmetry is wrong. The backup-code and recovery-email-OTP lockouts both sit *behind* phone
validation — to trigger them you must already control the number. The session phone OTP sits in
front of it: `start_device_configuration` is `@permission_classes([])` and creates a session from
nothing but a phone number and a Play Integrity token (§1.1). Locking on phone-OTP failure would let
anyone who knows a phone number deactivate that account in three requests, with recovery gated behind
a manual management command. That is a remote, unauthenticated denial of service against every user,
handed over in exchange for symmetry. Phone OTP therefore gets the counter and the token-burning —
case (a), `OTP_EXPIRED` — in every context, recovery included. See D1.


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
| `users/const.py` | `RECOVERY_METHOD_BACKUP_CODE` / `RECOVERY_METHOD_EMAIL_OTP` constants; `MAX_OTP_VERIFY_ATTEMPTS = 3`; `OTP_EXPIRED` error code; `NO_EMAIL_SET` error code if D4 lands. |
| `users/tests/test_views.py` | New `TestCompleteRecoveryApi` (§9). |
| `users/tests/test_models.py` | Counter, burn, reset, and backoff-preservation tests on `BaseOTPDevice` (§9). |

One additive migration, no backfill. No new API version — `AcceptHeaderVersioning` defaults to v2.0
and this endpoint behaves the same in both.

Rough shape:

```python
@api_view(["POST"])
@authentication_classes([SessionTokenAuthentication])
def complete_recovery(request):
    session = request.auth
    if not session.is_phone_validated:
        return JsonResponse({"error_code": ErrorCodes.PHONE_NOT_VALIDATED}, status=403)

    method = request.data.get("method")
    if not method:
        return JsonResponse({"error_code": ErrorCodes.MISSING_DATA}, status=400)
    if method not in (RECOVERY_METHOD_BACKUP_CODE, RECOVERY_METHOD_EMAIL_OTP):
        return JsonResponse({"error_code": ErrorCodes.INVALID_DATA}, status=400)

    user = ConnectUser.objects.get(phone_number=session.phone_number, is_active=True)

    verify = _verify_backup_code if method == RECOVERY_METHOD_BACKUP_CODE else _verify_email_otp
    early_response = verify(request, user)          # None means "verified, carry on"
    if early_response is not None:
        return early_response

    return JsonResponse(_complete_recovery_for_user(user, session))
```

---

## 9. Test plan

`users/tests/test_views.py`, class `TestCompleteRecoveryApi`, using the existing `authed_client_token`
/ `valid_token` / `user` / `session_client` fixtures.

**Auth and preconditions** (method-independent, parametrised over both methods)
- No `Authorization` header → 401.
- Expired session (`expired_token`) → 401 `TOKEN_EXPIRED`.
- Locked user's phone number → 401 `LOCKED_ACCOUNT` (raised in the auth class).
- `is_phone_validated = False` → 403 `PHONE_NOT_VALIDATED`.
- Basic-auth client and OAuth2 bearer client are both rejected — `SessionTokenAuthentication` only.
- No active user for the session's phone → 500.
- Missing `method` → 400 `MISSING_DATA`; `method="sms"` → 400 `INVALID_DATA`.

**`backup_code`**
- Missing `backup_code` → 400 `MISSING_DATA`.
- No backup code set → 400 `NO_RECOVERY_PIN_SET`.
- Wrong code → `{"attempts_left": 2}`, `failed_backup_code_attempts == 1`.
- Third wrong code → 401 `LOCKED_ACCOUNT`, user `is_active=False` and `is_locked=True`.
- Correct code → success payload; `failed_backup_code_attempts` reset to 0.

**`email_otp`**
- Missing `otp` → 400 `MISSING_DATA`.
- `user.email` is unset → 400 `NO_EMAIL_SET`, and `verify_token` is never called.
- No `SessionEmailOTPDevice` for this session + `user.email` → 400 `INVALID_DATA`.
- Device exists on a *different* session for the same email → 400 `INVALID_DATA` (cross-session
  redemption blocked).
- **A device exists on this session for a different email, with a valid OTP → 400 `INVALID_DATA`,
  and `verify_token` is never called.** This is the test that proves the client cannot nominate the
  mailbox: post the correct code for `attacker@evil.com` and it is not merely rejected, it is not
  even looked at. Assert the account is untouched — no password rotation, no `UserDeviceInfo` write.
- **An `email` key in the request body is ignored.** Send `{"method": "email_otp", "otp": <valid>,
  "email": "attacker@evil.com"}` with a valid device on `user.email` → succeeds, because the body's
  address plays no part; and the mirror case, a valid device on `attacker@evil.com` and an `email`
  key naming it → 400 `INVALID_DATA`. Guards against a later refactor quietly reintroducing
  client-supplied addressing.
- Wrong OTP → 401 `INCORRECT_OTP` with `attempts_left == 2`, and `device.failed_verifications == 1`.
- Second wrong OTP → 401 `INCORRECT_OTP`, `attempts_left == 1`, account still active.
- **Third wrong OTP → 401 `LOCKED_ACCOUNT`, `user.is_active is False`, `user.is_locked is True`**,
  and the device's token is burned. Mirror of the existing third-wrong-backup-code test at
  `test_views.py:937-941`; assert both produce the identical response body.
- After the lock, the correct OTP is still refused — the token is gone, and
  `SessionTokenAuthentication` no longer opens a session for that phone number at all.
- `failed_backup_code_attempts` is **unchanged** by wrong email OTPs, and `failed_verifications` is
  unchanged by wrong backup codes. The two counters are independent (§6.1) even though they now share
  a consequence.
- A successful verify resets `failed_verifications` to 0, so a later OTP starts clean.
- Correct OTP → success payload.
- Correct OTP with `email_otp_verification` inactive (`@override_switch(..., active=False)`) →
  403 `NOT_ALLOWED`; the `backup_code` path still succeeds with the switch off.
- Two prior failed backup-code attempts, then email recovery succeeds →
  `failed_backup_code_attempts == 0`.

**Shared completion** (parametrised over both methods so the two paths are proved identical)
- Response contains `username`, `db_key`, `invited_user`; `user.check_password(response["password"])`
  is true; `UserKey` row exists.
- `email` key omitted when the account has none, present when it does.
- Session has no `device` → no `UserDeviceInfo` written, no `previous_device` in the response.
- Same device → existing `UserDeviceInfo` updated, `last_accessed` bumped, no `previous_device`.
- Different device, old one accessed < 30 days ago → new record created, `previous_device` and
  `last_accessed` in the response.
- Different device, old one accessed > 30 days ago → new record, no `previous_device`.

**Failed-verify limit, at the model level** (`users/tests/test_models.py`, parametrised over
`SessionEmailOTPDevice`, `SessionPhoneDevice`, `UserEmailOTPDevice`, `PhoneDevice` — the limit must
behave identically on all four)
- Wrong token increments `failed_verifications`; `verify_attempts_left` counts down 3 → 2 → 1 → 0.
- The third wrong token sets `token = None`, `is_exhausted` true, and a subsequent `verify_token`
  with the **correct** code returns `False`.
- A correct token before exhaustion resets `failed_verifications` to 0.
- `generate_challenge()` on a naturally-expired token resets both `failed_verifications` and the
  send counter `attempts` to 0.
- **`generate_challenge()` after exhaustion resets `failed_verifications` but leaves `attempts`
  intact**, so the `2**attempts` backoff still applies. This is the test that closes the
  burn-and-resend loop described in §6.1 — without it, the limit is decorative.
- Concurrent wrong guesses each count. Two `verify_token` calls racing on one device leave
  `failed_verifications == 2`, not `1` (§6.1). Needs `@pytest.mark.django_db(transaction=True)` and
  threads — there is no existing concurrency test for `_attempt_send` to copy, despite its
  `select_for_update()`, so this pattern is new to the repo. `test_views.py:2493` is the only
  `transaction=True` test currently and it is not concurrent.

**A note on mocking, which affects most of the tests above.** The existing OTP tests patch
`verify_token` wholesale — `@patch("users.models.UserEmailOTPDevice.verify_token")`
(`test_views.py:2495, 2509`, and throughout `TestVerifyEmailOtp`). After §6, patching `verify_token`
patches out the counter with it, so a mocked failure leaves `failed_verifications` at `0` and
`is_exhausted` false — and any view logic branching on `is_exhausted` is then untested, or worse,
silently takes the wrong branch. Every new test that needs the counter must drive real tokens
(`device.generate_token()`, then submit a wrong string) rather than mock the verify. Mocks stay fine
for tests that only care about what happens *after* a successful verify.

**Non-recovery OTP endpoints** (`OTP_EXPIRED`, case (a) of §6.2)
- `verify_email_otp` during registration / edit profile: three wrong OTPs → 401 `OTP_EXPIRED`; the
  account is **not** locked, `user.email` is unwritten, and a fresh `send_email_otp` + correct OTP
  then succeeds (subject to the backoff).
- `confirm_session_otp`: three wrong OTPs → 401 `OTP_EXPIRED`, `session.is_phone_validated` still
  false, no account touched. Explicitly assert no lock, per D1.
- `confirm_payment_profile_otp` and the legacy `PhoneDevice` views keep their bare `401` body but
  stop accepting further guesses on the burned token.

**Regression**
- The existing `TestConfirmBackupCodeApi` and `TestVerifyEmailOtp` classes pass unmodified. That is
  the acceptance criterion for the §8 refactor — with one expected exception: any existing test that
  submits more than `MAX_OTP_VERIFY_ATTEMPTS` wrong OTPs to one device, or that reuses a device
  across sub-cases after failed verifies, will need the counter reset. Those are the only edits
  permitted to the old test classes; a change to an *assertion* in them means the refactor drifted.

---

## 10. Client and rollout impact

*(commcare-android, separate ticket — noted so the two land in the right order.)*

- New `ApiEndPoints.completeRecovery` + `ApiService` method + `PersonalIdApiHandler.completeRecovery`,
  parsing the same payload `confirmBackupCode` parses today into `PersonalIdSessionData`.
- `PersonalIdBackupCodeFragment.confirmBackupCode()` switches to `complete_recovery` with
  `method=backup_code`. Downstream handling is unchanged, including the
  `sessionData.dbKey != null` success test — that is what D3 buys.
- `PersonalIdEmailVerificationFragment` calls `complete_recovery` with `method=email_otp` in the
  mobile spec's `BACKUP_CODE_RECOVERY_SIGN_IN` workflow, then
  `PersonalIdRecoveryCompleter.finalizeAccountRecovery`. Registration, `EXISTING_USER`, and the
  profile-graph `BACKUP_CODE_RECOVERY_SET_CODE` flow keep using `verify_email_otp` — those attach an
  email or gate a local action, they do not recover an account.
- The account keeps its old, forgotten backup code after an `email_otp` recovery. Deliberately not
  the server's problem: the mobile spec already routes straight to `SET_NEW_CODE` and calls
  `set_recovery_pin` with `ProvidedAuth(userId, password)` using the password from this endpoint's
  response, which `DeviceBasicAuthentication` accepts. `complete_recovery` does **not** clear or
  invalidate `recovery_pin` — if the team wants the old code dead the moment email recovery
  succeeds, that is a deliberate addition and needs its own decision, since it would strand any
  client that fails between the two calls.
- `AnalyticsParamValue.CCC_RECOVERY_METHOD_BACKUPCODE` is currently hardcoded in
  `PersonalIdRecoveryCompleter.logRecoverySuccessResult()`. It needs an email variant so the
  recovery-method split is measurable.
- **Two new responses to handle, both from §6, and one of them lands on screens outside recovery.**
  - `401 INCORRECT_OTP` now carries `attempts_left` on `complete_recovery`. The email verification
    screen should show the same "N attempts remaining" warning the backup-code screen already shows,
    and the same "this will lock your account" language on the last attempt — the consequence is now
    identical, and a user who is not warned will meet it by surprise.
  - `401 OTP_EXPIRED` is new and can be returned by `verify_email_otp` and `confirm_session_otp` —
    i.e. on the **registration** and **edit-profile** email screens and the invited-user phone
    screen, not only in recovery. Treat it as "that code is no longer valid": clear the field, tell
    the user to request a new code, and re-enable the resend control. A client that falls through to
    a generic error here leaves the user re-typing a code that can never succeed. Note the resend
    may then hit the existing `429 RATE_LIMITED` with `retry_after_seconds`, which the client
    already handles for `send_email_otp`.
  - The client-side ordering follows from this: `OTP_EXPIRED` handling should ship **before or with**
    the server change, since it affects existing screens on existing builds. It is the one part of
    the client work that is not gated on `complete_recovery`.
- **Rollout order:** server first (both old and new endpoints live), then the client — with the
  `OTP_EXPIRED` caveat above, since older builds will start seeing that code on registration and
  edit-profile screens the moment §6 deploys. Older builds do not break (they show a generic error
  and the user requests a new code), but the UX is poor until the client ships. If that is judged
  unacceptable, the alternative is to gate the `OTP_EXPIRED` response behind a waffle switch and
  return the old bare `401` until client uptake is sufficient — the token is burned either way, so
  the security property does not wait on the client. No deprecation or removal of the old endpoints
  is proposed here; removing them is a later ticket gated on min-supported-version.

---

## 11. Out of scope

- Removing or deprecating `confirm_backup_code` / `verify_email_otp`.
- Any change to registration or to `EXISTING_USER` email attachment, beyond the `OTP_EXPIRED`
  response `verify_email_otp` gains from §6.
- Recovery by secondary phone (`recover/confirm_secondary_otp`) and the `RecoveryStatus` state
  machine — untouched; `complete_recovery` is a `ConfigurationSession` flow and does not read or
  write `RecoveryStatus`. Their `PhoneDevice`s do inherit the failed-verify limit (§6.3), but their
  views and responses are not otherwise changed.
- Any account lockout triggered by phone OTP failures — see D1 for why, and what would have to be
  answered first.
- The `check_name` masked-email hint (D6) — flagged, ticketed separately.

Explicitly **not** out of scope, despite being tempting to defer: the failed-verify limit itself
(§6). It may land as its own ticket sequenced before this one, but the `email_otp` path must not go
live without it.
