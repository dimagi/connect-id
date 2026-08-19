# `complete_recovery` — a single endpoint for account recovery

**Status:** Draft — for team review
**Ticket:** [CCCT-2708](https://dimagi.atlassian.net/browse/CCCT-2708)
**Repo:** `connect-id` (server). Client counterpart lands in `commcare-android`.
**Replaces (for new clients):** `POST /users/recover/confirm_backup_code`, `POST /users/verify_email_otp`
**Answers:** the "Server Team Request" section of the mobile tech spec —
[commcare-android#3843](https://github.com/dimagi/commcare-android/pull/3843) /
[CCCT-2677](https://dimagi.atlassian.net/browse/CCCT-2677),
`docs/superpowers/specs/2026-07-28-personalid-backup-code-management-design.md`

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

Both existing endpoints stay exactly as they are so older clients keep working. Nothing about their
behaviour changes except (optionally, see §7) an internal refactor that has `confirm_backup_code`
call the same shared completion helper.

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
`verify_email_otp`'s verification mechanics. §5 is the part of this document that most needs review,
because that is where the new factor's security properties are pinned down.

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

*Answer: (b), and masked rather than in full — see D6.* (a) has a problem worth being explicit
about: `start_device_configuration` is `@permission_classes([])` (`users/views.py:93-96`), gated
only by app integrity. It is the call that *creates* the session, so there is no phone validation
behind it. Returning the account's email there turns "phone number → email address" into a lookup
available to anyone who can produce a valid Play Integrity token. `check_name` at least sits behind
`is_phone_validated` (`users/views.py:943`), so the caller has already proved control of the number.
This one is a genuine client/server disagreement and should get an explicit decision rather than
being settled by whichever spec merges first.

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
     * User retrieves and enters the OTP and submits
 * On submission of either of the above options:
   * Mobile makes the new `complete_recovery` request with the chosen `method` and associated data

The session token is the only credential. `SessionTokenAuthentication` already rejects an unknown
key (`401 INVALID_TOKEN`), an expired session (`401 TOKEN_EXPIRED`), and a phone number belonging to
a locked account (`401 LOCKED_ACCOUNT`) before the view body runs.

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
| `otp` | `method=email_otp` | The code mailed by `send_email_otp` for this session + email. |

Fields belonging to the other method are ignored, not rejected.

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

`email` is present only when the account has one. `previous_device` / `last_accessed` are present
only when the session carries a `device` **and** a *different* device was seen on the account within
`DEVICE_RECENT_ACCESS_THRESHOLD` (30 days) — byte-for-byte the rule in `confirm_backup_code`
(`users/views.py:602-626`).

### Wrong-backup-code response — `200` (see decision D3)

```json
{ "attempts_left": 2 }
```

### Errors

| Status | `error_code` | When |
|---|---|---|
| 400 | `MISSING_DATA` | `method` absent, or the selected method's fields are absent/blank |
| 400 | `INVALID_DATA` | `method` not one of the two values; no pending email OTP device for this session+email |
| 400 | `NO_RECOVERY_PIN_SET` | `backup_code` and the account has no backup code set |
| 401 | `INCORRECT_OTP` | `email_otp` and the code is wrong or expired |
| 401 | `LOCKED_ACCOUNT` | the third consecutive wrong backup code — the account is deactivated and locked |
| 403 | `PHONE_NOT_VALIDATED` | `session.is_phone_validated` is false |
| 403 | `NOT_ALLOWED` | `email_otp` requested while the `email_otp_verification` switch is off (decision D2) |
| 404 | `USER_DOES_NOT_EXIST` | no active `ConnectUser` for the session's phone number (decision D5) |
| 4xx | *(D4)* | `email_otp` and the email does not match the account's — code TBD, see §5 |

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

- `user.check_recovery_pin(recovery_pin)`.
- `RecoveryPinNotSetError` → `400 NO_RECOVERY_PIN_SET`.
- Wrong code → `user.add_failed_backup_code_attempt()`. If `backup_code_attempts_left` is then `0`
  (`MAX_BACKUP_CODE_ATTEMPTS = 3`), set `is_active = False`, `is_locked = True`, save, and return
  `401 LOCKED_ACCOUNT`. Otherwise return `{"attempts_left": n}` — see D3 on the status code.
- Correct → §4.3.

### 4.2 `method = email_otp`

- `email` and `otp` both required and non-blank after `.strip()` → else `400 MISSING_DATA`.
- Look up `SessionEmailOTPDevice.objects.get(session=request.auth, email=email)`. Not found →
  `400 INVALID_DATA`. Binding the device to *this session* is what stops an OTP issued to one
  session being redeemed by another.
- **The email must match the account's email** — §5. This is the load-bearing rule.
- `device.verify_token(otp)` → false gives `401 INCORRECT_OTP` and logs the masked email, matching
  `verify_email_otp` (`users/views.py:1054-1056`). django-otp's `SideChannelDevice.verify_token`
  clears the stored token on success, so a code cannot be replayed — worth re-confirming against the
  pinned django-otp version during implementation, since the replay property depends on it.
- Success → §4.3.

Note there is deliberately **no `user.email = email` write** on this path: the matching rule in §5
means the email is already the account's. The only account-email writes stay in
`verify_email_otp` / `complete_profile`.

### 4.3 Shared completion

Exactly what `confirm_backup_code` does today, extracted into one helper so the two endpoints cannot
drift:

1. `password = token_hex(16)`; `user.set_password(password)`.
2. `user.reset_failed_backup_code_attempts()` — **including on the `email_otp` path.** A user who
   burned two backup-code attempts and then recovered by email should not be left one mistake away
   from a locked account. Called out because it is a genuine behaviour choice, not a mechanical
   copy.
3. `user.save()`.
4. Device bookkeeping when `session.device` is set: same device → update `UserDeviceInfo` password
   and `last_accessed`; different device → create a new record and, if the old one was accessed
   within 30 days, add `previous_device` / `last_accessed` to the response.
5. Build and return the payload in §3.

The whole of step 1–4 should run inside a single `transaction.atomic()` block. It does not today,
and a failure between the password rotation and the device write leaves the client without the
password that now authenticates the account. Cheap to fix while the code is being extracted.

---

## 5. Security: the email-match rule

**Requirement: `method=email_otp` succeeds only if the submitted email is already the email on the
account being recovered** (compared case-insensitively; `ConnectUser.email` is a `EmailField`).

Why this is not optional. The session has proved exactly one thing: the caller controls the phone
number. Recovery today requires a second factor on top of that — the backup code, something the
caller knows. `send_email_otp` on a `ConfigurationSession` will mail an OTP to *any* address the
caller types (`users/views.py:1010-1021`); it has no notion of the account's email. If
`complete_recovery` accepted any verified mailbox, then anyone holding the SIM — a recycled number,
a stolen or swapped SIM, a shared handset — recovers the account by mailing themselves an OTP. The
second factor would be decorative.

The check therefore belongs in `complete_recovery`, before `verify_token`, and it is the reason this
endpoint cannot simply delegate to the existing `verify_email_otp` view.

Corollaries worth having on the record:

- An account with no email set can never recover by `email_otp`. Same error as a mismatch (D4).
- **Nothing in the codebase limits wrong OTP guesses**, on any OTP, and that becomes a much sharper
  problem here. Verified: all seven `verify_token` call sites (`users/views.py` 183, 211, 315, 358,
  995, 1054 and `payments/views.py:41`) return a bare `401` with no counter; `BaseOTPDevice` extends
  `SideChannelDevice` *without* django-otp's `ThrottlingMixin`; the `attempts` field on
  `BaseOTPDevice` is a **send** counter driving the `2**attempts` minute resend backoff, not a
  verify counter, and it resets to `0` on every fresh token. A failed verify does not invalidate the
  token either — django-otp clears it only on success. So a 6-digit code is guessable without limit
  for its full 30-minute window (`EMAIL_OTP_VALIDITY_SECONDS`, default 1800). The only incidental
  brake is DRF's `UserRateThrottle` at 10000/day, which probably does not bucket per caller here:
  `SessionUser` subclasses `AnonymousUser`, whose `pk` is `None`, and DRF keys the bucket on
  `request.user.pk`. That is an accident, not a control. See D1 — this is the one item in this
  document I would not ship without.
- Contrast with the backup code, the only lockout in the system: `MAX_BACKUP_CODE_ATTEMPTS = 3`,
  counted on `ConnectUser.failed_backup_code_attempts` so it persists across sessions, and the third
  failure sets `is_active=False, is_locked=True` (`users/views.py:581` — the sole assignment in the
  codebase), after which `SessionTokenAuthentication` refuses to open any new session for that phone
  number and only the `unlock_and_generate_backup_code` management command can undo it. The
  hardened factor and the unguarded one are about to become interchangeable ways into an account.
- The endpoint stays replay-safe for the same OTP (the token is cleared on verify) but is *not*
  idempotent: every successful call rotates the password again. That matches `confirm_backup_code`
  and we are not proposing to change it.

---

## 6. Decisions to confirm

These are the review targets. Each has a recommendation; none is settled.

**D1 — A failed `email_otp` attempt must be counted. What counts it?** *(highest priority)*
Backup code has a hard 3-strike lockout. Email OTP has **no verify-side limit whatsoever** — see the
verified detail in §5. Today that is tolerable, because brute-forcing an email OTP only lets you
attach an email to an account whose phone you have already validated. The moment `email_otp` becomes
a recovery method, the same brute force hands over the account: 10⁶ combinations, unguarded, for the
token's full 30-minute life. The hardened factor and the unguarded one become interchangeable, which
defeats the point of hardening either.

Options: (a) leave it; (b) share the existing `failed_backup_code_attempts` counter; (c) add a
separate per-device failed-verify counter that invalidates the OTP (not the account) after N wrong
guesses.
*Recommendation: (c), in this ticket rather than as a follow-up.* Cheapest form: a
`failed_verifications` field on `BaseOTPDevice`, incremented on a false `verify_token`, which clears
the token once it hits ~5 and forces the user to request a new OTP — bounding guesses per token
while the existing send-side backoff bounds tokens per hour. That composes to a real limit without
inventing a second lockout.
(a) is what I first proposed here and I no longer think it is defensible for a recovery factor.
(b) is wrong regardless — it would let wrong email OTPs lock an account out of its backup code, and
it would corrupt the `attempts_left` number the client shows.
Note (c) improves every other OTP endpoint at the same time, since they all share `BaseOTPDevice`;
the team may prefer to split that into its own ticket sequenced *before* this one, which is fine, but
`complete_recovery` should not ship with the `email_otp` path unguarded.

**D2 — How does the `email_otp_verification` waffle switch gate this endpoint?**
`verify_email_otp` is wrapped in `@waffle_switch(EMAIL_OTP_VERIFICATION)`, which 404s the whole view
when inactive. We cannot do that here without also killing the `backup_code` path.
*Recommendation: no decorator on the view; check the switch inside the `email_otp` branch and return
`403 NOT_ALLOWED` when it is off.* All waffle switches are already shipped to the client in
`start_configuration`'s `toggles` (`flags/utils.get_user_toggles`), so the client should never reach
this state — the 403 is a backstop, not a UX path.

**D3 — Keep `200 {"attempts_left": n}` for a wrong backup code, or make it a `401`?**
Today a wrong backup code is a `200`, which is why the client checks `sessionData.dbKey != null` to
tell success from failure (`PersonalIdBackupCodeFragment:186`). A new endpoint is the clean moment
to make it `401 INCORRECT_CODE` with `attempts_left` in the body.
*Recommendation: keep the `200` for v1.* The client has to branch on method anyway, and identical
semantics keep the old and new paths sharing one handler while both are live. Worth spending the
change if the team disagrees — this is the last chance to fix it.

**D4 — What error does an email mismatch return?**
Options: reuse `400 INVALID_DATA` (indistinguishable from "no pending device", so it leaks nothing
extra), or add a specific code such as `EMAIL_MISMATCH` so the client can say something useful.
*Recommendation: a new `403 EMAIL_MISMATCH`.* The caller already controls the phone, so the
enumeration concern is thin, and "that isn't the email on this account" is exactly what the user
needs to be told. Needs a matching client string.

**D5 — What happens when no active user exists for the session's phone number?**
`confirm_backup_code` calls `.get()` unguarded, so this is a `ConnectUser.DoesNotExist` → `500`
today. *Recommendation: catch it and return `404 USER_DOES_NOT_EXIST` in the new endpoint.* Do not
retrofit the old one; a client that reaches this state has skipped `check_name`.

**D6 — How does the client learn that `email_otp` is available for this account?** *(client/server
disagreement — needs an explicit decision)*
The endpoint is unusable without an answer, and the mobile spec asks for one directly (§1.1, their
Q2). `check_name` returns `account_exists` and a photo, not whether the account has an email.
Without a hint, a user picks "recover by email", types an address, receives an OTP, verifies it, and
only *then* gets rejected for a mismatch — a bad flow, and a way to make us mail OTPs to arbitrary
addresses.

The client's stated preference is `start_configuration` returning `email`, "available from the very
start of the configuration flow". *Recommendation: `check_name` instead, returning a masked hint
(e.g. `d***@gmail.com`) plus an `email_recovery_available` boolean.* Two reasons:

- `start_device_configuration` is unauthenticated (`@permission_classes([])`, `users/views.py:93-96`)
  and gated only by app integrity — it is the call that creates the session, so nothing has proved
  control of the phone number yet. Returning the account's email makes phone → email a harvesting
  lookup. `check_name` runs behind `is_phone_validated` (`users/views.py:943`).
- The client only needs to *offer the option* and prefill; it never needs the full address, because
  `complete_recovery` matches server-side against `user.email` (§5). A mask is sufficient for the UI
  and leaks materially less if the phone factor is ever compromised.

If the flow genuinely needs this before `check_name` runs, the better answer is a third call behind
phone validation, not widening `start_configuration`. Build is a separate ticket either way;
sequence it *before* the client work.

**D7 — Path.** `recover/complete_recovery` (verbose but matches the URL name and the `recover/`
grouping) vs `recover/complete`. *Recommendation: `recover/complete_recovery`.* Trivial; just needs
picking before the client is written.

---

## 7. Implementation sketch

| File | Change |
|---|---|
| `users/urls.py` | `path("recover/complete_recovery", views.complete_recovery, name="complete_recovery")` |
| `users/views.py` | New `complete_recovery` view. Extract `_complete_recovery_for_user(user, session) -> dict` and `_apply_device_info(user, session, response_data)` from the tail of `confirm_backup_code`. Extract the backup-code verification into a helper the two views share. |
| `users/views.py` | `confirm_backup_code` calls the extracted helpers — **no behaviour change**, so its existing tests must pass untouched. |
| `users/const.py` | `RECOVERY_METHOD_BACKUP_CODE` / `RECOVERY_METHOD_EMAIL_OTP` constants; `EMAIL_MISMATCH` error code if D4 lands. |
| `users/tests/test_views.py` | New `TestCompleteRecoveryApi` (§8). |

No model changes and no migration. No new API version — `AcceptHeaderVersioning` defaults to v2.0
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

    try:
        user = ConnectUser.objects.get(phone_number=session.phone_number, is_active=True)
    except ConnectUser.DoesNotExist:
        return JsonResponse({"error_code": ErrorCodes.USER_DOES_NOT_EXIST}, status=404)

    verify = _verify_backup_code if method == RECOVERY_METHOD_BACKUP_CODE else _verify_email_otp
    early_response = verify(request, user)          # None means "verified, carry on"
    if early_response is not None:
        return early_response

    return JsonResponse(_complete_recovery_for_user(user, session))
```

---

## 8. Test plan

`users/tests/test_views.py`, class `TestCompleteRecoveryApi`, using the existing `authed_client_token`
/ `valid_token` / `user` / `session_client` fixtures.

**Auth and preconditions** (method-independent, parametrised over both methods)
- No `Authorization` header → 401.
- Expired session (`expired_token`) → 401 `TOKEN_EXPIRED`.
- Locked user's phone number → 401 `LOCKED_ACCOUNT` (raised in the auth class).
- `is_phone_validated = False` → 403 `PHONE_NOT_VALIDATED`.
- Basic-auth client and OAuth2 bearer client are both rejected — `SessionTokenAuthentication` only.
- No active user for the session's phone → 404 `USER_DOES_NOT_EXIST`.
- Missing `method` → 400 `MISSING_DATA`; `method="sms"` → 400 `INVALID_DATA`.

**`backup_code`**
- Missing `recovery_pin` → 400 `MISSING_DATA`.
- No backup code set → 400 `NO_RECOVERY_PIN_SET`.
- Wrong code → `{"attempts_left": 2}`, `failed_backup_code_attempts == 1`.
- Third wrong code → 401 `LOCKED_ACCOUNT`, user `is_active=False` and `is_locked=True`.
- Correct code → success payload; `failed_backup_code_attempts` reset to 0.

**`email_otp`**
- Missing `email` or `otp` → 400 `MISSING_DATA`.
- No `SessionEmailOTPDevice` for this session+email → 400 `INVALID_DATA`.
- Device exists on a *different* session for the same email → 400 `INVALID_DATA` (cross-session
  redemption blocked).
- Email does not match `user.email` → per D4, and `verify_token` is never called.
- `user.email` is null → same rejection.
- Email matches but differs in case → accepted.
- Wrong OTP → 401 `INCORRECT_OTP` (patch `SessionEmailOTPDevice.verify_token` → `False`, as the
  existing `TestVerifyEmailOtp` does).
- Per D1: N consecutive wrong OTPs invalidate the token — the (N+1)th request fails even when the
  *correct* code is supplied, and the account is **not** locked (`is_active` and `is_locked`
  unchanged, `failed_backup_code_attempts` unchanged). This is the test that proves email-OTP
  failures and backup-code failures have separate consequences.
- A successful verify resets the device's failed-verify count, so a later OTP starts clean.
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

**Regression**
- The existing `TestConfirmBackupCodeApi` and `TestVerifyEmailOtp` classes pass unmodified. That is
  the acceptance criterion for the §7 refactor.

---

## 9. Client and rollout impact

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
- **Rollout order:** server first (both old and new endpoints live), then the client. No deprecation
  or removal of the old endpoints is proposed here; removing them is a later ticket gated on
  min-supported-version.

---

## 10. Out of scope

- Removing or deprecating `confirm_backup_code` / `verify_email_otp`.
- Any change to registration or to `EXISTING_USER` email attachment.
- Recovery by secondary phone (`recover/confirm_secondary_otp`) and the `RecoveryStatus` state
  machine — untouched; `complete_recovery` is a `ConfigurationSession` flow and does not read or
  write `RecoveryStatus`.
- The `check_name` masked-email hint (D6) — flagged, ticketed separately.

Explicitly **not** out of scope, despite being tempting to defer: failed-verify limiting on email
OTPs (D1). It may land as its own ticket sequenced before this one, but the `email_otp` path should
not go live without it.
