# Rate limits

SMS and OTPs are capped to keep costs down and stop abuse. The counters live in the Redis `rate_limit` cache
(`utils/rate_limit.py`). If Redis can't be reached, everything is allowed, and the failure goes to Sentry as
`Rate limit cache unavailable`.

The limits are runtime settings: change them in Django admin under Config, with no restart. See
[runtime-config.md](runtime-config.md).

| Limit | Key | Settings (default) | When it's hit |
|---|---|---|---|
| Per country, SMS | `sms:country:<cc>` | `PHONE_COUNTRY_HOURLY_LIMIT` (50), `PHONE_COUNTRY_DAILY_LIMIT` (300) | `send_sms` raises `SmsRateLimitedError` |
| Per country, new configuration sessions | `configuration_session:country:<cc>` | same as above | `start_device_configuration` returns 429 |
| Per number | `sms:number:<e164>` | `SMS_NUMBER_HOURLY_LIMIT` (5), `SMS_NUMBER_DAILY_LIMIT` (10) | `send_sms` raises `SmsRateLimitedError` |
| Per user, OTPs across all their numbers | `otp:user:<id>` | `OTP_USER_HOURLY_LIMIT` (10), `OTP_USER_DAILY_LIMIT` (20) | `RateLimitedError` |
| Per OTP device, resend cooldown | none (kept on the device row) | doubles with each send: 1, 2, 4… minutes | `RateLimitedError` |

## What gets logged

Each event is logged by the `utils.rate_limit` logger as one line, `<event> key=value ...`. The same fields are
attached to the log record as `rate_limit`, and to Sentry events as `rate_limit.<field>` tags. Phone numbers
are never logged in full: only `country_code` and `number_ending` (the last 3 digits).

| Event | Level | When |
|---|---|---|
| `rate_limit_blocked` | WARNING | Every rejected SMS or OTP, including resends during the cooldown |
| `rate_limit_approaching` | ERROR for country limits (reaches Sentry), WARNING otherwise | A count reaches `RATE_LIMIT_WARN_FRACTION` (0.8) of the limit. Once per window |
| `rate_limit_reached` | ERROR (reaches Sentry) | The first rejection of a country limit in a window. Once per window |
| `rate_limit_suppressed` | WARNING | An OTP was rate limited, but the endpoint reported success. The user is waiting for a code that isn't coming |

Fields: `scope` (`sms`, `configuration_session`, `otp`), `kind` (`country`, `number`, `user`, `resend_cooldown`),
`country_code`, `number_ending`, `user_id`, `device`, `window_seconds`, `max_count`, `count`,
`retry_after_seconds`.

Example:

```
WARNING 2026-11-16 10:02:11,431 utils.rate_limit rate_limit_blocked scope=sms kind=number country_code=265 number_ending=567 window_seconds=3600 max_count=5 count=6 retry_after_seconds=1312
ERROR 2026-11-16 10:40:57,002 utils.rate_limit rate_limit_approaching scope=sms kind=country country_code=265 window_seconds=3600 max_count=50 count=40
```

## Looking at them

Logs go to CloudWatch, in the `connect-id-web` and `connect-id-celery` log groups.

Blocks per hour, by what was limited (CloudWatch Logs Insights):

```
fields @timestamp, @message
| filter @message like /rate_limit_blocked/
| parse @message /scope=(?<scope>\S+) kind=(?<kind>\S+)/
| parse @message /country_code=(?<country_code>\d+)/
| stats count() as blocked by bin(1h), scope, kind, country_code
| sort bin(1h) desc
```

The users blocked most often today:

```
fields @message
| filter @message like /rate_limit_(blocked|suppressed)/ and @message like /user_id=\d/
| parse @message /^\S+ \S+ \S+ \S+ (?<event>\S+)/
| parse @message /user_id=(?<user_id>\d+)/
| stats count() as events by user_id, event
| sort events desc
| limit 25
```

Everything about one user (e.g. for a "never got my code" support ticket): filter on `user_id=<id>`.

To get alerts or a dashboard, add metric filters to the log groups and alarm on them. For example, the filter
pattern `"rate_limit_blocked" "kind=country"` gives a count of country blocks, and `"rate_limit_suppressed"`
gives a count of codes that silently weren't sent.

In Sentry, `rate_limit_approaching` and `rate_limit_reached` are one issue per country and window. Filter
them with the `rate_limit.country_code` and `rate_limit.scope` tags.
