# Runtime settings

Some settings can be changed while the service is running, with no deploy or restart. They are kept in the
database by [django-constance](https://django-constance.readthedocs.io/) and edited in Django admin at
`/admin/constance/config/` ("Config" on the admin index). Saving a value takes effect on the next request on
every web and Celery worker. Only superusers, or staff with the `constance.change_config` permission, can
change them.

| Setting | What it does |
|---|---|
| `SMS_SUPPORTED_COUNTRY_CODES` | Calling codes (`265, 258`) `send_sms` may send to. **Empty allows every country.** Keep in sync with the Twilio geo permissions. It doesn't stop the Firebase SMS sent at registration |
| `BLACKLISTED_COUNTRY_CODES` | Two-letter codes (`ke, ng`, any case) refused by `start_device_configuration`, judged by the device's GPS location through Mapbox. No effect without `MAPBOX_ACCESS_TOKEN` or when the device sends no location |
| `PHONE_COUNTRY_*`, `SMS_NUMBER_*`, `OTP_USER_*`, `RATE_LIMIT_WARN_FRACTION` | The SMS and OTP caps. See [rate-limits.md](rate-limits.md) |

The admin form rejects a malformed country list. Code reads a list with `utils.config.code_set("<NAME>")`,
which drops spaces and blanks and returns lowercase codes.

## Blocking a country during an SMS pumping attack

1. In admin, open Config and take the country's calling code out of `SMS_SUPPORTED_COUNTRY_CODES`. This stops
   every SMS we send there through Twilio.
2. To also stop new registrations from devices located there, add its two-letter code to
   `BLACKLISTED_COUNTRY_CODES`.
3. Optionally lower `PHONE_COUNTRY_HOURLY_LIMIT` / `PHONE_COUNTRY_DAILY_LIMIT` to cap all countries harder.

## Env vars only seed the values

Each setting's env var of the same name (e.g. `SMS_SUPPORTED_COUNTRY_CODES=265,258`) gives its starting value.
The first time a setting is read, constance saves that value to the database, and **from then on the env var
is ignored**. To change a setting, use admin. To go back to the env var's value, edit it in admin, or delete
the setting's row (`constance_constance` table, key is the setting name) so the next read saves the env value
again.

## Adding a setting

Add it to `CONSTANCE_CONFIG` in `connectid/settings.py` as `(default, help text, type)`, and to a group in
`CONSTANCE_CONFIG_FIELDSETS`. Read it with `from constance import config; config.MY_SETTING`. Each read is one
database query, so read it where it's used rather than at import time. Keep secrets and anything needed
before Django starts (database, Redis, storage) in env vars.

In tests, the autouse `config` fixture in `conftest.py` keeps values in memory and resets them for each test:
`def test_x(config): config.MY_SETTING = 1`.
