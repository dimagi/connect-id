### Testing messaging with a phone

`local_message_server` stands in for an external message server such as OCS. It creates the
rows a phone needs (the Android app's OAuth application and its own message server record),
lists users, serves the channel key to the phone, sends messages from a prompt, and prints the
phone's replies. It only runs with `DEBUG=True`.

The phone must reach both PersonalID and this server. With a USB-connected device and
everything on localhost, `adb reverse tcp:8000 tcp:8000` and `adb reverse tcp:8001 tcp:8001`
do that and the defaults below work. Otherwise bind both to the dev machine's LAN address
and pass it with the flags.

1. In `.env`, disable the external services (see "Running locally without external services"
   in the top-level README) and set `CELERY_TASK_ALWAYS_EAGER=True`, which messaging needs
   because the sync endpoint reads rows a Celery task creates.

2. Start PersonalID, and in a second terminal the message server:

   ```bash
   uv run ./manage.py runserver 0.0.0.0:8000
   uv run ./manage.py local_message_server --personalid-url http://<dev-machine-ip>:8000 --public-url http://<dev-machine-ip>:8001
   ```

   `--listen` sets the host:port it binds (default `0.0.0.0:8001`); `--public-url` is how the
   phone and PersonalID reach it, and is what gets stored as the channel's `key_url`.
   `--setup-only` creates the rows, lists users and exits.

3. Register in the app with a user valid to this personalid server (note: demo numbers skip
   OTP). Then, at the prompt, with the username from the `users` list:

   ```
   channel <username> Local bot
   send last Hello from the laptop
   ```

   There is no push locally, so open the messaging screen in the app to sync. Replies from the
   phone appear at the prompt. Channel keys persist in `.local_temp_state/`; delete it to start
   over.
