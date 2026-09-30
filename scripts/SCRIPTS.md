Scripts for local evaluation and testing of the code outside of a production environment.

## Messaging tester

Create a sender to test messaging with a local device.

Note: Your phone will need to be able to reach PersonalID and the sending script for messaging.

If you are running everything on localhost, you can use adb port forwarding and skip the manual
ip/port settings below. Otherwise, use the flags for settings the ip and sender below.

1. In `.env`, set `LOCAL_MODE=True` and `CELERY_TASK_ALWAYS_EAGER=True`. The second is needed
   because the sync endpoint reads rows that a Celery task creates.

2. Create and register a test app the phone and the sender script need. This is safe to re-run.

   ```bash
   uv run ./manage.py seed_local_messaging --sender-url http://<subnet_ip>:8001
   ```

   It creates the OAuth application the Android app uses for token requests, and a message server
   record for the sender script, then prints the command to run the script with.

3. Start the server and, in a second terminal, the sender. The sender stands in for a real
   message server such as OCS: it serves the channel key to the phone, sends messages, and
   prints replies.

   ```bash
   uv run ./manage.py runserver <subnet_ip>:8000
   uv run python scripts/local_sender.py --personalid http://<subnet_ip>:8000 --client-id ... --secret ... serve
   ```

4. Configure your CommCare test build to communicate with the server.

Your phone will need to be able to reach PersonalID and the sending script for messaging.

If you don't have a local network that supports the routing, you can forward through adb on
a local USB-connected device.

```bash
adb reverse tcp:8000 tcp:8000
adb reverse tcp:8001 tcp:8001
```

The app needs a build whose PersonalID address can be changed; the release build's is fixed.

5. Register or login as a user wtih the mobile. Then, at the sender's prompt, using the username
   `seed_local_messaging` lists:

   ```
   channel <username> Local bot
   send last Hello from the laptop
   ```

   There is no push locally, so open the messaging screen in the app to sync. Replies from the
   phone appear in the sender's terminal.
