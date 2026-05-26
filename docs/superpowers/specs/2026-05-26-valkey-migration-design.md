# Valkey Instance Migration

**Date:** 2026-05-26
**Status:** Draft

## TL;DR
We're moving from one Valkey instance (which has clustering enabled) to another (which does not have clustering enabled) for ConnectID's celery broker. This is to fix an issue that currently exist with ConnectID celery on production.  

## Context

**Error observed**
ConnectID currently uses a Valkey instance to broker Celery, but this instance has clustering **enabled**. With clustering enabled Vakey creates "logical slots" and lables key-value pairs to aid routing to different physical servers. 
Even with topologies like the one we currently have for production, which have a single node, these slots are still created and assigned meaning a `CROSSSLOT` error is still a possibility if a multi-key operation run is attempted which spans multipl slots. A CROSSSLOT error is a security/performance guardrail built into the database cluster engine which basically says "you're not allowed to run a multi-key operation or transaction block if the keys belong to different slot numbers", but this is exactly what happens when celery is booted.   

Disabling clustering would solve this issue.

**Solution proposal**
Connect's Redis instance does not have clustering enabled so it makes sense that we also disable clustering for ConnectID's Valkey instance, but simply disabling it is not possible - we should create a new instance and migrate from the old instance.

We'll simply flip `CELERY_BROKER_URL` to the new endpoint, redeploy, run a smoke test, done. No drain, no parallel-run, no pre-cutover verification dance — there is nothing in the broker to preserve and no live traffic to protect during the swap.

**Where Valkey is used**
Valkey is used for exactly one purpose: the Celery broker (`CELERY_BROKER_URL` in `connectid/settings.py:228`). There is:

- No Django `CACHES` configuration — no app-level cache data in Valkey.
- No `CELERY_RESULT_BACKEND` configured — task results aren't stored.
- No direct `redis.Redis(...)` client usage anywhere in the project.
- No Celery beat schedule in Valkey — `DatabaseScheduler` (Postgres) and a file-backed schedule on a named volume hold this, per recent commits (`8f04d6a`, `0013568`).

**Operational state at time of migration:** Celery beat is running in production but not executing any tasks. The only ad-hoc task dispatch site (`send_ga_event.delay()` in `utils/analytics.py:58`) has no callers in the codebase. The broker is effectively dormant — no tasks are produced, none are queued.

This reduces the migration to a configuration swap with a post-deploy smoke test.

## Impacted Celery Tasks

All four registered tasks are unaffected by the broker swap because the broker is empty at cutover. The "Action" column reflects the migration treatment for each task's queue state in Valkey.

| Task | Definition | Trigger | Queue State at Cutover | Action |
|------|-----------|---------|------------------------|--------|
| `messaging.tasks.delete_old_messages` | `messaging/tasks.py:73` | Beat (daily) | Empty — beat off in prod | Leave (blank slate) |
| `messaging.tasks.resend_notifications_for_undelivered_messages` | `messaging/tasks.py:82` | Beat (hourly) | Empty — beat off in prod | Leave (blank slate). Idempotent: re-queries Postgres each run, so any missed invocation is auto-recovered. |
| `users.tasks.upload_connect_users_to_superset` | `users/tasks.py:147` | Beat (daily 00:00) | Empty — beat off in prod | Leave (blank slate) |
| `send_ga_event` | `utils/analytics.py:61` | Ad-hoc via `.delay()` | Empty — caller `send_bulk_events_to_ga` has no callers | Leave (blank slate) |

**No task state requires migration.**

## Steps

1. Confirm the new Valkey endpoint and credentials are available.
2. Update `CELERY_BROKER_URL` in the Kamal secrets / env store to the new endpoint (likely `rediss://...` if AWS Valkey enforces TLS).
3. Redeploy workers. Web/API redeploy is bundled in the same release to keep env consistent.
4. **Smoke test.** From `./manage.py shell` against production:
   ```python
   from messaging.tasks import delete_old_messages
   delete_old_messages.delay()
   ```
   Confirm a prod worker picks up the task and the DB delete runs. `delete_old_messages` is idempotent (deletes messages older than 7 days), so running it ad-hoc is safe.
5. Done.

## Rollback

If the smoke test fails (TLS handshake, auth, SG, endpoint typo, anything else) **and the old instance is still reachable**:

1. Revert `CELERY_BROKER_URL` to the old endpoint in Kamal secrets / env.
2. Redeploy.
3. Diagnose the new instance offline.

Expected revert time: ~10 minutes (one deploy cycle).
