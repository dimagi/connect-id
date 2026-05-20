# Revert django-celery-beat Migrations via Kamal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to walk this runbook task-by-task with a human reviewer at each checkpoint. Steps use checkbox (`- [ ]`) syntax for tracking. **This plan touches production data. Do not run any step without confirming the previous step's expected output.**

**Goal:** In production, undo the partial migration state left by the failed 2026-05-18 DatabaseScheduler deploy: drop the `django_celery_beat_*` tables, clear their rows from `django_migrations`, and remove the orphan `messaging.0008` row from `django_migrations`. Verify the database is in the state the file-scheduler branch expects. (The actual deploy of the file-scheduler branch happens separately, outside this plan.)

**Architecture:** We run one-off Kamal containers from the previously-built image at commit `9a63688ee4ff31aef31017a88ac4401e38270d9a` (the merge of PR #227, the SHA from the failed 2026-05-18 deploy), which has `django_celery_beat` registered (with `DatabaseScheduler`), `django-celery-beat==2.9.0` in requirements, and the `messaging/migrations/0008_periodic_tasks.py` file present. Two `manage.py migrate` commands clean up state, run in this order:

1. `migrate messaging 0007` — runs `0008`'s `reverse_code` (`remove_periodic_tasks`), which deletes the 3 PeriodicTask rows, and then removes the `0008` row from `django_migrations`. Done first because `0008` declares `dependencies = [..., ("django_celery_beat", "0019_alter_periodictasks_options")]`; if we ran `django_celery_beat zero` first, Django would cascade-unapply `0008` as part of that command anyway. Splitting it out makes each command do exactly one thing, and ordering it first guarantees the `django_celery_beat` tables still exist when `remove_periodic_tasks` runs.
2. `migrate django_celery_beat zero` — drops all `django_celery_beat_*` tables (now empty after Task 4) and clears their rows from `django_migrations`. No cross-app cascade because the only dependent (`messaging.0008`) is already cleared from the recorder.

**Tech Stack:** Kamal 1.9.3, Docker, AWS ECR, PostgreSQL (prod RDS), Django 4.1, django-celery-beat.

**Pre-flight assumptions (verify before starting):**
- Local `deploy/config/deploy.yml` parses cleanly (`cd deploy && kamal config` returns YAML, not an error).
- Production is running the pre-DatabaseScheduler image. Already confirmed: both `web` and `celery` are on SHA `1d4f968b0865...`, healthy.
- A recent RDS snapshot exists.
- The container image **does not** include a `psql` binary, so `manage.py dbshell` is unavailable. All verification uses `manage.py showmigrations` and `manage.py shell -c "..."`; all DB mutation goes through `manage.py migrate`.
- Local uncommitted changes are out of scope.
- Deploying the file-scheduler branch is **out of scope** for this plan — handled separately. This plan ends when the DB state is verified clean.

---

### Task 1: Identify and verify the rollback image

**Why:** We need an image whose code still has `django_celery_beat` in `INSTALLED_APPS` and the `messaging/migrations/0008_*` file present, otherwise neither migrate command can run.

**Files:**
- Read only: `deploy/config/deploy.yml` (already validated)

- [ ] **Step 1: Confirm the rollback commit SHA**

The image tag in ECR matches the full git commit SHA Kamal built from. The target is `9a63688ee4ff31aef31017a88ac4401e38270d9a` — the merge of PR #227, the SHA that produced the image deployed on 2026-05-18. Verify it's an ancestor of `main`:

```bash
git merge-base --is-ancestor 9a63688ee4ff31aef31017a88ac4401e38270d9a main && echo "OK: ancestor of main" || echo "NOT an ancestor — pick a different SHA"
```
Expected: `OK: ancestor of main`.

Capture for later steps:
```bash
export ROLLBACK_SHA=9a63688ee4ff31aef31017a88ac4401e38270d9a
```

- [ ] **Step 2: Confirm the image exists in ECR**

```bash
aws ecr describe-images \
  --repository-name connectid \
  --image-ids imageTag=$ROLLBACK_SHA \
  --region us-east-1 \
  --query 'imageDetails[0].imagePushedAt' --output text
```
Expected: a timestamp from 2026-05-18 (the failed deploy build).

If you get `ImageNotFoundException`, STOP — the image must be present. Rebuild via `kamal build push --version $ROLLBACK_SHA` against a checkout of that commit before continuing.

---

### Task 2: Pre-flight verification (read-only)

**Why:** Before destructive ops, confirm the symptoms match the incident notes — `django_celery_beat` migrations recorded as applied + `messaging.0008` recorded as applied. If state differs, the rest of the plan may not be correct.

**Files:** none

- [ ] **Step 1: Confirm django_celery_beat migrations are recorded as applied**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py showmigrations django_celery_beat"
```
Expected: a list of migrations, **all marked with `[X]`** (applied). Typically ~18 migrations ending around `0018_*` or `0019_*` depending on the django-celery-beat version pinned in `requirements.txt`.

If any are `[ ]` (unapplied), the database state is partial — record exactly which are applied vs not, and pause for review before proceeding. `migrate ... zero` still handles partial state correctly, but you want a record before changing anything.

- [ ] **Step 2: Confirm messaging migrations include the orphan 0008**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py showmigrations messaging"
```
Expected: migrations `0001_initial` through `0008_*` all marked `[X]`. The `0008_*` line is the orphan we are going to remove.

Record the exact name of the `0008_*` migration shown — it should match the data migration that seeded the celery-beat schedule.

- [ ] **Step 3: Confirm the PeriodicTask row count matches the incident notes (3 rows)**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA \
  "./manage.py shell -c 'from django_celery_beat.models import PeriodicTask; print(PeriodicTask.objects.count())'"
```
Expected: `3`.

If the count differs, pause and reconcile with the incident notes before continuing. (If `3` is confirmed as okay-to-delete, no further safeguarding is needed — `migrate django_celery_beat zero` drops the tables they live in.)

---

### Task 3: Dry-run both migrate commands

**Why:** `migrate messaging 0007` runs the real reverse of `0008` (deletes 3 PeriodicTask rows) and updates `django_migrations`. `migrate ... zero` drops tables. The `--plan` flag prints exactly what Django will do for each, without executing.

**Files:** none

- [ ] **Step 1: Plan the messaging reversal**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py migrate messaging 0007 --plan"
```
Expected: a single line — `Unapply messaging.0008_periodic_tasks`. **Only one migration.** If the plan shows more than one unapply (e.g., it tries to unapply 0007 too), STOP — the target `0007` was misspecified.

- [ ] **Step 2: Plan the django_celery_beat reversal**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py migrate django_celery_beat zero --plan"
```
Expected: an ordered list of `Unapply django_celery_beat.<NNNN>_<name>` lines, starting from the highest-numbered migration and walking down to `0001_initial`. Every migration name shown as `[X]` in Task 2 Step 1 must appear here. **No `messaging.0008` should appear in the plan** — if it does, Task 4 didn't take effect or wasn't run yet.

(Note: the plan in Step 2 reflects the *current* recorder state, so re-run this command after Task 4 to confirm the clean plan before executing Task 5.)

---

### Task 4: Run `migrate messaging 0007`

**Why:** The DatabaseScheduler deploy recorded `messaging.0008_periodic_tasks` as applied, but the file-scheduler branch does not include that migration file. Leaving the row in `django_migrations` will cause Django on the new code to error with "node not found" on startup. This command runs `0008`'s `reverse_code` (`remove_periodic_tasks` — deletes the 3 PeriodicTask rows it created) and removes the `0008` row from `django_migrations`. Running this **first** ensures the `django_celery_beat_periodictask` table still exists when `remove_periodic_tasks` runs, and prevents Task 5 from triggering this same cascade implicitly.

**Files:** none

- [ ] **Step 1: Execute**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py migrate messaging 0007"
```
Expected: a single line `Unapplying messaging.0008_periodic_tasks... OK`. Exit 0.

- [ ] **Step 2: Verify**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py showmigrations messaging"
```
Expected: migrations `0001_initial` through `0007_notification` marked `[X]`, and `0008_periodic_tasks` marked `[ ]` (or absent — depends on Django version). The important property: `0008_*` is no longer recorded as applied.

---

### Task 5: Run `migrate django_celery_beat zero`

**Why:** Drops all `django_celery_beat_*` tables (including the 3 `PeriodicTask` rows — intentional) and removes the corresponding rows from `django_migrations`. With Task 4 already done, there are no dependents recorded as applied, so this runs cleanly without cross-app cascade.

**Files:** none

- [ ] **Step 1: Re-confirm there is no cross-app cascade**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py migrate django_celery_beat zero --plan"
```
Expected: ONLY `Unapply django_celery_beat.*` lines, no `messaging.*` lines. If `messaging.0008` shows up here, Task 4 didn't take effect — go back and re-run Task 4 Step 1.

- [ ] **Step 2: Execute**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py migrate django_celery_beat zero"
```
Expected: a sequence of `Unapplying django_celery_beat.<NNNN>_<name>... OK` lines, finishing without errors. Exit 0.

If it fails partway, do NOT immediately rerun. Run `showmigrations django_celery_beat` again to see what's left, then decide whether to continue forward (re-run `zero`) or stop and reassess.

- [ ] **Step 3: Verify migrations cleared**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py showmigrations django_celery_beat"
```
Expected: same list of migrations, **all marked `[ ]`** (unapplied). No `[X]` rows remain.

- [ ] **Step 4: Verify the PeriodicTask table is actually gone**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA \
  "./manage.py shell -c 'from django_celery_beat.models import PeriodicTask; print(PeriodicTask.objects.count())'"
```
Expected: an error like `django.db.utils.ProgrammingError: relation "django_celery_beat_periodictask" does not exist`. That's the desired state — the table is gone.

---

### Task 6: Final consistency check

**Why:** Confirm no unexpected applied migrations linger and the DB is in the state the file-scheduler branch expects. **This is the success criterion for the plan.**

**Files:** none

- [ ] **Step 1: Show the full migration plan**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA "./manage.py showmigrations --plan" | grep -E "^\[ \]|^\?" | head -50
```
Expected: any `[ ]` (unapplied) lines should be limited to `django_celery_beat.*` and `messaging.0008_*` — both intentional. No other unapplied migrations should appear for apps we didn't touch (e.g., `users`, `oauth2_provider` should still be fully `[X]`).

If anything unexpected shows up, investigate before considering the plan complete.

- [ ] **Step 2: Confirm celery-beat-related migration rows are gone**

Quick check that nothing django_celery_beat-related remains as applied:

```bash
kamal app exec --roles web --version $ROLLBACK_SHA \
  "./manage.py shell -c 'from django.db.migrations.recorder import MigrationRecorder; print(list(MigrationRecorder.Migration.objects.filter(app=\"django_celery_beat\").values_list(\"name\", flat=True)))'"
```
Expected: `[]` (empty list).

- [ ] **Step 3: Confirm the orphan messaging.0008 row is gone**

```bash
kamal app exec --roles web --version $ROLLBACK_SHA \
  "./manage.py shell -c 'from django.db.migrations.recorder import MigrationRecorder; print(list(MigrationRecorder.Migration.objects.filter(app=\"messaging\", name__startswith=\"0008\").values_list(\"name\", flat=True)))'"
```
Expected: `[]` (empty list).

- [ ] **Step 4: Record the final state**

Paste the outputs from Steps 1–3 into the incident channel / PR description as the closeout record. The DB is now consistent with the file-scheduler branch; the separate deploy step can proceed when ready.

---

## Rollback

If anything goes wrong:

1. The rollback image is still in ECR. Production was never promoted to the broken DatabaseScheduler image, so the running app is unaffected by any task here — they all run in one-off containers.
2. If Tasks 4–5 leave the DB in an unexpected state, the impact is bounded: at worst, 3 `PeriodicTask` rows are lost (re-seeded by the file-scheduler config on next celery start) and one `django_migrations` row is missing. No user data is touched. Re-run the relevant migrate command after diagnosing what failed.
