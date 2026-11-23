# Automated code review

The Claude Code Review workflow (`.github/workflows/claude-code-review.yml`) reviews pull requests in two stages:

1. **OpenCodeReview** reviews the diff and posts inline findings. Its per-path rules are in `.opencodereview/`.
2. **Claude Code Review** runs only if OpenCodeReview found nothing, and posts its own inline findings.

Comments from both stages come from `github-actions[bot]`. Address them before asking for human review.

## When it runs

- **Ready PRs** are reviewed on every push. A new push cancels the review in progress.
- **Drafts are skipped**, so work in progress isn't reviewed on every push. To review a draft, add the `review-draft` label: that reviews it straight away, and every push after that until you remove the label. An unlabelled draft is first reviewed when you mark it ready.
- **Forks and Dependabot PRs** are not reviewed: their runs get no access to the credentials the review needs. Dependabot PRs get their own review instead; see below.

## The verdict

The **Automated review verdict** check is advisory: it never fails. Its job summary says whether both stages ran and found nothing, or why not.

## Setup

- `ANTHROPIC_API_KEY` repository secret, used by the OpenCodeReview stage only.
- A Claude API workload identity federation rule for the Claude stage, whose subject prefix is exactly `repo:dimagi/connect-id:pull_request`. The rule's IDs are in the workflow; they are identifiers, not secrets.

## Dependabot PRs

`.github/workflows/claude-dependabot.yml` reviews Dependabot PRs with the `dependabot-pr-review` skill in `.claude/skills/dependabot-pr-review/`, the same skill you can run locally with `/dependabot-pr-review <N>`. It posts one comment per PR with a risk rating and a merge recommendation, and edits that comment on each Dependabot rebase instead of adding another. It never installs the PR's dependencies or runs tests; the PR's own CI checks are its test evidence.

To review a Dependabot PR again, or one that opened before the workflow existed, run the workflow by hand (Actions → Claude Dependabot PR Review → Run workflow) with the PR number. Manual runs are limited to PRs that Dependabot opened.

It authenticates to the Claude API with workload identity federation, so it needs no API key secret. Its federation rule (IDs in the workflow) must accept the subjects of both triggers: `repo:dimagi/connect-id:pull_request` for Dependabot-triggered runs and `repo:dimagi/connect-id:ref:refs/heads/<branch>` for manual runs.
