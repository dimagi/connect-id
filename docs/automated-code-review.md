# Automated code review

The Claude Code Review workflow (`.github/workflows/claude-code-review.yml`) reviews pull requests in two stages:

1. **OpenCodeReview** reviews the diff and posts inline findings. Its per-path rules are in `.opencodereview/`.
2. **Claude Code Review** runs only if OpenCodeReview found nothing, and posts its own inline findings.

Comments from both stages come from `github-actions[bot]`. Address them before asking for human review.

## When it runs

- **Ready PRs** are reviewed on every push. A new push cancels the review in progress.
- **Drafts are skipped**, so work in progress isn't reviewed on every push. To review a draft, add the `review-draft` label: that reviews it straight away, and every push after that until you remove the label. An unlabelled draft is first reviewed when you mark it ready.
- **Forks and Dependabot PRs** are not reviewed: their runs get no access to the credentials the review needs.

## The verdict

The **Automated review verdict** check is advisory: it never fails. Its job summary says whether both stages ran and found nothing, or why not.

## Setup

- `ANTHROPIC_API_KEY` repository secret, used by the OpenCodeReview stage only.
- A Claude API workload identity federation rule for the Claude stage, whose subject prefix is exactly `repo:dimagi/connect-id:pull_request`. The rule's IDs are in the workflow; they are identifiers, not secrets.
