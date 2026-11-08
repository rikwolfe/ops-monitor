# AGENTS.md: ops-monitor

- **Public repo.** Never commit secrets, tokens, the ntfy topic, keys or private data. Only public URLs and IDs.
- **What goes live on merge:** the workflows on `main` run on their schedules right away. No deploy step.
- **Merge gate:** small changes may go to `main` directly; run `python3 monitor.py uptime` locally first (needs `pyyaml`).
- **Cloud:** GCP project `rwolfe-watchdog` (WIF pool `github`, SA `ops-monitor@`, datasets `billing_export` in rwolfe-watchdog, braintoss-website, ef2-learning-companion-487101 and gen-lang-client-0815954328); AWS account 444625565274, role `ops-monitor-cost-read`. Always pass `--project`.
- **State:** `state/status.json` (uptime) and `state/spend.json` (spend) are written by the workflows; don't hand-edit unless resetting.
- **Safety:** secrets stay out of chat and repos; Rik types them himself or they're piped between stores without printing. Ask Rik before deleting anything or adding a new cloud resource.
