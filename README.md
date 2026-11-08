# ops-monitor

Small GitHub Actions monitor for Rik's live sites and cloud spend. It replaces the Cloud Run "watchdog". Alerts go to the ntfy app.

**This repo is public on purpose** (scheduled Actions on a private Free repo would use more than the 2,000 free minutes). It contains **no secrets**: only public URLs and IDs. The ntfy topic and any API keys are GitHub Actions secrets. GCP and AWS access use short-lived OIDC credentials (Workload Identity Federation / IAM role), not stored keys.

| Workflow | When | What |
|---|---|---|
| `uptime.yml` | every 15 min | HTTP check of every URL in `sites.yml` (2xx/3xx, follows redirects, 2 retries) and TLS expiry (< 14 days). Alerts **only when the state flips** (down: high priority, recovered: default). State lives in `state/status.json`. |
| `spend.yml` | daily, 06:00 Amsterdam (winter) | Yesterday's spend vs the 7 days before, per GCP project (BigQuery billing export in `rwolfe-watchdog.billing_export`), AWS account (Cost Explorer) and Anthropic workspace (Admin API). Yellow: > 3x baseline or > €20/day (ntfy default). Red: > 10x or > €100/day (ntfy urgent). Also says once when a source becomes unreadable or readable again. |
| `weekly.yml` | Monday 06:30 Amsterdam (winter) | "ops-monitor alive" summary: sites ok and spend over the last 7 days per source. **If this stops arriving, the monitor is broken.** |
| `heartbeat.yml` | 1st of the month | Empty-ish commit so GitHub doesn't disable the schedules after 60 days without activity. |
| `test.yml` | by hand | Sends "ops-monitor test" to ntfy. |

## Secrets (names only)

- `NTFY_TOPIC`: ntfy.sh topic. Copied from Secret Manager `ntfy-topic` in `rwolfe-watchdog`.
- `ANTHROPIC_ADMIN_KEY`: optional. Without it, the Anthropic source reports "not readable".

## Cloud access

- GCP: WIF pool `github`, provider `ops-monitor` in project `rwolfe-watchdog` (only this repo can use it), service account `ops-monitor@rwolfe-watchdog.iam.gserviceaccount.com` with BigQuery Job User on the project and read access on dataset `billing_export` only.
- AWS: IAM role `ops-monitor-cost-read` in account 444625565274, trusted only for `repo:rikwolfe/ops-monitor`, allowed `ce:GetCostAndUsage` only.

## Changing the site list

Edit `sites.yml`. A removed URL drops out of the state on the next run.
