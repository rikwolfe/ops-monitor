# ops-monitor

Small GitHub Actions monitor for Rik's live sites and cloud spend. It replaces the Cloud Run "watchdog". Alerts go to the ntfy app.

**This repo is public on purpose** (scheduled Actions on a private Free repo would use more than the 2,000 free minutes). It contains **no secrets**: only public URLs and IDs. The ntfy topic and any API keys are GitHub Actions secrets. GCP and AWS access use short-lived OIDC credentials (Workload Identity Federation / IAM role), not stored keys.

| Workflow | When | What |
|---|---|---|
| `uptime.yml` | every 15 min (:07/:22/:37/:52) | **DNS** of every zone in `sites.yml` `domains:`, asked straight at its own Google Cloud DNS nameservers (no cache), plus MX where mail is expected. REFUSED/SERVFAIL/NXDOMAIN alerts at once (urgent) and starts `repair.yml`. **HTTP** of every URL in `sites.yml` (browser User-Agent, 3 retries with backoff, 30 s timeout): DOWN only after 2 failed runs in a row, Recovered only after a confirmed DOWN, 403/429 from bot protection counts as up for ~2 hours. Each DOWN names the likely cause (DNS not served / billing, 5xx, 404, TLS, timeout). TLS expiry < 14 days. State: `state/status.json`. |
| `repair.yml` | when uptime sees a zone go dark, or by hand | **Billing guard + auto-repair**, see below. State: `state/repair.json`. |
| `postcheck.yml` | by hand | DNS + MX + HTTP of everything in ~1 minute, no state, no ntfy. Run after every infra change. |
| `spend.yml` | daily, 06:00 Amsterdam (winter) | Yesterday's spend vs the 7 days before, per GCP project (standard BigQuery billing export, one `billing_export` dataset per billing account: rwolfe-watchdog, braintoss-website, ef2-learning-companion-487101, see `BQ_EXPORTS` in `monitor.py`), AWS account (Cost Explorer) and Anthropic workspace (Admin API). Yellow: > 3x baseline or > €20/day (ntfy default). Red: > 10x or > €100/day (ntfy urgent). Errors per source go to the log; ntfy says it only once when a source starts failing. |
| `weekly.yml` | Monday 06:30 Amsterdam (winter) | "ops-monitor alive" summary: sites ok and spend over the last 7 days per source. **If this stops arriving, the monitor is broken.** |
| `heartbeat.yml` | 1st of the month | Empty-ish commit so GitHub doesn't disable the schedules after 60 days without activity. |
| `test.yml` | by hand | Sends "ops-monitor test" to ntfy. |

## Secrets (names only)

- `NTFY_TOPIC`: ntfy.sh topic. Copied from Secret Manager `ntfy-topic` in `rwolfe-watchdog`.
- `ANTHROPIC_ADMIN_KEY`: optional. Without it, the Anthropic source reports "not readable".

## Cloud access

- GCP: WIF pool `github`, provider `ops-monitor` in project `rwolfe-watchdog` (only this repo can use it), service account `ops-monitor@rwolfe-watchdog.iam.gserviceaccount.com` with BigQuery Job User on the project and read access on the four `billing_export` datasets only.
- AWS: IAM role `ops-monitor-cost-read` in account 444625565274, trusted only for `repo:rikwolfe/ops-monitor`, allowed `ce:GetCostAndUsage` only.

## What auto-repair may do

Exactly one thing: **if a project in `sites.yml` `billing:` with `repair: true` has billing off, link it to the Wolfe Business Development billing account (`017AA8-04A2E1-158420`)**. At most once per project per 24 hours. Afterwards it runs the postcheck for that project and sends "Hersteld: billing van <project> teruggekoppeld; postcheck <result>", or an urgent "Repair did not help" with the cause. Projects with `repair: false` only get an urgent alert. It never deletes, moves zones, redeploys or touches anything else.

Why: on 8 Nov 2026 the Bespoke Software Inc billing account was closed; its project holds most DNS zones, Cloud DNS stopped serving them and wolfe.nl, richardwolfe.nl, kawanaki.com, bespokesoftware.nl and speedmailing.* went offline, mail included.

Its rights are separate from the read-only monitor: service account `ops-repair@rwolfe-watchdog.iam.gserviceaccount.com`, used only through WIF pool `github-repair`, provider `repair`, which accepts only `.github/workflows/repair.yml` on `main` of this repo. Roles: `roles/billing.user` on billing account 017AA8 only; `roles/billing.projectManager` and `roles/browser` on the `repair: true` projects; `roles/browser` on the alert-only ones.

Dry run: start `repair.yml` by hand with `simulate_off` = a project ID. It prints the exact command it would run and changes nothing.

## Changing the site list

Edit `sites.yml`. A removed URL or domain drops out of the state on the next run. A new project in `billing:` also needs the roles above.
