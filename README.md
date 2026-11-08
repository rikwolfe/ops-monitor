# ops-monitor

Small GitHub Actions monitor for Rik's live sites and cloud spend. It replaces the Cloud Run "watchdog". Alerts go to the ntfy app.

**This repo is public on purpose** (scheduled Actions on a private Free repo would use more than the 2,000 free minutes). It contains **no secrets**: only public URLs and IDs. The ntfy topic and any API keys are GitHub Actions secrets. GCP and AWS access use short-lived OIDC credentials (Workload Identity Federation / IAM role), not stored keys.

| Workflow | When | What |
|---|---|---|
| `uptime.yml` | every 15 min (:07/:22/:37/:52) | **DNS** of every zone in `sites.yml` `domains:`, asked straight at its own Google Cloud DNS nameservers (no cache), plus MX where mail is expected. REFUSED/SERVFAIL/NXDOMAIN counts at once (no 2-run wait). **HTTP** of every URL in `sites.yml` (browser User-Agent, 3 retries with backoff, 30 s timeout): DOWN only after 2 failed runs in a row, Recovered only after a confirmed DOWN, 403/429 from bot protection counts as up for ~2 hours. A confirmed incident opens an `incident` issue (see below) and sends ntfy with the cause and the issue link. TLS expiry < 14 days. State: `state/status.json`. |
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

## When an alert comes in: Claude proposes, Rik approves

Nothing here repairs on its own. A confirmed incident (a zone that stops being served, or a site down 2 runs in a row) opens or updates a GitHub issue labelled **`incident`** with the cause, the evidence (dig/HTTP results) and the exact proposed fix with its rollback; DNS incidents are grouped per GCP project. The ntfy alert gives the cause, "Voorstel staat klaar, zeg 'fix' in Claude" and the issue link. When everything recovers, ops-monitor closes the issue itself.

**For Claude:** read the open `incident` issues in this repo, put the proposal to Rik in plain words, and run the fix with his own sign-in **only after his OK**. Then run the `postcheck` workflow and report. `python3 monitor.py billing` (local, read-only) shows which projects in `sites.yml` `billing:` have billing off and the fix for each.

Why: on 8 Nov 2026 the Bespoke Software Inc billing account was closed; its project holds most DNS zones, Cloud DNS stopped serving them and wolfe.nl, richardwolfe.nl, kawanaki.com, bespokesoftware.nl and speedmailing.* went offline, mail included.

## Changing the site list

Edit `sites.yml`. A removed URL or domain drops out of the state on the next run.
