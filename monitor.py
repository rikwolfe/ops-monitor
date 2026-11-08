#!/usr/bin/env python3
"""ops-monitor: uptime, TLS expiry and cloud-spend checks that alert via ntfy.

Usage: monitor.py uptime | postcheck | billing [--simulate-off=PROJECT] | spend | weekly | test

Secrets come from the environment (GitHub Actions secrets), never from files:
  NTFY_TOPIC            ntfy.sh topic (works as a password)
  ANTHROPIC_ADMIN_KEY   optional; Anthropic Admin API key for cost_report
GCP and AWS credentials come from OIDC (Workload Identity Federation / IAM role),
set up by the workflow before this script runs.
"""
import datetime as dt
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from zoneinfo import ZoneInfo

import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(ROOT, "state", "status.json")
SPEND_STATE_FILE = os.path.join(ROOT, "state", "spend.json")
SITES_FILE = os.path.join(ROOT, "sites.yml")

# Strikingly resets connections for anything that doesn't look like a browser.
USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
TLS_WARN_DAYS = 14
TIMEOUT = 30
BACKOFF = [5, 15, 30]       # seconds before each retry within one run
DOWN_AFTER_RUNS = 2         # consecutive failed runs before a DOWN alert
BLOCKED_AFTER_RUNS = 8      # 403/429 from bot protection counts as up for ~2 hours

# Spend rules, same as the old watchdog.
YELLOW_EUR, RED_EUR = 20.0, 100.0
YELLOW_MUL, RED_MUL = 3.0, 10.0

BQ_PROJECT = "rwolfe-watchdog"  # where the queries run (ops-monitor SA has jobUser here)
# One standard billing export per billing account; Google only allows a dataset
# in a project on that same account. The SA has read access on each dataset.
BQ_EXPORTS = [
    "rwolfe-watchdog.billing_export",                # Wolfe Business Development
    "braintoss-website.billing_export",              # Braintoss
    "ef2-learning-companion-487101.billing_export",  # EF2 Learning Companion
]
# Bespoke Software Inc billing account closed 8 Nov 2026; its project now bills
# to Wolfe Business Development, so its old export gets no new rows.
AWS_ACCOUNTS = ["444625565274"]

# The fix proposed when a project's billing is off. Never applied automatically:
# Rik approves it in Claude, which runs it with his own sign-in.
REPAIR_BILLING_ACCOUNT = "017AA8-04A2E1-158420"  # Wolfe Business Development


# ---------- helpers ----------

def ntfy(title, message, priority="default", tags=""):
    topic = os.environ.get("NTFY_TOPIC")
    if not topic:
        print(f"[ntfy skipped, no NTFY_TOPIC] {title}: {message}")
        return
    req = urllib.request.Request(
        "https://ntfy.sh/" + urllib.parse.quote(topic),
        data=message.encode("utf-8"),
        headers={"Title": title.encode("utf-8").decode("latin-1", "ignore"),
                 "Priority": priority, "Tags": tags},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        print(f"ntfy sent ({r.status}): {title}")


def load_state(path=STATE_FILE):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state, path=STATE_FILE):
    with open(path, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")


def now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def load_config():
    with open(SITES_FILE) as f:
        return yaml.safe_load(f)


# ---------- DNS (authoritative) ----------

def dig(name, rtype, server):
    """(status, answers) straight from an authoritative server, no recursion/cache."""
    out = subprocess.run(["dig", "+norec", "+time=5", "+tries=2", rtype, name, "@" + server],
                         capture_output=True, text=True)
    text = out.stdout
    if "status: " not in text:
        return "TIMEOUT", []
    status = text.split("status: ", 1)[1].split(",", 1)[0]
    answers, in_answer = [], False
    for line in text.splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
        elif in_answer and not line.strip():
            break
        elif in_answer and not line.startswith(";"):
            answers.append(line.split()[-1])
    return status, answers


def check_domain(d):
    """Return (ok, problem). Asks the zone's own nameservers; one healthy NS is enough."""
    servers = [f"ns-cloud-{d['ns']}{i}.googledomains.com" for i in (1, 2)]
    results = [dig(d["name"], "SOA", ns) for ns in servers]
    good = next((r for r in results if r[0] == "NOERROR" and r[1]), None)
    if not good:
        status = next((r[0] for r in results if r[0] != "TIMEOUT"), "TIMEOUT")
        return False, f"DNS {status}"
    if d.get("mail"):
        for ns in servers:
            status, mx = dig(d["name"], "MX", ns)
            if status == "NOERROR":
                return (True, "") if mx else (False, "no MX records")
        return False, "MX lookup failed"
    return True, ""


def fix_command(project):
    return f"gcloud billing projects link {project} --billing-account={REPAIR_BILLING_ACCOUNT}"


def dns_cause(problem, project):
    if problem in ("DNS REFUSED", "DNS SERVFAIL"):
        return (f"Google Cloud DNS no longer serves the zone ({problem.split()[1]}); "
                f"most likely billing is off on project {project}")
    if problem == "DNS NXDOMAIN":
        return f"zone or record removed in project {project}"
    if problem == "DNS TIMEOUT":
        return "nameservers did not answer"
    return problem


def run_dns_checks(domains):
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(zip([d["name"] for d in domains], pool.map(check_domain, domains)))


def domain_for(host, domains):
    return next((d for d in domains if host == d["name"] or host.endswith("." + d["name"])), None)


def diagnose(detail, dns_problem, project):
    """Likely cause of an HTTP failure, for the alert text."""
    if dns_problem:
        return dns_cause(dns_problem, project)
    if detail.startswith("HTTP 5"):
        return "hosting returns a server error"
    if detail.startswith("HTTP 404"):
        return "hosting returns 404 (site not deployed or removed?)"
    if "CERTIFICATE" in detail or "SSL" in detail:
        return "TLS certificate problem"
    if "Name or service not known" in detail or "nodename nor servname" in detail:
        return "DNS lookup failed"
    if "timed out" in detail.lower():
        return "timeout: host up but not answering"
    return detail


# ---------- incidents (GitHub issues) ----------
# A confirmed incident opens an issue labelled `incident` with cause, evidence
# and the proposed fix. Nothing is repaired automatically: Claude reads open
# incident issues, puts the fix to Rik, and runs it only after his OK.

INCIDENT_LABEL = "incident"


def gh(*args):
    if not os.environ.get("GH_TOKEN") and os.environ.get("GITHUB_ACTIONS"):
        print("gh skipped: no GH_TOKEN")
        return None
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        print(f"gh {args[0]} {args[1]} failed: {out.stderr.strip()[:200]}")
        return None
    return out.stdout.strip()


def open_incident(incidents, key, title, body, labels=()):
    """Create the issue for `key`, or comment on it if it is already open. Returns its URL."""
    if key in incidents:
        num = incidents[key]
        gh("issue", "comment", str(num), "--body", body)
        return f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', 'rikwolfe/ops-monitor')}/issues/{num}"
    gh("label", "create", INCIDENT_LABEL, "--color", "B60205", "--description",
       "Confirmed outage seen by ops-monitor", "--force")
    args = ["issue", "create", "--title", title, "--body", body, "--label", INCIDENT_LABEL]
    for label in labels:
        args += ["--label", label]
    url = gh(*args)
    if url:
        incidents[key] = int(url.rstrip("/").rsplit("/", 1)[1])
    return url or ""


def close_incident(incidents, key, note):
    num = incidents.pop(key, None)
    if num:
        gh("issue", "close", str(num), "--comment", note)


def dns_incident_body(project, failing, relink):
    lines = [f"**Cause:** {dns_cause(failing[0][1], project)}.", "",
             "**Evidence** (asked straight at the zones' own Google Cloud DNS nameservers, no cache):", ""]
    lines += [f"- `{name}`: {problem}" for name, problem in failing]
    lines += ["", "Billing state is not readable from Actions; check it with "
              f"`gcloud billing projects describe {project}`.", ""]
    if relink and any(p in ("DNS REFUSED", "DNS SERVFAIL") for _, p in failing):
        lines += ["**Proposed fix:** link the project back to the Wolfe Business Development billing account.",
                  "", "```", fix_command(project), "```", "",
                  "**Rollback:** `gcloud billing projects unlink " + project + "` (puts it back as it is now: "
                  "DNS stays down).", ""]
    else:
        lines += ["**Proposed fix:** none automatic for this cause; Claude investigates and proposes one.", ""]
    lines += ["**Check after the fix:** run the `postcheck` workflow.", "",
              "_Opened by ops-monitor. Nothing is changed until Rik approves the fix in Claude._"]
    return "\n".join(lines)


def http_fix(cause):
    if "404" in cause:
        return "redeploy the site from its own repo (deploy workflow on `main`)"
    if "server error" in cause:
        return "check the hosting logs (Cloud Run / Firebase) and roll back the last deploy if it is the cause"
    if "TLS" in cause:
        return "renew or re-provision the certificate at the host"
    return "Claude investigates and proposes one"


# ---------- uptime ----------

def check_http(url):
    """Return (result, detail); result is "up", "blocked" (403/429) or "down".
    Follows redirects; 2xx/3xx is up. Retries with backoff before giving up."""
    last = ""
    for attempt in range(len(BACKOFF) + 1):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9,nl;q=0.8"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                if 200 <= r.status < 400:
                    return "up", f"HTTP {r.status}"
                last = f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                return "up", f"HTTP {e.code}"
            if e.code in (403, 429):
                # Bot protection answering means the site itself is there.
                return "blocked", f"HTTP {e.code} (blocked by bot protection)"
            last = f"HTTP {e.code}"
        except Exception as e:  # noqa: BLE001 - any network failure counts as a failed try
            last = type(e).__name__ + ": " + str(e)[:120]
        if attempt < len(BACKOFF):
            time.sleep(BACKOFF[attempt])
    return "down", last


def cert_days_left(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=20) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            not_after = s.getpeercert()["notAfter"]
    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), dt.timezone.utc)
    return (expires - dt.datetime.now(dt.timezone.utc)).days


def run_uptime():
    """Alert only on confirmed changes: DOWN after DOWN_AFTER_RUNS failed runs in
    a row, Recovered only after a confirmed DOWN. Single blips stay in the log."""
    config = load_config()
    sites, domains = config["sites"], config.get("domains", [])
    state = load_state()
    sites_state = state.setdefault("sites", {})
    changed = False

    # DNS first, and without the 2-run delay: an authoritative REFUSED/SERVFAIL is
    # never a blip, and resolver caches hide it for hours (8 Nov 2026).
    dns_state = state.setdefault("dns", {})
    incidents = state.setdefault("incidents", {})
    dns_results = run_dns_checks(domains)
    newly_down, recovered = {}, {}
    for d in domains:
        name = d["name"]
        ok, problem = dns_results[name]
        prev = dns_state.get(name, {})
        # A timeout can be the runner's network: that one does wait for a 2nd run.
        fails = 0 if ok else prev.get("fails", 0) + 1
        bad = not ok and (problem != "DNS TIMEOUT" or fails >= 2)
        status = "down" if bad else ("up" if ok else prev.get("status", "up"))
        print(f"DNS {name}: {'OK' if ok else problem}; confirmed {status}")
        if status == "down" and prev.get("status") != "down":
            newly_down.setdefault(d["project"], []).append((name, problem))
        elif status == "up" and prev.get("status") == "down":
            recovered.setdefault(d["project"], []).append(name)
        new = {"status": status, "fails": min(fails, 2), "problem": problem}
        if new != {k: prev.get(k) for k in new}:
            dns_state[name] = new
            changed = True
    for gone in set(dns_state) - {d["name"] for d in domains}:
        del dns_state[gone]
        changed = True

    # One incident (issue + ntfy) per project, not one per domain.
    relink = {b["project"]: b.get("relink", False) for b in config.get("billing", [])}
    for project, failing in newly_down.items():
        all_failing = [(n, dns_state[n]["problem"]) for n in dns_state
                       if dns_state[n]["status"] == "down"
                       and next(d["project"] for d in domains if d["name"] == n) == project]
        cause = dns_cause(failing[0][1], project)
        url = open_incident(incidents, f"dns:{project}",
                            f"DNS down: {', '.join(n for n, _ in all_failing)} ({project})",
                            dns_incident_body(project, all_failing, relink.get(project, False)))
        names = ", ".join(n for n, _ in failing)
        ntfy(f"DNS DOWN: {names}", f"Cause: {cause}. Voorstel staat klaar, zeg 'fix' in Claude. {url}".strip(),
             "urgent", "rotating_light")
        changed = True
    for project, names in recovered.items():
        still = [n for n in dns_state if dns_state[n]["status"] == "down"
                 and next(d["project"] for d in domains if d["name"] == n) == project]
        ntfy(f"DNS recovered: {', '.join(names)}", f"{', '.join(names)} answers again", "default", "white_check_mark")
        if not still and f"dns:{project}" in incidents:
            close_incident(incidents, f"dns:{project}", f"Recovered at {now_iso()}: all zones answer again.")
            changed = True

    # In parallel, so retries with backoff on a few sites can't blow the job timeout.
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = dict(zip([s["url"] for s in sites], pool.map(check_http, [s["url"] for s in sites])))

    for site in sites:
        url = site["url"]
        host = urllib.parse.urlparse(url).hostname
        prev = sites_state.get(url, {})
        result, detail = results[url]

        blocked = prev.get("blocked_runs", 0)
        blocked = min(blocked + 1, BLOCKED_AFTER_RUNS) if result == "blocked" else 0
        failed = result == "down" or (result == "blocked" and blocked >= BLOCKED_AFTER_RUNS)
        fails = min(prev.get("fails", 0) + 1, DOWN_AFTER_RUNS) if failed else 0

        status = prev.get("status") or ("down" if failed else "up")
        if status == "up" and fails >= DOWN_AFTER_RUNS:
            status = "down"
            dom = domain_for(host, domains)
            dns_problem = dom and (dns_results[dom["name"]][1] or None)
            cause = diagnose(detail, dns_problem, dom["project"] if dom else "?")
            link = ""
            if not dns_problem:  # DNS incidents already have their own issue
                link = open_incident(incidents, f"http:{url}", f"Site down: {url}", "\n".join([
                    f"**Cause:** {cause}.", "", f"**Evidence:** {DOWN_AFTER_RUNS} uptime runs in a row, "
                    f"each with {len(BACKOFF) + 1} tries: `{detail}`", "",
                    f"**Proposed fix:** {http_fix(cause)}.", "",
                    "**Check after the fix:** run the `postcheck` workflow.", "",
                    "_Opened by ops-monitor. Nothing is changed until Rik approves the fix in Claude._"]))
            ntfy(f"DOWN: {host}", f"{url} is down: {detail}. Cause: {cause}."
                 + (f" Voorstel staat klaar, zeg 'fix' in Claude. {link}" if link else ""),
                 "high", "rotating_light")
        elif status == "down" and not failed:
            status = "up"
            ntfy(f"Recovered: {host}", f"{url} is back up ({detail})", "default", "white_check_mark")
            close_incident(incidents, f"http:{url}", f"Recovered at {now_iso()}: {detail}.")

        cert_ok, days = prev.get("cert_ok", True), None
        if result != "down":
            try:
                days = cert_days_left(host)
                if prev.get("cert_ok", True) and days < TLS_WARN_DAYS:
                    ntfy(f"TLS expiring: {host}", f"Certificate for {host} expires in {days} days",
                         "high", "lock")
                cert_ok = days >= TLS_WARN_DAYS
            except Exception as e:  # noqa: BLE001 - a flaky TLS probe is logged, not alerted
                print(f"{host}: TLS check failed: {type(e).__name__}")
        print(f"{url}: {result.upper()} ({detail}); confirmed {status}; "
              f"failed runs {fails}; cert days left: {days}")

        # Only write when something changes, so the state file (and git history)
        # stays quiet while everything is up.
        new = {"status": status, "cert_ok": cert_ok, "fails": fails, "blocked_runs": blocked}
        if any(new[k] != prev.get(k, 0 if k in ("fails", "blocked_runs") else None) for k in new):
            new["detail"] = detail
            new["since"] = now_iso() if status != prev.get("status") else prev.get("since", now_iso())
            sites_state[url] = new
            changed = True

    for gone in set(sites_state) - {s["url"] for s in sites}:
        del sites_state[gone]
        changed = True

    if changed:
        state["updated"] = now_iso()
    save_state(state)
    return changed


# ---------- postcheck ----------

def run_postcheck(only_project=None):
    """DNS + MX + HTTP for everything, about a minute, no state, no ntfy.
    Returns (ok, summary). Run after every infra change, and after a fix."""
    config = load_config()
    domains = [d for d in config.get("domains", []) if not only_project or d["project"] == only_project]
    names = {d["name"] for d in domains}
    sites = [s for s in config["sites"]
             if not only_project or (domain_for(urllib.parse.urlparse(s["url"]).hostname, domains))]
    dns = run_dns_checks(domains)
    global BACKOFF
    saved, BACKOFF = BACKOFF, [5]
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            http = dict(zip([s["url"] for s in sites], pool.map(check_http, [s["url"] for s in sites])))
    finally:
        BACKOFF = saved
    bad = [f"{n}: {p}" for n, (ok, p) in sorted(dns.items()) if not ok]
    bad += [f"{u}: {d}" for u, (r, d) in http.items() if r == "down"]
    for n, (ok, p) in sorted(dns.items()):
        print(f"DNS  {'OK  ' if ok else 'FAIL'} {n} {p}")
    for u, (r, d) in http.items():
        print(f"HTTP {'OK  ' if r != 'down' else 'FAIL'} {u} {d}")
    summary = (f"all OK ({len(names)} domains, {len(sites)} sites)" if not bad
               else f"{len(bad)} failing: " + "; ".join(bad[:6]))
    print("postcheck:", summary)
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(f"**postcheck:** {summary}\n")
    return not bad, summary


# ---------- billing check (read-only) ----------

def billing_enabled(project):
    out = subprocess.run(["gcloud", "billing", "projects", "describe", project, "--format=json"],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(" ".join(out.stderr.split())[:200])
    return bool(json.loads(out.stdout).get("billingEnabled"))


def run_billing(simulate_off=()):
    """Check that every project in sites.yml `billing:` has billing on, and print the
    proposed fix for any that hasn't. Changes nothing: Claude runs this with Rik's
    sign-in, proposes the fix, and applies it only after Rik approves."""
    bad = []
    for entry in load_config().get("billing", []):
        project = entry["project"]
        try:
            on = billing_enabled(project) and project not in simulate_off
        except Exception as e:  # noqa: BLE001
            print(f"{project}: billing not readable: {e}")
            continue
        print(f"{project}: billing {'on' if on else 'OFF'}")
        if not on:
            bad.append(project)
            if entry.get("relink", False):
                print(f"  proposed fix: {fix_command(project)}")
            else:
                print("  proposed fix: none automatic; this project has its own billing account")
    return not bad


# ---------- spend ----------

def usd_to_eur():
    try:
        with urllib.request.urlopen("https://api.frankfurter.app/latest?from=USD&to=EUR", timeout=15) as r:
            return float(json.load(r)["rates"]["EUR"])
    except Exception:  # noqa: BLE001
        return 0.92


def days_window():
    """Yesterday (Amsterdam) is evaluated; the 7 days before it are the baseline."""
    today = dt.datetime.now(ZoneInfo("Europe/Amsterdam")).date()
    target = today - dt.timedelta(days=1)
    start = target - dt.timedelta(days=7)
    return start, target


def gcp_spend(start, target):
    """{project_id: {date: eur}} from the BigQuery billing exports, or raises."""
    rows, empty, failed = [], [], []
    for dataset in BQ_EXPORTS:
        sql = f"""
          SELECT IFNULL(project.id, '(no project)') AS project,
                 CAST(DATE(usage_start_time, 'Europe/Amsterdam') AS STRING) AS day,
                 SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS amount,
                 ANY_VALUE(currency) AS currency
          FROM `{dataset}.gcp_billing_export_v1_*`
          WHERE DATE(usage_start_time, 'Europe/Amsterdam') BETWEEN '{start}' AND '{target}'
            AND _PARTITIONTIME >= TIMESTAMP_SUB(TIMESTAMP('{start}'), INTERVAL 2 DAY)
          GROUP BY project, day"""
        out = subprocess.run(
            ["bq", f"--project_id={BQ_PROJECT}", "--location=EU", "query", "--quiet",
             "--use_legacy_sql=false", "--format=json", "--max_rows=10000", sql],
            capture_output=True, text=True)
        if out.returncode != 0:
            msg = " ".join((out.stdout + out.stderr).split())
            if "Not found" in msg or "does not match any table" in msg:
                empty.append(dataset)
            else:  # one unreadable export goes to the log; the others still count
                failed.append(dataset)
                print(f"GCP: {dataset} not readable: {msg[:250]}")
            continue
        rows += json.loads(out.stdout or "[]")
    if failed and len(failed) + len(empty) == len(BQ_EXPORTS):
        raise RuntimeError(f"no billing export readable ({', '.join(failed)})")
    if len(empty) == len(BQ_EXPORTS):
        raise RuntimeError("no billing export tables yet")
    if empty:
        print(f"GCP: no export tables yet in {', '.join(empty)}")
    if not rows:
        print("GCP: no data yet (export tables exist, still filling)")
    fx = None
    result = {}
    for r in rows:
        amount = float(r["amount"] or 0)
        if r.get("currency") == "USD":
            fx = fx or usd_to_eur()
            amount *= fx
        result.setdefault(r["project"], {})[r["day"]] = amount
    return result


def aws_spend(start, target):
    end = target + dt.timedelta(days=1)
    out = subprocess.run(
        ["aws", "ce", "get-cost-and-usage", "--region", "us-east-1",
         "--time-period", f"Start={start},End={end}", "--granularity", "DAILY",
         "--metrics", "UnblendedCost",
         "--group-by", "Type=DIMENSION,Key=LINKED_ACCOUNT", "--output", "json"],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError((out.stdout + out.stderr).strip()[:300])
    fx = usd_to_eur()
    result = {a: {} for a in AWS_ACCOUNTS}
    for period in json.loads(out.stdout).get("ResultsByTime", []):
        day = period["TimePeriod"]["Start"]
        for g in period.get("Groups", []):
            acct = g["Keys"][0]
            usd = float(g["Metrics"]["UnblendedCost"]["Amount"])
            result.setdefault(acct, {})[day] = usd * fx
    return result


def anthropic_spend(start, target):
    key = os.environ.get("ANTHROPIC_ADMIN_KEY")
    if not key:
        raise RuntimeError("no ANTHROPIC_ADMIN_KEY secret")
    params = [("starting_at", f"{start}T00:00:00Z"),
              ("ending_at", f"{target + dt.timedelta(days=1)}T00:00:00Z"),
              ("group_by[]", "workspace_id"), ("bucket_width", "1d")]
    url = "https://api.anthropic.com/v1/organizations/cost_report?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"cost_report HTTP {e.code}") from None
    fx = usd_to_eur()
    result = {}
    for bucket in data.get("data", []):
        day = bucket["starting_at"][:10]
        for res in bucket.get("results", []):
            ws = res.get("workspace_id") or "default"
            # amount is in cents (USD) per the Admin API
            usd = float(res.get("amount") or 0) / 100
            result.setdefault(ws, {})
            result[ws][day] = result[ws].get(day, 0) + usd * fx
    return result


def evaluate(series, start, target):
    day = target.isoformat()
    spent = series.get(day, 0.0)
    baseline_days = [(start + dt.timedelta(days=i)).isoformat() for i in range(7)]
    baseline = sum(series.get(d, 0.0) for d in baseline_days) / 7
    mul = spent / baseline if baseline > 0 else 0
    if spent > RED_EUR or (baseline > 0 and mul > RED_MUL):
        sev = "red"
    elif spent > YELLOW_EUR or (baseline > 0 and mul > YELLOW_MUL):
        sev = "yellow"
    else:
        sev = "green"
    # tiny amounts don't count as anomalies
    if sev != "green" and spent < 1.0:
        sev = "green"
    return sev, spent, baseline, mul


SOURCES = {"GCP": gcp_spend, "AWS": aws_spend, "Anthropic": anthropic_spend}


def collect_all(start, target):
    data, errors = {}, {}
    for name, fn in SOURCES.items():
        try:
            data[name] = fn(start, target)
        except Exception as e:  # noqa: BLE001
            errors[name] = str(e)
            print(f"{name}: ERROR {e}")
    return data, errors


def run_spend():
    start, target = days_window()
    data, errors = collect_all(start, target)
    alerts = []
    for source, by_id in data.items():
        for ident, series in sorted(by_id.items()):
            sev, spent, baseline, mul = evaluate(series, start, target)
            print(f"{source} {ident}: {target} €{spent:.2f}, 7d avg €{baseline:.2f}, x{mul:.1f} -> {sev}")
            if sev != "green":
                alerts.append((sev, f"{source} {ident}: €{spent:.2f} on {target} "
                                    f"(7-day avg €{baseline:.2f}, x{mul:.1f})"))
    reds = [m for s, m in alerts if s == "red"]
    yellows = [m for s, m in alerts if s == "yellow"]
    if reds:
        ntfy("RED spend alert", "\n".join(reds + yellows), "urgent", "rotating_light,moneybag")
    elif yellows:
        ntfy("Spend warning", "\n".join(yellows), "default", "warning,moneybag")

    # Source errors go to the log every day, but to ntfy only once per new
    # error, so a source that stays unavailable never alerts again.
    # Own file, so it never conflicts with the uptime commits.
    state = load_state(SPEND_STATE_FILE)
    prev = state.get("spend_errors", {})
    if set(errors) != set(prev):
        new = sorted(set(errors) - set(prev))
        if new:
            ntfy("ops-monitor spend source unavailable",
                 "\n".join(f"{n} not readable: {errors[n]}" for n in new), "low", "information_source")
        state["spend_errors"] = errors
        state["updated"] = now_iso()
        save_state(state, SPEND_STATE_FILE)


def run_weekly():
    state = load_state()
    sites = state.get("sites", {})
    up = sum(1 for s in sites.values() if s.get("status") == "up")
    down = [u for u, s in sites.items() if s.get("status") != "up"]

    today = dt.date.today()
    start = today - dt.timedelta(days=8)
    target = today - dt.timedelta(days=1)
    data, errors = collect_all(start, target)
    week = [(start + dt.timedelta(days=i)).isoformat() for i in range(1, 8)]
    lines = [f"{up} of {len(sites)} sites ok" + (f"; down: {', '.join(down)}" if down else "")]
    for source in SOURCES:
        if source in errors:
            lines.append(f"{source}: not readable ({errors[source][:80]})")
            continue
        total = sum(v for series in data[source].values() for d, v in series.items() if d in week)
        lines.append(f"{source}: €{total:.2f} last 7 days")
    ntfy("ops-monitor alive", "\n".join(lines), "low", "heartbeat")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "uptime":
        run_uptime()
    elif cmd == "postcheck":
        sys.exit(0 if run_postcheck()[0] else 1)
    elif cmd == "billing":
        sim = [a.split("=", 1)[1] for a in sys.argv[2:] if a.startswith("--simulate-off=")]
        sim = [p for x in sim for p in x.split(",") if p]
        sys.exit(0 if run_billing(simulate_off=sim) else 1)
    elif cmd == "spend":
        run_spend()
    elif cmd == "weekly":
        run_weekly()
    elif cmd == "test":
        ntfy("ops-monitor test", "ops-monitor test", "default", "test_tube")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
