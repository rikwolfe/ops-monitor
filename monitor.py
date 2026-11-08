#!/usr/bin/env python3
"""ops-monitor: uptime, TLS expiry and cloud-spend checks that alert via ntfy.

Usage: monitor.py uptime | spend | weekly | test

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
from zoneinfo import ZoneInfo

import yaml

ROOT = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(ROOT, "state", "status.json")
SPEND_STATE_FILE = os.path.join(ROOT, "state", "spend.json")
SITES_FILE = os.path.join(ROOT, "sites.yml")

# Strikingly resets connections for curl/python default user agents.
USER_AGENT = "Mozilla/5.0 (compatible; ops-monitor; +https://github.com/rikwolfe/ops-monitor)"
TLS_WARN_DAYS = 14
RETRIES = 2

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
    "gen-lang-client-0815954328.billing_export",     # Bespoke Software Inc
]
AWS_ACCOUNTS = ["444625565274"]


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


# ---------- uptime ----------

def check_http(url):
    """Return (ok, detail). Follows redirects; 2xx/3xx is ok."""
    last = ""
    for attempt in range(RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=20) as r:
                if 200 <= r.status < 400:
                    return True, f"HTTP {r.status}"
                last = f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            if 300 <= e.code < 400:
                return True, f"HTTP {e.code}"
            last = f"HTTP {e.code}"
        except Exception as e:  # noqa: BLE001 - any network failure counts as down
            last = type(e).__name__ + ": " + str(e)[:120]
        if attempt < RETRIES:
            time.sleep(10)
    return False, last


def cert_days_left(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=20) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            not_after = s.getpeercert()["notAfter"]
    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), dt.timezone.utc)
    return (expires - dt.datetime.now(dt.timezone.utc)).days


def run_uptime():
    with open(SITES_FILE) as f:
        sites = yaml.safe_load(f)["sites"]
    state = load_state()
    sites_state = state.setdefault("sites", {})
    changed = False

    for site in sites:
        url = site["url"]
        host = urllib.parse.urlparse(url).hostname
        ok, detail = check_http(url)
        try:
            days = cert_days_left(host)
            cert_ok = days >= TLS_WARN_DAYS
        except Exception as e:  # noqa: BLE001
            days = None
            if ok:
                cert_ok, detail = False, f"TLS check failed: {type(e).__name__}"
            else:  # site is down, we already alert on that
                cert_ok = sites_state.get(url, {}).get("cert_ok", True)
        print(f"{url}: {'UP' if ok else 'DOWN'} ({detail}); cert days left: {days}")

        prev = sites_state.get(url, {})
        status = "up" if ok else "down"
        if prev.get("status") and prev["status"] != status:
            if status == "down":
                ntfy(f"DOWN: {host}", f"{url} is down: {detail}", "high", "rotating_light")
            else:
                ntfy(f"Recovered: {host}", f"{url} is back up ({detail})", "default", "white_check_mark")
        if prev.get("cert_ok", True) and not cert_ok and ok:
            ntfy(f"TLS expiring: {host}", f"Certificate for {host} expires in {days} days", "high", "lock")

        # Only write on a flip, so the state file (and git history) changes only then.
        if status != prev.get("status") or cert_ok != prev.get("cert_ok"):
            sites_state[url] = {"status": status, "cert_ok": cert_ok,
                                "detail": detail, "since": now_iso()}
            changed = True

    for gone in set(sites_state) - {s["url"] for s in sites}:
        del sites_state[gone]
        changed = True

    if changed:
        state["updated"] = now_iso()
    save_state(state)
    return changed


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
    rows, empty = [], []
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
                continue
            raise RuntimeError(f"{dataset}: {msg[:250]}")
        rows += json.loads(out.stdout or "[]")
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

    # Tell Rik once when a source starts or stops failing (not every day).
    # Own file, so it never conflicts with the uptime commits.
    state = load_state(SPEND_STATE_FILE)
    prev = state.get("spend_errors", {})
    if set(errors) != set(prev):
        new = sorted(set(errors) - set(prev))
        fixed = sorted(set(prev) - set(errors))
        lines = [f"{n} not readable: {errors[n]}" for n in new] + [f"{n} readable again" for n in fixed]
        ntfy("ops-monitor spend sources changed", "\n".join(lines), "default", "information_source")
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
