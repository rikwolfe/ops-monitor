"""Mail-authentication check: SPF, DKIM and DMARC for every domain in sites.yml.

Asks each zone's own Google Cloud DNS nameservers (no resolver cache), so a
change shows up on the next run. Compares what it finds with the `mail:` block
of each domain in sites.yml:

  mail:
    senders: [google, m365, mailerlite]   # who may send; [] = parked (never sends)
    dmarc: none | quarantine | reject     # the policy we expect right now

A parked domain must publish exactly "v=spf1 -all" and DMARC p=reject, so
nobody can send mail in its name. A sending domain must have one valid SPF
record that lists its senders, a DKIM key for each sender, and the DMARC policy
we expect. Nothing here changes DNS: it only reports.
"""
import re
import subprocess

# What each sender needs: an SPF include and the DKIM selector(s) it signs with.
SENDERS = {
    "google":     {"spf": "_spf.google.com",          "dkim": ["google"]},
    "m365":       {"spf": "spf.protection.outlook.com", "dkim": ["selector1", "selector2"]},
    "mailerlite": {"spf": "_spf.mlsend.com",          "dkim": ["ml"]},
    "firebase":   {"spf": "_spf.firebasemail.com",    "dkim": []},
    "ses":        {"spf": "amazonses.com",            "dkim": []},
}
PARKED_SPF = "v=spf1 -all"


def dig_txt(name, server):
    """(status, [record, ...]) for TXT at an authoritative server. Each record is
    its character-strings joined with NO separator, which is how mail servers
    read them (RFC 7208 3.3): "v=spf1" "~all" really is "v=spf1~all"."""
    out = subprocess.run(["dig", "+norec", "+time=5", "+tries=2", "TXT", name, "@" + server],
                         capture_output=True, text=True).stdout
    if "status: " not in out:
        return "TIMEOUT", [], []
    status = out.split("status: ", 1)[1].split(",", 1)[0]
    records, cnames, in_answer = [], [], False
    for line in out.splitlines():
        if line.startswith(";; ANSWER SECTION"):
            in_answer = True
        elif in_answer and not line.strip():
            break
        elif in_answer and not line.startswith(";"):
            parts = line.split(None, 4)
            if len(parts) == 5 and parts[3] == "TXT":
                records.append("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', parts[4])))
            elif len(parts) == 5 and parts[3] == "CNAME":
                cnames.append(parts[4].strip())
    return status, records, cnames


def ask(name, servers):
    for ns in servers:
        status, txt, cnames = dig_txt(name, ns)
        if status in ("NOERROR", "NXDOMAIN"):
            return status, txt, cnames
    return "TIMEOUT", [], []


def dmarc_tags(record):
    return {k.strip().lower(): v.strip() for k, v in
            (p.split("=", 1) for p in record.split(";") if "=" in p)}


def check(domain):
    """Return (problems, facts) for one domain entry from sites.yml."""
    name, want = domain["name"], domain.get("mail_auth") or {}
    senders = want.get("senders", [])
    servers = [f"ns-cloud-{domain['ns']}{i}.googledomains.com" for i in (1, 2)]
    problems, facts = [], {}

    status, txt, _ = ask(name, servers)
    if status == "TIMEOUT":
        return ["nameservers did not answer"], facts
    spf = [r for r in txt if r.lower().startswith("v=spf1")]
    facts["spf"] = spf[0] if len(spf) == 1 else spf
    if not spf:
        problems.append("no SPF record")
    elif len(spf) > 1:
        problems.append(f"{len(spf)} SPF records (must be one)")
    else:
        s = spf[0]
        if not re.match(r"^v=spf1( |$)", s) or re.search(r"[a-z0-9]include:|[a-z0-9][~-]all", s):
            problems.append(f"SPF is broken (words run together): {s}")
        elif not senders:
            if s != PARKED_SPF:
                problems.append(f"parked domain, SPF should be '{PARKED_SPF}', is '{s}'")
        else:
            if not re.search(r" [~-]all$", s):
                problems.append(f"SPF does not end in -all or ~all: {s}")
            for snd in senders:
                inc = SENDERS[snd]["spf"]
                if f"include:{inc}" not in s:
                    problems.append(f"SPF misses {snd} (include:{inc})")

    status, txt, _ = ask(f"_dmarc.{name}", servers)
    dmarc = [r for r in txt if r.lower().startswith("v=dmarc1")]
    facts["dmarc"] = dmarc[0] if len(dmarc) == 1 else dmarc
    if not dmarc:
        problems.append("no DMARC record")
    elif len(dmarc) > 1:
        problems.append(f"{len(dmarc)} DMARC records (must be one)")
    else:
        tags = dmarc_tags(dmarc[0])
        p, expect = tags.get("p", "?"), want.get("dmarc", "reject" if not senders else "none")
        if p != expect:
            problems.append(f"DMARC p={p}, expected p={expect}")
        if senders and "rua" not in tags:
            problems.append("DMARC has no report address (rua)")

    for snd in senders:
        for sel in SENDERS[snd]["dkim"]:
            status, txt, cnames = ask(f"{sel}._domainkey.{name}", servers)
            if not (cnames or any("p=" in r for r in txt)):
                problems.append(f"no DKIM key for {snd} ({sel}._domainkey)")

    return problems, facts


def run(domains):
    """Return {domain: problems} for every domain that has a mail_auth block."""
    from concurrent.futures import ThreadPoolExecutor
    checked = [d for d in domains if "mail_auth" in d]
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = dict(zip([d["name"] for d in checked], pool.map(check, checked)))
    return results
