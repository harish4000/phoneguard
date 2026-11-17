#!/usr/bin/env python3
"""Builds PhoneGuard's daily threat definitions. Standard library only.

Output files are sorted one-entry-per-line text, gzipped, because the app binary-searches them on the phone:
  hosts.txt   malicious and phishing hostnames
  hashes.txt  SHA-256, SHA-1 and MD5 of known malicious files
  calls.txt   spam-call numbers and prefixes
  certs.txt   SHA-1 or SHA-256 of signing certificates used by known stalkerware and spyware
  pkgs.txt    package names of known stalkerware and spyware
  bloat.txt   preinstalled apps the community rates safe to remove: package, tab, one-line description
  rules.txt   scam patterns written by the family's own AI model: weight, tab, pattern, tab, reason
  version.txt date and counts
"""
import gzip
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

OUT = sys.argv[1] if len(sys.argv) > 1 else "out"
REPO = os.environ.get("GITHUB_REPOSITORY", "harish4000/phoneguard")
UA = {"User-Agent": "phoneguard-defs"}
HOST_RX = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
HASH_RX = re.compile(r"^(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})$")  # SHA-256, SHA-1 or MD5
CERT_RX = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HEX_IN_TEXT = re.compile(rb"(?<![0-9a-fA-F])([0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
# Hashes of empty input, which appear in reports but identify nothing.
EMPTY = {"d41d8cd98f00b204e9800998ecf8427e", "da39a3ee5e6b4b0d3255bfef95601890afd80709",
         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
IOC_DIR = os.environ.get("IOC_DIR", "ioc")      # shallow clones of vendor indicator repositories
CLAM_DIR = os.environ.get("CLAM_DIR", "clam")    # ClamAV databases fetched by cvdupdate
PKG_RX = re.compile(r"^[a-z][a-z0-9_]*(\.[a-zA-Z0-9_]+)+$")
STALKERWARE = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/"
MAX_HOSTS = 600_000
MAX_HASHES = 500_000

# Shared platforms and major sites. A phishing page hosted on one of these must not get the whole domain flagged,
# because the app also matches parent domains.
NEVER = set("""
google.com google.ca googleusercontent.com googleapis.com gstatic.com youtube.com youtu.be goo.gl forms.gle withgoogle.com
blogspot.com appspot.com web.app firebaseapp.com page.link sites.google.com docs.google.com drive.google.com
microsoft.com live.com office.com outlook.com sharepoint.com windows.net azurewebsites.net onmicrosoft.com bing.com msn.com
apple.com icloud.com amazon.com amazon.ca amazonaws.com cloudfront.net facebook.com fb.com instagram.com whatsapp.com
twitter.com x.com t.co linkedin.com github.com github.io githubusercontent.com gitlab.com gitlab.io dropbox.com
dropboxusercontent.com box.com wetransfer.com notion.so notion.site cloudflare.com pages.dev workers.dev r2.dev
netlify.app vercel.app herokuapp.com glitch.me replit.app repl.co weebly.com wixsite.com wix.com squarespace.com
wordpress.com godaddysites.com webflow.io typedream.app framer.app framer.website carrd.co canva.com canva.site
000webhostapp.com ipfs.io dweb.link bit.ly tinyurl.com is.gd rb.gy cutt.ly ow.ly discord.com discord.gg telegram.org
t.me reddit.com paypal.com netflix.com zoom.us adobe.com yahoo.com duckdns.org ngrok.io ngrok-free.app
walmart.com walmart.ca costco.com costco.ca canadapost.ca canadapost-postescanada.ca interac.ca
""".split())


def fetch(url, data=None, headers=None, timeout=120):
    req = urllib.request.Request(url, data=data, headers={**UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def lines_of(path):
    try:
        with open(path, encoding="utf-8") as f:
            return [x.strip() for x in f if x.strip() and not x.startswith("#")]
    except FileNotFoundError:
        return []


def clean_host(h):
    h = h.strip().lower().rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    return h if HOST_RX.match(h) else None


def shielded(h, allow):
    parts = h.split(".")
    return any(".".join(parts[i:]) in allow for i in range(len(parts) - 1))


def build_hosts(extra=()):
    allow = NEVER | {x.lower() for x in lines_of("data/hosts-allow.txt")}
    hosts = {h for h in extra if not shielded(h, allow)}
    sources = [
        ("phishing-database", "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", False),
        ("openphish", "https://openphish.com/feed.txt", True),
    ]
    for name, url, is_urls in sources:
        try:
            n = 0
            for line in fetch(url).decode("utf-8", "replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                raw = urllib.parse.urlsplit(line).hostname if is_urls else line
                h = clean_host(raw or "")
                if h and not shielded(h, allow):
                    hosts.add(h)
                    n += 1
            print(f"{name}: {n} hosts")
        except Exception as e:  # one dead feed must not stop the build
            print(f"{name}: FAILED {e}")
    for line in lines_of("data/hosts-extra.txt"):
        h = clean_host(line)
        if h:
            hosts.add(h)
    return sorted(hosts)[:MAX_HOSTS]


def build_hashes(seed):
    hashes = set(seed)
    try:  # yesterday's list, so matches accumulate
        prev = gzip.decompress(fetch(f"https://github.com/{REPO}/releases/download/defs/hashes.txt.gz"))
        hashes.update(x for x in prev.decode().split() if real_hash(x))
        print(f"previous hashes: {len(hashes)}")
    except Exception as e:
        print(f"previous hashes: none ({e})")
    key = os.environ.get("ABUSECH_KEY", "").strip()
    if key:
        try:
            body = urllib.parse.urlencode({"query": "get_file_type", "file_type": "apk", "limit": "1000"}).encode()
            data = json.loads(fetch("https://mb-api.abuse.ch/api/v1/", data=body, headers={"Auth-Key": key}))
            new = [d.get("sha256_hash", "").lower() for d in (data.get("data") or [])]
            new = [x for x in new if HASH_RX.match(x)]
            hashes.update(new)
            print(f"malwarebazaar: {len(new)} recent apk hashes ({data.get('query_status')})")
        except Exception as e:
            print(f"malwarebazaar: FAILED {e}")
    else:
        print("malwarebazaar: skipped, ABUSECH_KEY secret not set")
    hashes.update(x.lower() for x in lines_of("data/hashes-extra.txt") if HASH_RX.match(x.lower()))
    hashes -= {x.lower() for x in lines_of("data/hashes-allow.txt")}
    return sorted(hashes)[-MAX_HASHES:] if len(hashes) > MAX_HASHES else sorted(hashes)


def build_stalkerware():
    """Package names, signing certificates and sample hashes from the Echap stalkerware-indicators project (CC BY 4.0)."""
    pkgs, certs, hashes = set(), set(), set()
    try:
        section = None
        for line in fetch(STALKERWARE + "ioc.yaml").decode("utf-8", "replace").splitlines():
            m = re.match(r"^\s{2}(\w+):\s*$", line)
            if m:
                section = m.group(1)
                continue
            if line.startswith("- name"):
                section = None
                continue
            m = re.match(r"^\s+-\s+(\S+)\s*$", line)
            if not m:
                continue
            v = m.group(1).strip("'\"")
            if section == "packages" and PKG_RX.match(v):
                pkgs.add(v)
            elif section == "certificates" and CERT_RX.match(v.lower()):
                certs.add(v.lower())
        for row in fetch(STALKERWARE + "samples.csv").decode("utf-8", "replace").splitlines()[1:]:
            h = row.split(",")[0].strip().lower()
            if HASH_RX.match(h):
                hashes.add(h)
        print(f"stalkerware: {len(pkgs)} packages, {len(certs)} certificates, {len(hashes)} hashes")
    except Exception as e:
        print(f"stalkerware: FAILED {e}")
    for line in lines_of("data/pkgs-extra.txt"):
        if PKG_RX.match(line):
            pkgs.add(line)
    return sorted(pkgs), sorted(certs), hashes


def build_bloat():
    """Universal Android Debloater list (GPL-3.0). Only entries rated Recommended, the safest tier."""
    url = ("https://raw.githubusercontent.com/Universal-Debloater-Alliance/"
           "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json")
    rows = []
    try:
        data = json.loads(fetch(url))
        items = data.items() if isinstance(data, dict) else [(x.get("id"), x) for x in data]
        for pkg, v in items:
            if not pkg or v.get("removal") != "Recommended" or not PKG_RX.match(pkg):
                continue
            desc = (v.get("description") or "").strip().splitlines()
            note = re.sub(r"[^\x20-\x7e]", "", desc[0] if desc else "").replace("\t", " ").strip()[:140]
            rows.append(f"{pkg}\t{note}")
        print(f"debloat list: {len(rows)} apps rated safe to remove")
    except Exception as e:
        print(f"debloat list: FAILED {e}")
    return sorted(rows)


def build_rules():
    """AI-written scam patterns from data/scam-rules.txt, checked again here so nothing unsafe reaches a phone."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import rulecheck
    benign = lines_of("data/benign-messages.txt")
    rows, dropped = [], 0
    for line in lines_of("data/scam-rules.txt"):
        p = line.split("\t")
        if len(p) < 4 or not p[1].isdigit():
            dropped += 1
            continue
        weight = max(rulecheck.MIN_WEIGHT, min(rulecheck.MAX_WEIGHT, int(p[1])))
        reason = re.sub(r"[^\x20-\x7e]", "", p[3]).strip()[:80]
        if rulecheck.problem(p[2], benign) or not reason:
            dropped += 1
            continue
        rows.append(f"{weight}\t{p[2]}\t{reason}")
    print(f"ai scam rules: {len(rows)} active, {dropped} dropped")
    return sorted(set(rows))[:400]


def real_hash(h):
    return HASH_RX.match(h) and h not in EMPTY and not h.isdigit() and len(set(h)) > 6


def build_vendor_hashes():
    """File hashes published by security vendors alongside their research (ESET, Doctor Web, Cisco Talos, Amnesty, MVT).

    The repositories are cloned by the workflow. Their content is untrusted: it is only scanned for hash-shaped text.
    """
    found = set()
    if not os.path.isdir(IOC_DIR):
        print("vendor indicators: none fetched")
        return found
    for repo in sorted(os.listdir(IOC_DIR)):
        before = len(found)
        for dp, dn, fn in os.walk(os.path.join(IOC_DIR, repo)):
            dn[:] = [d for d in dn if d != ".git"]
            for name in fn:
                path = os.path.join(dp, name)
                try:
                    if os.path.islink(path) or os.path.getsize(path) > 8_000_000:
                        continue
                    with open(path, "rb") as f:
                        blob = f.read()
                except OSError:
                    continue
                for h in HEX_IN_TEXT.findall(blob):
                    h = h.decode().lower()
                    if real_hash(h):
                        found.add(h)
        print(f"vendor indicators: {repo}: {len(found) - before} hashes")
    return found


def build_clamav_hashes():
    """Android entries from ClamAV's main and daily databases (hash signatures only)."""
    import io
    import tarfile
    found = set()
    for name in ("main.cvd", "daily.cvd", "main.cld", "daily.cld"):
        path = os.path.join(CLAM_DIR, name)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "rb") as f:
                raw = f.read()
            if name.endswith(".cvd"):
                raw = raw[512:]
            with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as t:
                for m in t.getmembers():
                    if not m.name.endswith((".hdb", ".hsb")):
                        continue
                    for line in t.extractfile(m):
                        p = line.decode("latin1").strip().split(":")
                        if len(p) >= 3 and p[2].startswith(("Andr.", "Android.")) and real_hash(p[0].lower()):
                            found.add(p[0].lower())
        except Exception as e:
            print(f"clamav: {name} FAILED {e}")
    print(f"clamav: {len(found)} android hashes")
    return found


STIX_RX = re.compile(r"\[(domain-name:value|file:hashes\.[a-z0-9-]+|app:id|app:cert\.sha256|app:cert\.sha1)\s*=\s*'([^']+)'\]")


def build_spyware_stix():
    """Mercenary and state spyware indicators (Pegasus, Predator and others) from the MVT project index and Amnesty."""
    domains, hashes, pkgs, certs = set(), set(), set(), set()
    texts = []
    for dp, dn, fn in os.walk(IOC_DIR) if os.path.isdir(IOC_DIR) else []:
        dn[:] = [d for d in dn if d != ".git"]
        for name in fn:
            if name.endswith(".stix2"):
                try:
                    texts.append(open(os.path.join(dp, name), encoding="utf-8", errors="replace").read())
                except OSError:
                    pass
    # The MVT index also points at indicator files kept in other repositories.
    try:
        idx = fetch("https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml").decode("utf-8", "replace")
        for block in idx.split("github:")[1:]:
            f = dict(re.findall(r"^\s+(owner|repo|branch|path):\s*(\S+)\s*$", block, re.M)[:4])
            if len(f) == 4 and re.match(r"^[\w.-]+$", f["owner"]) and re.match(r"^[\w.-]+$", f["repo"]):
                try:
                    texts.append(fetch(f"https://raw.githubusercontent.com/{f['owner']}/{f['repo']}/{f['branch']}/{f['path']}", timeout=60).decode("utf-8", "replace"))
                except Exception:
                    pass
    except Exception as e:
        print(f"spyware index: FAILED {e}")
    for text in texts:
        for kind, value in STIX_RX.findall(text):
            v = value.strip()
            if kind == "domain-name:value":
                h = clean_host(v)
                if h:
                    domains.add(h)
            elif kind.startswith("file:hashes"):
                if real_hash(v.lower()):
                    hashes.add(v.lower())
            elif kind == "app:id" and PKG_RX.match(v):
                pkgs.add(v)
            elif kind.startswith("app:cert") and CERT_RX.match(v.lower()):
                certs.add(v.lower())
    print(f"spyware indicators: {len(domains)} domains, {len(hashes)} hashes, {len(pkgs)} packages, {len(certs)} certificates")
    return domains, hashes, pkgs, certs


def build_calls():
    out = set()
    for line in lines_of("data/calls.txt"):
        d = re.sub(r"\D", "", line)
        if len(d) >= 3:
            out.add(d)
    return sorted(out)


def write_gz(name, rows):
    with open(os.path.join(OUT, name + ".gz"), "wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as z:
            z.write(("\n".join(rows) + ("\n" if rows else "")).encode("ascii"))


def main():
    os.makedirs(OUT, exist_ok=True)
    pkgs, certs, sample_hashes = build_stalkerware()
    spy_domains, spy_hashes, spy_pkgs, spy_certs = build_spyware_stix()
    pkgs = sorted(set(pkgs) | spy_pkgs)
    certs = sorted(set(certs) | spy_certs)
    seed = set(sample_hashes) | spy_hashes | build_vendor_hashes() | build_clamav_hashes()
    hosts, hashes, calls = build_hosts(spy_domains), build_hashes(seed), build_calls()
    if len(hosts) < 1000:
        # Refuse to publish a near-empty list over a good one when the feeds are down.
        sys.exit(f"Only {len(hosts)} hosts collected. Feeds look down, keeping yesterday's definitions.")
    write_gz("hosts.txt", hosts)
    write_gz("hashes.txt", hashes)
    write_gz("calls.txt", calls)
    write_gz("certs.txt", certs)
    write_gz("pkgs.txt", pkgs)
    rules = build_rules()
    write_gz("rules.txt", rules)
    bloat = build_bloat()
    if bloat:
        write_gz("bloat.txt", bloat)
    else:  # keep the app's download from failing if the list is unreachable today
        try:
            open(os.path.join(OUT, "bloat.txt.gz"), "wb").write(fetch(f"https://github.com/{REPO}/releases/download/defs/bloat.txt.gz"))
        except Exception:
            write_gz("bloat.txt", [])
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(os.path.join(OUT, "version.txt"), "w") as f:
        f.write(f"{stamp} hosts={len(hosts)} hashes={len(hashes)} certs={len(certs)} pkgs={len(pkgs)} calls={len(calls)} airules={len(rules)}\n")
    print(open(os.path.join(OUT, "version.txt")).read().strip())


if __name__ == "__main__":
    main()
