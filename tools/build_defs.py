#!/usr/bin/env python3
"""Builds PhoneGuard's daily threat definitions. Standard library only.

Output files are sorted one-entry-per-line text, gzipped, because the app binary-searches them on the phone:
  hosts.txt   malicious and phishing hostnames
  hashes.txt  SHA-256 of known malicious Android packages
  calls.txt   spam-call numbers and prefixes
  certs.txt   SHA-1 of signing certificates used by known stalkerware
  pkgs.txt    package names of known stalkerware
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
HASH_RX = re.compile(r"^[0-9a-f]{64}$")
CERT_RX = re.compile(r"^[0-9a-f]{40}$")
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


def build_hosts():
    allow = NEVER | {x.lower() for x in lines_of("data/hosts-allow.txt")}
    hosts = set()
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
        hashes.update(x for x in prev.decode().split() if HASH_RX.match(x))
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
    hosts, hashes, calls = build_hosts(), build_hashes(sample_hashes), build_calls()
    if len(hosts) < 1000:
        # Refuse to publish a near-empty list over a good one when the feeds are down.
        sys.exit(f"Only {len(hosts)} hosts collected. Feeds look down, keeping yesterday's definitions.")
    write_gz("hosts.txt", hosts)
    write_gz("hashes.txt", hashes)
    write_gz("calls.txt", calls)
    write_gz("certs.txt", certs)
    write_gz("pkgs.txt", pkgs)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(os.path.join(OUT, "version.txt"), "w") as f:
        f.write(f"{stamp} hosts={len(hosts)} hashes={len(hashes)} certs={len(certs)} pkgs={len(pkgs)} calls={len(calls)}\n")
    print(open(os.path.join(OUT, "version.txt")).read().strip())


if __name__ == "__main__":
    main()
