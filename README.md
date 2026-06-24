<h1 align="center">🌫️ dnsmirage</h1>
<p align="center"><b>Catch data being smuggled out over DNS.</b> Tunnel &amp; exfiltration detection from logs or pcaps — with reasons.</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/input-DNS%20log%20%C2%B7%20pcap-7c4dff">
  <img src="https://img.shields.io/badge/detects-dnscat2%20%C2%B7%20iodine%20%C2%B7%20DNSExfiltrator-d7263d">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

DNS is almost never firewalled, so attackers tunnel **C2 and data exfiltration** through it (dnscat2, iodine, DNSExfiltrator). The payload hides as a flood of long, random-looking subdomain lookups. `dnsmirage` scores every domain on the tell-tale signals and surfaces the tunnel — and tells you *why*.

## Demo

```text
$ dnsmirage generate            # 400 normal queries + a 300-query tunnel
$ dnsmirage analyze sample_dns.log

dnsmirage · 700 queries · 9 domains · 1 flagged
 score  domain          queries  entropy        verdict        why
   100  evil-c2.net         300   █████████· 4.5  TUNNEL/EXFIL   high entropy (4.5 bits/char),
                                                                 long labels (avg 49 chars),
                                                                 300 unique subdomains
     0  cloudflare.com       48   ███······· 1.5  normal
     0  apple.com            55   ██········ 1.4  normal
```

Real, encoded DNS tunnel traffic lights up at **100**; ordinary CDN/web lookups stay at **0**.

## Detection signals

For every registered domain, `dnsmirage` measures:

- **Subdomain entropy** — base32/base64 payloads are near-random (≈4.5 bits/char vs ~1.5 for `www`/`api`)
- **Label length & unique-subdomain count** — tunnels burn through thousands of unique, long labels
- **Encoded-label ratio** — base32 / hex / base64 patterns
- **Record-type mix** — a high share of `TXT` / `NULL` / `CNAME` (favoured for capacity)
- **Burst rate** — bulk transfers spike queries-per-minute

These combine into a 0–100 score with a per-domain explanation, so an analyst can triage in seconds.

## Install & run

```bash
git clone https://github.com/Halting24/dnsmirage && cd dnsmirage
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # rich (core); scapy only if you use --pcap

dnsmirage generate                        # make a sample log to play with
dnsmirage analyze sample_dns.log
dnsmirage analyze --pcap capture.pcap     # parse a real capture
```

**Log format** (CSV-ish, one query per line): `timestamp,qname,qtype`
Plug it straight onto Zeek `dns.log`, Pi-hole, or `tcpdump` output with a one-line transform.

## Why it stands out

Not another signature scanner — it's **behavioral analytics on a protocol everyone ignores**, the same technique a real detection-engineering / threat-hunting team builds in-house, in ~230 lines of mostly-stdlib Python.

---
<p align="center"><i>Part of a cybersecurity project series · <a href="https://github.com/Halting24">@Halting24</a></i></p>
