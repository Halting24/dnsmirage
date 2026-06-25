<h1 align="center">dnsmirage</h1>
<p align="center"><b>Catch data being smuggled out over DNS.</b> Tunnel and exfiltration detection from logs or pcaps, with reasons, confidence levels, and MITRE ATT&amp;CK tags.</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/input-BIND%20%7C%20dnsmasq%20%7C%20Zeek%20%7C%20Suricata%20%7C%20tcpdump-7c4dff">
  <img src="https://img.shields.io/badge/detects-dnscat2%20%7C%20iodine%20%7C%20dns2tcp%20%7C%20OzymanDNS-d7263d">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

DNS is almost never firewalled, so attackers tunnel C2 and data exfiltration through it
(dnscat2, iodine, dns2tcp, OzymanDNS). The payload hides as a flood of long, random-looking
subdomain lookups. `dnsmirage` scores every domain on the tell-tale signals and surfaces the
tunnel, and tells you why.

## Quick start

```bash
git clone https://github.com/Halting24/dnsmirage && cd dnsmirage
pip install rich          # only runtime dep; degrades gracefully without it

dnsmirage generate                        # 700 mixed queries: benign + 3 tunnel tools
dnsmirage generate --queries 2000         # larger sample
dnsmirage generate --queries 500 --seed 42   # deterministic/reproducible
dnsmirage analyze sample_dns.log          # rich table, flags all 3 tunnel domains
```

## Commands

### generate

Write a realistic mixed DNS log with benign CDN traffic and tunnel-tool patterns.

```
dnsmirage generate [OPTIONS]

  -o, --out FILE      output path (default: sample_dns.log)
  -n, --queries N     total query count to generate (default: 700)
      --seed INT      random seed for reproducible output
```

Three tunnel-tool patterns are injected: iodine-style (.tun. base32 TXT), dnscat2-style
(hex session + sequence prefix), and generic high-entropy hex exfiltration.

### analyze

Score every domain in a DNS log or pcap. Format is auto-detected.

```
dnsmirage analyze [OPTIONS] [LOGFILE]

  LOGFILE             DNS log file - auto-detects format (default: sample_dns.log)
  --pcap FILE         parse a .pcap file (stdlib struct only, no external deps)
  --allowlist FILE    skip trusted domains listed in FILE (one per line, # = comment)
  --json FILE         write JSON report to FILE
  --csv FILE          write CSV report to FILE
  --html FILE         write dark-themed HTML report to FILE
  --top N             show top N domains in terminal output (default: 20)
```

All output flags can be combined; the rich terminal table is always shown unless all
three output flags are used with `--json`, `--csv`, and `--html` together.

## Supported input formats (auto-detected)

| Format | Example |
|---|---|
| BIND/named CSV (default) | `2026-06-25T10:00:00,evil.net,TXT,NOERROR,192.168.1.5` |
| dnsmasq query log | `Jun 25 10:22:01 dnsmasq[1234]: query[A] example.com from 192.168.1.10` |
| Zeek dns.log (TSV) | standard Zeek output with `#fields` header |
| Suricata eve.json | `{"event_type":"dns","dns":{"type":"query","rrname":"...","rrtype":"TXT"}}` |
| tcpdump -n text | `12:34:56.789 IP 192.168.1.5.52312 > 8.8.8.8.53: A? foo.example.com.` |

## Example: full pipeline

```bash
# Generate a sample
dnsmirage generate --queries 1000 --seed 99 -o bigtest.log

# Analyze and export all formats
dnsmirage analyze bigtest.log --json report.json --csv report.csv --html report.html

# Suppress known CDN noise with an allowlist
dnsmirage analyze bigtest.log --allowlist trusted_cdns.txt

# Analyze a real Zeek dns.log from a sensor
dnsmirage analyze /var/log/bro/dns.log

# Analyze a pcap
dnsmirage analyze --pcap capture.pcap
```

## Example output

```
dnsmirage - DNS Tunneling/Exfiltration Detector
700 queries analyzed - 14 domains - 3 flagged

 Score  Domain            Queries  Confidence  Verdict       MITRE       Signals
  100   evil-c2.net           105  HIGH        TUNNEL/EXFIL  T1071.004   very high entropy (4.55), very long labels, 105 unique subs,
                                                              T1048.003   100% base32/hex/b64, burst rate 505 q/min, tool: iodine
  100   badactor.io           105  HIGH        TUNNEL/EXFIL  T1071.004   very high entropy (4.60), 100% TXT/NULL/CNAME, tool: dnscat2
                                                              T1048.003
  100   exfil-target.ru       105  HIGH        TUNNEL/EXFIL  T1071.004   high entropy (3.85), high digit ratio, tool: OzymanDNS
                                                              T1048.003
    6   google.com             38  NONE        normal        -
    6   apple.com              35  NONE        normal        -

Suspicious source hosts:
  192.168.1.42   105/105 queries to suspicious domains  (evil-c2.net)
  192.168.1.99   105/105 queries to suspicious domains  (badactor.io)
  192.168.1.77   105/105 queries to suspicious domains  (exfil-target.ru)
```

## Detection signals

All signals combine into a weighted 0-100 score with a confidence level (NONE/LOW/MEDIUM/HIGH):

| Signal | Max pts | Notes |
|---|---|---|
| Subdomain Shannon entropy | 30 | Encoded payloads are near-random (about 4.5 bits/char vs about 1.5 for www/api) |
| Average label length | 20 | Tunnel labels are often 40-60 chars |
| Unique subdomain count | 20 | Tunnels burn through hundreds of unique labels |
| Encoded-label ratio | 15 | base32 / hex / base64 pattern match |
| Record-type mix | 15 | High share of TXT, NULL, CNAME (favored for payload capacity) |
| Burst rate | 10 | Bulk transfers spike queries per minute |
| Beaconing regularity | 10 | Tool-driven traffic is metronomically regular |
| NXDOMAIN ratio | 8 | Tools probe non-existent names during channel setup |
| DNS-0x20 obfuscation | 8 | Mixed-case labels used to evade some detectors |
| Label char-class distribution | 6 | Abnormally high digit ratio |
| Known-tool signatures | 25 | iodine, dnscat2, dns2tcp, OzymanDNS regex patterns |
| Estimated bytes exfiltrated | 5 | Rough decode of base32/hex carried in labels |

## MITRE ATT&CK mapping

Flagged domains are tagged automatically:

- **T1071.004** - Application Layer Protocol: DNS (C2 over DNS)
- **T1048.003** - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

## Per-source-host attribution

When the input log includes client IP addresses (BIND CSV columns 4+, Zeek `id.orig_h`,
Suricata `src_ip`), dnsmirage shows which internal host is responsible:

```
Suspicious source hosts:
  192.168.1.42   105 queries to flagged domains  (evil-c2.net)
```

This lets a responder immediately identify which workstation to isolate.

## Allowlist

Create a text file with one trusted domain per line (lines starting with # are comments),
then pass it with `--allowlist`. Known-good high-volume CDN and telemetry domains will be
silently skipped, cutting false positives on noisy networks.

```bash
# trusted_cdns.txt
google.com
cloudflare.com
amazonaws.com
fastly.net
```

## pcap parsing

`dnsmirage analyze --pcap capture.pcap` uses only Python stdlib struct to parse Ethernet/IPv4/IPv6/UDP/DNS.
No scapy, no external deps. Supports pcap files with little-endian or big-endian magic.

## Why it stands out

Not another signature scanner, it uses behavioral analytics on a protocol that most teams
ignore: the same technique a real detection-engineering team builds in-house, in a single
file of mostly-stdlib Python. Zero external dependencies outside of rich for terminal color.

---
<p align="center"><i>Part of a cybersecurity project series by <a href="https://github.com/Halting24">@Halting24</a></i></p>
