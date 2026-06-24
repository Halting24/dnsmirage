#!/usr/bin/env python3
"""
dnsmirage — catch data being smuggled out over DNS.

DNS is almost never blocked, so attackers tunnel C2 and exfiltrate data through
it (dnscat2, iodine, DNSExfiltrator). The traffic hides in plain sight as a flood
of long, high-entropy subdomain lookups. dnsmirage scores every domain in a DNS
log (or pcap) on the tell-tale signals and flags the tunnels — with reasons.

    dnsmirage generate                 # write a realistic sample log (normal + a tunnel)
    dnsmirage analyze sample_dns.log   # score every domain, flag exfiltration
    dnsmirage analyze --pcap dns.pcap  # parse a capture instead (needs scapy)

Detection signals per domain:
  • subdomain Shannon entropy (encoded data looks random)
  • subdomain length & count of unique subdomains (tunnels burn through many)
  • base32/base64/hex-looking labels
  • share of TXT / NULL / CNAME records (favoured for capacity)
  • query volume / burst rate
"""
from __future__ import annotations

import argparse
import math
import random
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

ENCODED = re.compile(r"^[a-z2-7]{16,}$|^[a-f0-9]{16,}$|^[A-Za-z0-9+/=_-]{20,}$")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = defaultdict(int)
    for c in s:
        counts[c] += 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parent_domain(qname: str) -> tuple[str, str]:
    """Return (registered_domain, subdomain_part). Approximate eTLD+1 via last 2 labels."""
    labels = qname.strip(".").split(".")
    if len(labels) <= 2:
        return qname.strip("."), ""
    return ".".join(labels[-2:]), ".".join(labels[:-2])


# --------------------------------------------------------------------------- #
@dataclass
class DomainStat:
    domain: str
    subs: list[str] = field(default_factory=list)
    qtypes: list[str] = field(default_factory=list)
    times: list[datetime] = field(default_factory=list)

    def score(self) -> tuple[int, list[str]]:
        subs = [s for s in self.subs if s]
        n = len(self.qtypes)
        reasons, pts = [], 0.0
        if subs:
            ent = sum(entropy(s) for s in subs) / len(subs)
            avglen = sum(len(s) for s in subs) / len(subs)
            uniq = len(set(subs))
            enc = sum(bool(ENCODED.match(s.split(".")[0].lower())) for s in subs) / len(subs)
            if ent >= 3.5:
                pts += 30; reasons.append(f"high entropy ({ent:.1f} bits/char)")
            elif ent >= 3.0:
                pts += 15; reasons.append(f"elevated entropy ({ent:.1f})")
            if avglen >= 30:
                pts += 20; reasons.append(f"long labels (avg {avglen:.0f} chars)")
            if uniq >= 50:
                pts += 20; reasons.append(f"{uniq} unique subdomains")
            elif uniq >= 20:
                pts += 10; reasons.append(f"{uniq} unique subdomains")
            if enc >= 0.5:
                pts += 15; reasons.append("base32/hex-encoded labels")
        odd = sum(t in ("TXT", "NULL", "CNAME") for t in self.qtypes)
        if n and odd / n >= 0.5:
            pts += 15; reasons.append(f"{round(100*odd/n)}% TXT/NULL/CNAME")
        if len(self.times) >= 2:
            span = (max(self.times) - min(self.times)).total_seconds() or 1
            rate = n / span * 60
            if rate >= 60:
                pts += 10; reasons.append(f"burst rate ({rate:.0f} q/min)")
        return min(100, round(pts)), reasons


def analyze(records: list[tuple[datetime, str, str]]) -> list[tuple[DomainStat, int, list[str]]]:
    stats: dict[str, DomainStat] = {}
    for ts, qname, qtype in records:
        dom, sub = parent_domain(qname)
        st = stats.setdefault(dom, DomainStat(dom))
        st.subs.append(sub); st.qtypes.append(qtype); st.times.append(ts)
    scored = [(st, *st.score()) for st in stats.values()]
    return sorted(scored, key=lambda x: x[1], reverse=True)


# --------------------------------------------------------------------------- #
def load_log(path: Path) -> list[tuple[datetime, str, str]]:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\t,]\s*|\s{2,}", line)
        if len(parts) < 3:
            parts = line.split()
        ts_s, qname, qtype = parts[0], parts[-2], parts[-1]
        try:
            ts = datetime.fromisoformat(ts_s)
        except ValueError:
            ts = datetime.fromtimestamp(float(ts_s)) if ts_s.replace(".", "").isdigit() else datetime.now()
        out.append((ts, qname.lower().rstrip("."), qtype.upper()))
    return out


def load_pcap(path: Path) -> list[tuple[datetime, str, str]]:
    try:
        from scapy.all import rdpcap, DNS, DNSQR
    except ImportError:
        sys.exit("pcap parsing needs scapy:  pip install scapy")
    out = []
    for pkt in rdpcap(str(path)):
        if pkt.haslayer(DNS) and pkt[DNS].qd is not None and pkt[DNS].qr == 0:
            q = pkt[DNSQR]
            qt = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 10: "NULL"}.get(q.qtype, str(q.qtype))
            out.append((datetime.fromtimestamp(float(pkt.time)),
                        q.qname.decode(errors="ignore").lower().rstrip("."), qt))
    return out


# --------------------------------------------------------------------------- #
def generate(path: Path, n_normal: int = 400, n_exfil: int = 300):
    import base64
    base = datetime.now()
    rows = []
    normal = ["google.com", "apple.com", "github.com", "cloudflare.com",
              "microsoft.com", "amazonaws.com", "fastly.net", "akamai.net"]
    subs = ["www", "api", "cdn", "mail", "static", "img", "login", "m", ""]
    for i in range(n_normal):
        d = random.choice(normal); s = random.choice(subs)
        q = f"{s + '.' if s else ''}{d}"
        rows.append((base + timedelta(seconds=random.uniform(0, 3600)),
                     q, random.choice(["A", "A", "A", "AAAA", "CNAME"])))
    # a DNS tunnel to attacker infra: many high-entropy base32 TXT lookups, fast
    t0 = base + timedelta(seconds=1800)
    for i in range(n_exfil):
        chunk = base64.b32encode(random.randbytes(28)).decode().lower().rstrip("=")
        q = f"{chunk}.tun.evil-c2.net"
        rows.append((t0 + timedelta(milliseconds=i * 120), q,
                     random.choice(["TXT", "NULL", "TXT"])))
    rows.sort(key=lambda r: r[0])
    path.write_text("# timestamp,qname,qtype\n" +
                    "\n".join(f"{ts.isoformat()},{q},{t}" for ts, q, t in rows) + "\n")
    print(f"wrote {len(rows)} DNS queries ({n_normal} normal + {n_exfil} tunnel) -> {path}")


# --------------------------------------------------------------------------- #
def report(scored):
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for st, sc, why in scored:
            print(f"{sc:3}  {st.domain:28} {', '.join(why)}")
        return
    con = Console()
    flagged = [x for x in scored if x[1] >= 50]
    con.print(f"[bold]dnsmirage[/] · {sum(len(s.qtypes) for s,_,_ in scored)} queries · "
              f"{len(scored)} domains · [red]{len(flagged)} flagged[/]")
    t = Table(header_style="bold")
    t.add_column("score", justify="right"); t.add_column("domain")
    t.add_column("queries", justify="right"); t.add_column("entropy")
    t.add_column("verdict"); t.add_column("why")
    for st, sc, why in scored[:15]:
        subs = [s for s in st.subs if s]
        ent = sum(entropy(s) for s in subs) / len(subs) if subs else 0
        bar = "█" * int(ent / 4.7 * 10) + "·" * (10 - int(ent / 4.7 * 10))
        verdict = ("[red]TUNNEL/EXFIL[/]" if sc >= 70 else
                   "[yellow]suspicious[/]" if sc >= 50 else "[green]normal[/]")
        color = "red" if sc >= 70 else "yellow" if sc >= 50 else "white"
        t.add_row(f"[{color}]{sc}[/]", st.domain, str(len(st.qtypes)),
                  f"{bar} {ent:.1f}", verdict, ", ".join(why[:3]))
    con.print(t)


def main(argv=None):
    p = argparse.ArgumentParser(prog="dnsmirage",
                                description="Detect DNS tunneling / exfiltration in logs or pcaps.")
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate", help="write a realistic sample log")
    g.add_argument("-o", "--out", default="sample_dns.log")
    a = sub.add_parser("analyze", help="score a log/pcap for exfiltration")
    a.add_argument("logfile", nargs="?", help="CSV-ish DNS log (timestamp,qname,qtype)")
    a.add_argument("--pcap", help="parse a .pcap instead (needs scapy)")
    args = p.parse_args(argv)

    if args.cmd == "generate":
        generate(Path(args.out)); return 0
    records = load_pcap(Path(args.pcap)) if args.pcap else \
        load_log(Path(args.logfile or "sample_dns.log"))
    scored = analyze(records)
    report(scored)
    return 1 if any(sc >= 70 for _, sc, _ in scored) else 0


if __name__ == "__main__":
    raise SystemExit(main())
