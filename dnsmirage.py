#!/usr/bin/env python3
"""
dnsmirage - catch data being smuggled out over DNS.

DNS is almost never blocked, so attackers tunnel C2 and exfiltrate data through
it (dnscat2, iodine, dns2tcp, OzymanDNS). The traffic hides in plain sight as a
flood of long, high-entropy subdomain lookups. dnsmirage scores every domain in a
DNS log (or pcap) on the tell-tale signals and flags the tunnels, with reasons,
confidence levels, and MITRE ATT&CK tags.

    dnsmirage generate                    # write a realistic sample log
    dnsmirage generate --queries 1000     # control total query count
    dnsmirage analyze sample_dns.log      # score every domain, flag exfiltration
    dnsmirage analyze sample_dns.log --json out.json
    dnsmirage analyze sample_dns.log --csv  out.csv
    dnsmirage analyze sample_dns.log --html out.html
    dnsmirage analyze --allowlist cdns.txt sample_dns.log

Supported input formats (auto-detected):
  - BIND/named query log (default CSV-ish format used by this tool)
  - dnsmasq query log
  - Zeek dns.log (TSV with #fields header)
  - Suricata eve.json (dns event type)
  - tcpdump -n text output

Detection signals per domain:
  - subdomain Shannon entropy (encoded data looks random)
  - subdomain length and count of unique subdomains (tunnels burn through many)
  - base32/base64/hex-looking labels
  - share of TXT/NULL/CNAME records (favoured for capacity)
  - query volume/burst rate
  - beaconing regularity (uniform inter-query intervals typical of tools)
  - NXDOMAIN ratio (tools often probe non-existent names while enumerating)
  - uppercase/DNS-0x20 obfuscation ratio
  - label character-class distribution
  - known-tool signature patterns (iodine, dnscat2, dns2tcp, OzymanDNS)
  - estimated bytes exfiltrated
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import random
import re
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------
ENCODED_B32 = re.compile(r"^[a-z2-7]{16,}$")
ENCODED_HEX = re.compile(r"^[a-f0-9]{16,}$")
ENCODED_B64 = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")
ENCODED = re.compile(r"^[a-z2-7]{16,}$|^[a-f0-9]{16,}$|^[A-Za-z0-9+/=_-]{20,}$")

# Known-tool patterns applied to the full query name
TOOL_SIGS = [
    ("iodine",     re.compile(r"(?:^|\.)(?:t[0-9]+|[a-z][0-9]{5})\.[a-z0-9-]+\.[a-z]{2,}$")),
    ("iodine",     re.compile(r"\.tun\d*\.")),
    ("dnscat2",    re.compile(r"(?:^|\.)[a-f0-9]{8}\.[a-f0-9]{4}\.")),
    ("dns2tcp",    re.compile(r"\.[a-z0-9]{32,}\.[a-z0-9-]{1,20}\.[a-z]{2,}$")),
    ("OzymanDNS",  re.compile(r"(?:^|\.)(?:ssh|data|file)[0-9]*\.[a-z0-9-]+\.[a-z]{2,}$")),
]

QTYPE_NAMES = {1: "A", 28: "AAAA", 16: "TXT", 5: "CNAME", 10: "NULL",
               12: "PTR", 15: "MX", 2: "NS", 33: "SRV", 255: "ANY"}

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def parent_domain(qname: str) -> tuple[str, str]:
    """Return (registered_domain, subdomain_part). Approximate eTLD+1 via last 2 labels."""
    labels = qname.strip(".").split(".")
    if len(labels) <= 2:
        return qname.strip("."), ""
    return ".".join(labels[-2:]), ".".join(labels[:-2])


def beaconing_score(intervals: list[float]) -> float:
    """Return 0-1 regularity score. Perfect beaconing = 1.0. Noise = 0.0."""
    if len(intervals) < 5:
        return 0.0
    mean = sum(intervals) / len(intervals)
    if mean == 0:
        return 0.0
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    cv = math.sqrt(variance) / mean  # coefficient of variation
    # Low CV = very regular = suspicious
    return max(0.0, 1.0 - min(cv, 1.0))


def estimate_bytes(subs: list[str]) -> int:
    """Rough estimate of bytes carried in subdomain labels (base32 decodes to 5/8)."""
    total = 0
    for s in subs:
        # base32: each char is 5 bits so 8 chars = 5 bytes
        if ENCODED_B32.match(s.lower()):
            total += len(s) * 5 // 8
        elif ENCODED_HEX.match(s.lower()):
            total += len(s) // 2
        else:
            total += len(s)  # raw upper bound
    return total


def check_tool_sigs(qname: str) -> list[str]:
    found = []
    for name, pat in TOOL_SIGS:
        if pat.search(qname) and name not in found:
            found.append(name)
    return found


# ---------------------------------------------------------------------------
# Domain statistics and scoring
# ---------------------------------------------------------------------------

@dataclass
class DomainStat:
    domain: str
    subs: list[str] = field(default_factory=list)
    qtypes: list[str] = field(default_factory=list)
    times: list[datetime] = field(default_factory=list)
    rcodes: list[str] = field(default_factory=list)        # NOERROR, NXDOMAIN, etc.
    src_ips: list[str] = field(default_factory=list)       # client IPs if available
    raw_qnames: list[str] = field(default_factory=list)    # full query names
    tool_hits: list[str] = field(default_factory=list)     # matched tool signatures

    def score(self) -> tuple[int, list[str], str, list[str]]:
        """Return (score 0-100, reasons, confidence, mitre_tags)."""
        subs_nonempty = [s for s in self.subs if s]
        n = len(self.qtypes)
        reasons: list[str] = []
        pts = 0.0

        # 1. Shannon entropy of subdomain labels (weight 30)
        ent = 0.0
        if subs_nonempty:
            ent = sum(entropy(s) for s in subs_nonempty) / len(subs_nonempty)
            if ent >= 3.8:
                pts += 30; reasons.append(f"very high entropy ({ent:.2f} bits/char)")
            elif ent >= 3.3:
                pts += 20; reasons.append(f"high entropy ({ent:.2f} bits/char)")
            elif ent >= 3.0:
                pts += 10; reasons.append(f"elevated entropy ({ent:.2f} bits/char)")

        # 2. Average label length (weight 20)
        if subs_nonempty:
            avglen = sum(len(s) for s in subs_nonempty) / len(subs_nonempty)
            if avglen >= 40:
                pts += 20; reasons.append(f"very long labels (avg {avglen:.0f} chars)")
            elif avglen >= 25:
                pts += 10; reasons.append(f"long labels (avg {avglen:.0f} chars)")

        # 3. Unique subdomain count (weight 20)
        if subs_nonempty:
            uniq = len(set(subs_nonempty))
            if uniq >= 100:
                pts += 20; reasons.append(f"{uniq} unique subdomains")
            elif uniq >= 30:
                pts += 12; reasons.append(f"{uniq} unique subdomains")
            elif uniq >= 10:
                pts += 6; reasons.append(f"{uniq} unique subdomains")

        # 4. Encoded-label ratio (weight 15)
        if subs_nonempty:
            enc = sum(
                bool(ENCODED.match(s.split(".")[0].lower())) for s in subs_nonempty
            ) / len(subs_nonempty)
            if enc >= 0.7:
                pts += 15; reasons.append(f"{round(enc*100)}% base32/hex/b64 labels")
            elif enc >= 0.4:
                pts += 8; reasons.append(f"{round(enc*100)}% encoded-looking labels")

        # 5. Record-type mix - TXT/NULL/CNAME (weight 15)
        odd = sum(t in ("TXT", "NULL", "CNAME") for t in self.qtypes)
        if n and odd / n >= 0.7:
            pts += 15; reasons.append(f"{round(100*odd/n)}% TXT/NULL/CNAME (tunnel types)")
        elif n and odd / n >= 0.4:
            pts += 8; reasons.append(f"{round(100*odd/n)}% TXT/NULL/CNAME")

        # 6. Burst rate (weight 10)
        if len(self.times) >= 5:
            times_sorted = sorted(self.times)
            span = (times_sorted[-1] - times_sorted[0]).total_seconds() or 1
            rate = n / span * 60
            if rate >= 120:
                pts += 10; reasons.append(f"burst rate ({rate:.0f} q/min)")
            elif rate >= 40:
                pts += 5; reasons.append(f"elevated rate ({rate:.0f} q/min)")

        # 7. Beaconing regularity (weight 10)
        if len(self.times) >= 10:
            times_sorted = sorted(self.times)
            intervals = [
                (times_sorted[i+1] - times_sorted[i]).total_seconds()
                for i in range(len(times_sorted) - 1)
            ]
            # Filter near-zero intervals (duplicates)
            intervals = [x for x in intervals if x > 0.01]
            if intervals:
                bscore = beaconing_score(intervals)
                if bscore >= 0.85:
                    pts += 10; reasons.append(f"highly regular beaconing (regularity={bscore:.2f})")
                elif bscore >= 0.65:
                    pts += 5; reasons.append(f"regular intervals (regularity={bscore:.2f})")

        # 8. NXDOMAIN ratio (weight 8)
        if self.rcodes:
            nx = sum(1 for r in self.rcodes if r == "NXDOMAIN")
            nxr = nx / len(self.rcodes)
            if nxr >= 0.5:
                pts += 8; reasons.append(f"{round(nxr*100)}% NXDOMAIN responses")
            elif nxr >= 0.2:
                pts += 4; reasons.append(f"{round(nxr*100)}% NXDOMAIN responses")

        # 9. DNS-0x20 / uppercase obfuscation (weight 8)
        if self.raw_qnames:
            mixed = sum(
                1 for q in self.raw_qnames if any(c.isupper() for c in q.split(".")[0])
            )
            mixr = mixed / len(self.raw_qnames)
            if mixr >= 0.5:
                pts += 8; reasons.append(f"{round(mixr*100)}% mixed-case (DNS-0x20 obfuscation)")

        # 10. Label character-class distribution (weight 6)
        if subs_nonempty:
            all_chars = "".join(subs_nonempty)
            digits = sum(c.isdigit() for c in all_chars)
            letters = sum(c.isalpha() for c in all_chars)
            total_c = len(all_chars) or 1
            digit_ratio = digits / total_c
            # High digit ratio is unusual in legitimate subdomains
            if digit_ratio >= 0.35:
                pts += 6; reasons.append(f"high digit ratio in labels ({digit_ratio:.0%})")

        # 11. Known-tool signatures (weight 25, independent)
        all_tools = list(self.tool_hits)
        for qname in self.raw_qnames:
            for tool in check_tool_sigs(qname):
                if tool not in all_tools:
                    all_tools.append(tool)
        if all_tools:
            pts += 25
            reasons.append(f"tool signatures: {', '.join(set(all_tools))}")

        # 12. Estimated bytes smuggled (informational, small weight)
        est = estimate_bytes(subs_nonempty)
        if est >= 50000:
            pts += 5; reasons.append(f"est. {est//1024}KB payload encoded in labels")
        elif est >= 10000:
            pts += 2; reasons.append(f"est. {est//1024}KB payload in labels")

        final_score = min(100, round(pts))

        # Confidence level based on number of independent signals triggered
        n_signals = len(reasons)
        if final_score >= 70 and n_signals >= 4:
            confidence = "HIGH"
        elif final_score >= 50 or n_signals >= 3:
            confidence = "MEDIUM"
        elif final_score >= 20 or n_signals >= 1:
            confidence = "LOW"
        else:
            confidence = "NONE"

        # MITRE tags
        mitre: list[str] = []
        if final_score >= 50:
            mitre.append("T1071.004")   # Application Layer Protocol - DNS (C2)
        if final_score >= 70 or est >= 10000:
            mitre.append("T1048.003")   # Exfiltration Over Alternative Protocol

        return final_score, reasons, confidence, mitre


# ---------------------------------------------------------------------------
# Per-source-host aggregation
# ---------------------------------------------------------------------------

@dataclass
class HostStat:
    """Aggregate suspicious activity per internal client IP."""
    ip: str
    domains: dict[str, int] = field(default_factory=lambda: defaultdict(int))  # domain -> query count
    total_queries: int = 0
    flagged_queries: int = 0

    def add(self, domain: str, flagged: bool) -> None:
        self.domains[domain] += 1
        self.total_queries += 1
        if flagged:
            self.flagged_queries += 1


# ---------------------------------------------------------------------------
# Input format auto-detection and parsing
# ---------------------------------------------------------------------------

def detect_format(lines: list[str]) -> str:
    """Detect log format from the first non-comment lines."""
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            # Zeek uses #separator and #fields headers
            if line.startswith("#separator") or line.startswith("#fields"):
                return "zeek"
            continue
        # Suricata eve.json: starts with {
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if "event_type" in obj:
                    return "suricata"
            except json.JSONDecodeError:
                pass
        # tcpdump text: looks like "HH:MM:SS.ffffff IP src > dst: ... A? qname."
        if re.match(r"\d{2}:\d{2}:\d{2}\.\d+ IP ", line):
            return "tcpdump"
        # dnsmasq: "Mon Jan  2 15:04:05 2006 dnsmasq[pid]: query[TYPE] name from ip"
        if re.search(r"dnsmasq\[\d+\].*query\[", line):
            return "dnsmasq"
        # Default to bind/named/our CSV
        break
    # Check for Zeek #fields header
    for line in lines[:20]:
        if line.startswith("#fields"):
            return "zeek"
    return "bind"


def parse_zeek_line(line: str, fields: list[str]) -> Optional[tuple[datetime, str, str, str, str, str]]:
    """Parse a Zeek dns.log TSV line. Returns (ts, qname, qtype, rcode, src_ip, '')."""
    parts = line.split("\t")
    if len(parts) < len(fields):
        return None
    d = dict(zip(fields, parts))
    ts_str = d.get("ts", "")
    qname = d.get("query", "").lower().rstrip(".")
    qtype = d.get("qtype_name", d.get("qtype", "A")).upper()
    rcode = d.get("rcode_name", "").upper()
    src = d.get("id.orig_h", "")
    if not qname or qname == "-":
        return None
    try:
        ts = datetime.fromtimestamp(float(ts_str))
    except (ValueError, TypeError):
        ts = datetime.now()
    return ts, qname, qtype, rcode, src, ""


def parse_suricata_line(line: str) -> Optional[tuple[datetime, str, str, str, str, str]]:
    """Parse a Suricata eve.json DNS event line."""
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if obj.get("event_type") != "dns":
        return None
    dns = obj.get("dns", {})
    # Only process queries (type=query) or all if type not present
    if dns.get("type", "query") not in ("query", ""):
        return None
    qname = dns.get("rrname", "").lower().rstrip(".")
    qtype = dns.get("rrtype", "A").upper()
    rcode = dns.get("rcode", "").upper()
    src = obj.get("src_ip", "")
    ts_str = obj.get("timestamp", "")
    if not qname:
        return None
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        ts = datetime.now()
    return ts, qname, qtype, rcode, src, ""


def parse_tcpdump_line(line: str) -> Optional[tuple[datetime, str, str, str, str, str]]:
    """Parse tcpdump -n text output. Example:
    12:34:56.789012 IP 192.168.1.5.52312 > 8.8.8.8.53: A? foo.example.com. (28)
    """
    m = re.match(
        r"(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([\d\.]+)\.\d+\s+>.*?:\s+(\w+)\?\s+([\w\.\-]+)",
        line
    )
    if not m:
        return None
    ts_str, src, qtype, qname = m.groups()
    qname = qname.lower().rstrip(".")
    now = datetime.now()
    try:
        h, mi, s = ts_str.split(":")
        sec, us = s.split(".")
        ts = now.replace(hour=int(h), minute=int(mi), second=int(sec),
                         microsecond=int(us[:6].ljust(6, "0")))
    except (ValueError, AttributeError):
        ts = now
    return ts, qname, qtype.upper(), "", src, ""


def parse_dnsmasq_line(line: str) -> Optional[tuple[datetime, str, str, str, str, str]]:
    """Parse dnsmasq query log. Example:
    Jun 25 10:22:01 dnsmasq[1234]: query[A] example.com from 192.168.1.10
    Or with date+time:
    2026-06-25T10:22:01 dnsmasq[1234]: query[A] example.com from 192.168.1.10
    """
    m = re.search(r"query\[(\w+)\]\s+([\w\.\-]+)\s+from\s+([\d\.]+)", line)
    if not m:
        return None
    qtype, qname, src = m.groups()
    qname = qname.lower().rstrip(".")
    # Try ISO timestamp first
    ts_m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if ts_m:
        try:
            ts = datetime.fromisoformat(ts_m.group(1))
        except ValueError:
            ts = datetime.now()
    else:
        ts = datetime.now()
    return ts, qname, qtype.upper(), "", src, ""


def parse_bind_line(line: str) -> Optional[tuple[datetime, str, str, str, str, str]]:
    """Parse our default CSV-ish format (timestamp,qname,qtype[,rcode][,src_ip])."""
    if not line or line.startswith("#"):
        return None
    # Try splitting on comma or tab
    parts = re.split(r"[,\t]", line.strip())
    if len(parts) < 3:
        parts = line.split()
    if len(parts) < 3:
        return None
    ts_s = parts[0].strip()
    qname = parts[1].strip().lower().rstrip(".")
    qtype = parts[2].strip().upper()
    rcode = parts[3].strip().upper() if len(parts) > 3 else ""
    src = parts[4].strip() if len(parts) > 4 else ""
    try:
        ts = datetime.fromisoformat(ts_s)
    except ValueError:
        try:
            ts = datetime.fromtimestamp(float(ts_s))
        except (ValueError, OSError):
            ts = datetime.now()
    return ts, qname, qtype, rcode, src, ""


def load_log(path: Path) -> list[tuple[datetime, str, str, str, str, str]]:
    """
    Auto-detect format and return list of (ts, qname, qtype, rcode, src_ip, raw_qname).
    raw_qname preserves original case before lowercasing.
    """
    text = path.read_text(errors="replace")
    lines = text.splitlines()
    fmt = detect_format(lines)

    out: list[tuple[datetime, str, str, str, str, str]] = []

    if fmt == "zeek":
        fields: list[str] = []
        for line in lines:
            if line.startswith("#fields"):
                fields = line[len("#fields"):].strip().split("\t")
                continue
            if line.startswith("#") or not line.strip():
                continue
            r = parse_zeek_line(line, fields)
            if r:
                ts, qname, qtype, rcode, src, _ = r
                out.append((ts, qname, qtype, rcode, src, r[1]))  # raw = qname before lower
            continue

        return out

    if fmt == "suricata":
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = parse_suricata_line(line)
            if r:
                ts, qname, qtype, rcode, src, _ = r
                out.append((ts, qname, qtype, rcode, src, qname))
        return out

    if fmt == "tcpdump":
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = parse_tcpdump_line(line)
            if r:
                ts, qname, qtype, rcode, src, _ = r
                out.append((ts, qname, qtype, rcode, src, qname))
        return out

    if fmt == "dnsmasq":
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = parse_dnsmasq_line(line)
            if r:
                ts, qname, qtype, rcode, src, _ = r
                out.append((ts, qname, qtype, rcode, src, qname))
        return out

    # Default: bind/named/our CSV
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        r = parse_bind_line(line)
        if r:
            ts, qname, qtype, rcode, src, _ = r
            out.append((ts, qname, qtype, rcode, src, qname))
    return out


def load_pcap(path: Path) -> list[tuple[datetime, str, str, str, str, str]]:
    """
    Parse a pcap file using stdlib struct only (no scapy).
    Handles pcap global header, then packet records, extracts UDP/DNS queries.
    Returns same tuple as load_log.
    """
    data = path.read_bytes()
    if len(data) < 24:
        sys.exit("pcap file too small or corrupt")

    # Parse pcap global header
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xA1B2C3D4:
        endian = "<"
    elif magic == 0xD4C3B2A1:
        endian = ">"
    elif magic in (0xA1B23C4D, 0x4D3CB2A1):
        # nanosecond variant
        endian = "<" if magic == 0xA1B23C4D else ">"
    else:
        sys.exit(f"not a valid pcap file (magic={hex(magic)})")

    _ver_maj, _ver_min, _thiszone, _sigfigs, snaplen, network = struct.unpack_from(
        endian + "HHIIII", data, 4
    )

    out: list[tuple[datetime, str, str, str, str, str]] = []
    offset = 24

    while offset + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            break
        pkt = data[offset: offset + incl_len]
        offset += incl_len
        ts = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000)

        try:
            # network=1 is Ethernet
            if network == 1 and len(pkt) >= 14:
                eth_type = struct.unpack_from(">H", pkt, 12)[0]
                if eth_type == 0x0800:      # IPv4
                    ip_off = 14
                elif eth_type == 0x86DD:    # IPv6
                    ip_off = 14
                else:
                    continue
                if eth_type == 0x0800 and len(pkt) >= ip_off + 20:
                    ihl = (pkt[ip_off] & 0x0F) * 4
                    proto = pkt[ip_off + 9]
                    src_ip = ".".join(str(b) for b in pkt[ip_off+12:ip_off+16])
                    udp_off = ip_off + ihl
                    if proto != 17:     # not UDP
                        continue
                elif eth_type == 0x86DD:    # IPv6 simplified
                    proto = pkt[ip_off + 6]
                    src_ip = ":".join(
                        format(struct.unpack_from(">H", pkt, ip_off+8+i*2)[0], "x")
                        for i in range(8)
                    )
                    udp_off = ip_off + 40
                    if proto != 17:
                        continue
                else:
                    continue

                if len(pkt) < udp_off + 8:
                    continue
                dst_port = struct.unpack_from(">H", pkt, udp_off + 2)[0]
                if dst_port != 53:
                    continue
                dns_off = udp_off + 8
                dns_data = pkt[dns_off:]
                if len(dns_data) < 12:
                    continue
                # DNS header: id(2), flags(2), qdcount(2), ancount(2), nscount(2), arcount(2)
                flags = struct.unpack_from(">H", dns_data, 2)[0]
                qr = (flags >> 15) & 1
                if qr != 0:     # only parse queries
                    continue
                qdcount = struct.unpack_from(">H", dns_data, 4)[0]
                if qdcount < 1:
                    continue
                # Parse first QNAME
                pos = 12
                labels = []
                while pos < len(dns_data):
                    length = dns_data[pos]
                    if length == 0:
                        pos += 1
                        break
                    if (length & 0xC0) == 0xC0:     # compression pointer
                        pos += 2
                        break
                    pos += 1
                    if pos + length > len(dns_data):
                        break
                    labels.append(dns_data[pos:pos+length].decode(errors="ignore"))
                    pos += length
                if not labels:
                    continue
                qname = ".".join(labels).lower()
                if pos + 4 <= len(dns_data):
                    qtype_num = struct.unpack_from(">H", dns_data, pos)[0]
                    qtype = QTYPE_NAMES.get(qtype_num, str(qtype_num))
                else:
                    qtype = "A"
                out.append((ts, qname, qtype, "", src_ip, qname))
        except (struct.error, IndexError, UnicodeDecodeError):
            continue

    return out


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze(
    records: list[tuple[datetime, str, str, str, str, str]],
    allowlist: set[str] | None = None,
) -> tuple[list[tuple[DomainStat, int, list[str], str, list[str]]], dict[str, HostStat]]:
    """
    Score every domain.
    Returns (scored_domains, host_stats).
    scored_domains is list of (DomainStat, score, reasons, confidence, mitre_tags).
    """
    if allowlist is None:
        allowlist = set()

    stats: dict[str, DomainStat] = {}
    for ts, qname, qtype, rcode, src_ip, raw_qname in records:
        dom, sub = parent_domain(qname)
        if dom in allowlist:
            continue
        st = stats.setdefault(dom, DomainStat(dom))
        st.subs.append(sub)
        st.qtypes.append(qtype)
        st.times.append(ts)
        if rcode:
            st.rcodes.append(rcode)
        if src_ip:
            st.src_ips.append(src_ip)
        if raw_qname:
            st.raw_qnames.append(raw_qname)
        # Pre-check tool signatures on full qname
        for tool in check_tool_sigs(qname):
            if tool not in st.tool_hits:
                st.tool_hits.append(tool)

    scored = [(st, *st.score()) for st in stats.values()]
    scored = sorted(scored, key=lambda x: x[1], reverse=True)

    # Per-source-host aggregation
    host_stats: dict[str, HostStat] = {}
    for ts, qname, qtype, rcode, src_ip, raw_qname in records:
        if not src_ip:
            continue
        dom, _ = parent_domain(qname)
        if dom in allowlist:
            continue
        hs = host_stats.setdefault(src_ip, HostStat(src_ip))
        score_for_domain = next((sc for st, sc, *_ in scored if st.domain == dom), 0)
        hs.add(dom, score_for_domain >= 50)

    return scored, host_stats


# ---------------------------------------------------------------------------
# Generate sample log
# ---------------------------------------------------------------------------

def generate(path: Path, total_queries: int = 700, seed: Optional[int] = None):
    """Generate a realistic mixed DNS log with benign + tunnel traffic."""
    if seed is not None:
        random.seed(seed)

    import base64
    base_time = datetime(2026, 6, 24, 14, 0, 0)
    rows: list[tuple[datetime, str, str, str, str]] = []

    benign_domains = [
        "google.com", "apple.com", "github.com", "cloudflare.com",
        "microsoft.com", "amazonaws.com", "fastly.net", "akamai.net",
        "gstatic.com", "icloud.com", "office365.com",
    ]
    benign_subs = ["www", "api", "cdn", "mail", "static", "img", "login", "m",
                   "update", "push", "analytics", ""]
    benign_types = ["A", "A", "A", "AAAA", "CNAME"]
    benign_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.20", "10.0.0.5"]

    # Allocate about 55% benign, 45% tunnel
    n_benign = int(total_queries * 0.55)
    n_tunnel_remaining = total_queries - n_benign

    # Benign traffic spread over full window
    for _ in range(n_benign):
        d = random.choice(benign_domains)
        s = random.choice(benign_subs)
        q = f"{s + '.' if s else ''}{d}"
        ts = base_time + timedelta(seconds=random.uniform(0, 3600))
        rcode = random.choice(["NOERROR"] * 19 + ["NXDOMAIN"])
        src = random.choice(benign_ips)
        rows.append((ts, q, random.choice(benign_types), rcode, src))

    # Tunnel tool 1: iodine-style (base32 subdomain, .tun. in path)
    n_iodine = n_tunnel_remaining // 3
    t0 = base_time + timedelta(seconds=1800)
    infected_host = "192.168.1.42"
    for i in range(n_iodine):
        chunk = base64.b32encode(random.randbytes(28)).decode().lower().rstrip("=")
        q = f"{chunk}.tun0.evil-c2.net"
        ts = t0 + timedelta(milliseconds=i * 120)
        rows.append((ts, q, random.choice(["TXT", "NULL", "TXT"]), "NOERROR", infected_host))

    # Tunnel tool 2: dnscat2-style (hex session ID prefix)
    n_dnscat = n_tunnel_remaining // 3
    t1 = base_time + timedelta(seconds=2200)
    infected_host2 = "192.168.1.99"
    for i in range(n_dnscat):
        session = format(random.randint(0, 0xFFFFFFFF), "08x")
        seq = format(random.randint(0, 0xFFFF), "04x")
        payload = base64.b32encode(random.randbytes(20)).decode().lower().rstrip("=")
        q = f"{session}.{seq}.{payload}.dnscat.badactor.io"
        ts = t1 + timedelta(milliseconds=i * 100)
        rows.append((ts, q, "CNAME", "NOERROR", infected_host2))

    # Tunnel tool 3: generic high-entropy hex exfil
    n_hex = n_tunnel_remaining - n_iodine - n_dnscat
    t2 = base_time + timedelta(seconds=2700)
    infected_host3 = "192.168.1.77"
    for i in range(n_hex):
        chunk = "".join(format(b, "02x") for b in random.randbytes(20))
        q = f"{chunk}.data.exfil-target.ru"
        ts = t2 + timedelta(milliseconds=i * 150)
        rows.append((ts, q, random.choice(["TXT", "A"]), "NOERROR", infected_host3))

    rows.sort(key=lambda r: r[0])
    lines = ["# timestamp,qname,qtype,rcode,src_ip"]
    for ts, q, t, rc, src in rows:
        lines.append(f"{ts.isoformat()},{q},{t},{rc},{src}")
    path.write_text("\n".join(lines) + "\n")
    print(
        f"wrote {len(rows)} DNS queries "
        f"({n_benign} normal + {n_iodine} iodine + {n_dnscat} dnscat2 + {n_hex} hex-exfil) "
        f"-> {path}"
    )


# ---------------------------------------------------------------------------
# Load allowlist
# ---------------------------------------------------------------------------

def load_allowlist(path: Path) -> set[str]:
    """Read a plain-text file of domains, one per line."""
    domains = set()
    for line in path.read_text().splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            domains.add(line)
    return domains


# ---------------------------------------------------------------------------
# Output renderers
# ---------------------------------------------------------------------------

def render_rich(
    scored: list[tuple[DomainStat, int, list[str], str, list[str]]],
    host_stats: dict[str, HostStat],
) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
    except ImportError:
        render_plain(scored, host_stats)
        return

    con = Console()
    total_q = sum(len(st.qtypes) for st, *_ in scored)
    flagged = [x for x in scored if x[1] >= 50]

    con.print(Panel(
        f"[bold cyan]dnsmirage[/] - DNS Tunneling/Exfiltration Detector\n"
        f"{total_q} queries analyzed - {len(scored)} domains - "
        f"[red bold]{len(flagged)} flagged[/]",
        border_style="cyan"
    ))

    t = Table(header_style="bold cyan", show_lines=True)
    t.add_column("Score", justify="right", width=6)
    t.add_column("Domain", width=28)
    t.add_column("Queries", justify="right", width=7)
    t.add_column("Entropy", width=14)
    t.add_column("Confidence", width=10)
    t.add_column("Verdict", width=14)
    t.add_column("MITRE", width=22)
    t.add_column("Signals", width=45)

    for st, sc, why, conf, mitre in scored[:20]:
        subs = [s for s in st.subs if s]
        ent = sum(entropy(s) for s in subs) / len(subs) if subs else 0
        bar = "█" * int(ent / 4.7 * 10) + "·" * (10 - int(ent / 4.7 * 10))
        if sc >= 70:
            verdict = "[red bold]TUNNEL/EXFIL[/]"
            color = "red"
        elif sc >= 50:
            verdict = "[yellow]suspicious[/]"
            color = "yellow"
        else:
            verdict = "[green]normal[/]"
            color = "white"
        mitre_str = " ".join(mitre) if mitre else "-"
        conf_colored = (
            f"[red]{conf}[/]" if conf == "HIGH"
            else f"[yellow]{conf}[/]" if conf == "MEDIUM"
            else f"[dim]{conf}[/]"
        )
        t.add_row(
            f"[{color}]{sc}[/]",
            st.domain,
            str(len(st.qtypes)),
            f"{bar} {ent:.1f}",
            conf_colored,
            verdict,
            mitre_str,
            ", ".join(why[:4]),
        )
    con.print(t)

    # Per-host table if any hosts found
    flagged_hosts = {ip: hs for ip, hs in host_stats.items() if hs.flagged_queries > 0}
    if flagged_hosts:
        con.print("\n[bold cyan]Suspicious source hosts:[/]")
        ht = Table(header_style="bold cyan")
        ht.add_column("Source IP", width=18)
        ht.add_column("Total Queries", justify="right", width=13)
        ht.add_column("To Flagged Domains", justify="right", width=18)
        ht.add_column("Top Suspicious Domains", width=40)
        for ip, hs in sorted(flagged_hosts.items(),
                              key=lambda kv: kv[1].flagged_queries, reverse=True):
            top_domains = sorted(
                [(d, c) for d, c in hs.domains.items()],
                key=lambda dc: dc[1], reverse=True
            )[:3]
            top_str = ", ".join(f"{d}({c})" for d, c in top_domains)
            ht.add_row(ip, str(hs.total_queries), str(hs.flagged_queries), top_str)
        con.print(ht)


def render_plain(
    scored: list[tuple[DomainStat, int, list[str], str, list[str]]],
    host_stats: dict[str, HostStat],
) -> None:
    total_q = sum(len(st.qtypes) for st, *_ in scored)
    flagged = [x for x in scored if x[1] >= 50]
    print(f"dnsmirage - {total_q} queries - {len(scored)} domains - {len(flagged)} flagged")
    for st, sc, why, conf, mitre in scored[:20]:
        verdict = "TUNNEL/EXFIL" if sc >= 70 else "suspicious" if sc >= 50 else "normal"
        mitre_str = " ".join(mitre) if mitre else ""
        print(f"{sc:3}  {conf:6}  {st.domain:30}  {verdict:14}  {mitre_str:22}  {', '.join(why[:3])}")
    for ip, hs in sorted(host_stats.items(), key=lambda kv: kv[1].flagged_queries, reverse=True):
        if hs.flagged_queries > 0:
            print(f"HOST {ip}: {hs.flagged_queries}/{hs.total_queries} queries to suspicious domains")


def render_json(
    scored: list[tuple[DomainStat, int, list[str], str, list[str]]],
    host_stats: dict[str, HostStat],
    path: str,
) -> None:
    results = {
        "tool": "dnsmirage",
        "total_queries": sum(len(st.qtypes) for st, *_ in scored),
        "total_domains": len(scored),
        "flagged_count": sum(1 for _, sc, *_ in scored if sc >= 50),
        "domains": [
            {
                "domain": st.domain,
                "score": sc,
                "confidence": conf,
                "verdict": ("TUNNEL/EXFIL" if sc >= 70 else "suspicious" if sc >= 50 else "normal"),
                "mitre_tags": mitre,
                "reasons": why,
                "query_count": len(st.qtypes),
                "unique_subdomains": len(set(s for s in st.subs if s)),
                "query_types": dict(Counter(st.qtypes)),
                "source_ips": list(set(st.src_ips)),
                "estimated_bytes": estimate_bytes([s for s in st.subs if s]),
            }
            for st, sc, why, conf, mitre in scored
        ],
        "suspicious_hosts": [
            {
                "ip": hs.ip,
                "total_queries": hs.total_queries,
                "flagged_queries": hs.flagged_queries,
                "domains": dict(hs.domains),
            }
            for hs in sorted(host_stats.values(), key=lambda h: h.flagged_queries, reverse=True)
            if hs.flagged_queries > 0
        ],
    }
    out_path = Path(path)
    out_path.write_text(json.dumps(results, indent=2))
    print(f"JSON report -> {out_path}")


def render_csv(
    scored: list[tuple[DomainStat, int, list[str], str, list[str]]],
    path: str,
) -> None:
    out_path = Path(path)
    with out_path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "domain", "score", "confidence", "verdict",
            "mitre_tags", "query_count", "unique_subdomains",
            "estimated_bytes_exfil", "signals"
        ])
        for st, sc, why, conf, mitre in scored:
            verdict = "TUNNEL/EXFIL" if sc >= 70 else "suspicious" if sc >= 50 else "normal"
            writer.writerow([
                st.domain, sc, conf, verdict,
                "|".join(mitre),
                len(st.qtypes),
                len(set(s for s in st.subs if s)),
                estimate_bytes([s for s in st.subs if s]),
                " | ".join(why),
            ])
    print(f"CSV report -> {out_path}")


def render_html(
    scored: list[tuple[DomainStat, int, list[str], str, list[str]]],
    host_stats: dict[str, HostStat],
    path: str,
) -> None:
    rows_html = []
    for st, sc, why, conf, mitre in scored:
        verdict = "TUNNEL/EXFIL" if sc >= 70 else "suspicious" if sc >= 50 else "normal"
        row_class = "tunnel" if sc >= 70 else "suspicious" if sc >= 50 else "normal"
        mitre_str = " ".join(mitre) if mitre else "-"
        why_str = "; ".join(why)
        rows_html.append(
            f'<tr class="{row_class}">'
            f"<td>{sc}</td><td>{st.domain}</td>"
            f"<td>{len(st.qtypes)}</td><td>{conf}</td>"
            f"<td>{verdict}</td><td>{mitre_str}</td>"
            f"<td>{why_str}</td></tr>"
        )

    host_rows = []
    for ip, hs in sorted(host_stats.items(), key=lambda kv: kv[1].flagged_queries, reverse=True):
        if hs.flagged_queries > 0:
            top = sorted(hs.domains.items(), key=lambda dc: dc[1], reverse=True)[:3]
            top_str = ", ".join(f"{d}({c})" for d, c in top)
            host_rows.append(
                f'<tr class="suspicious"><td>{ip}</td>'
                f"<td>{hs.total_queries}</td><td>{hs.flagged_queries}</td>"
                f"<td>{top_str}</td></tr>"
            )

    total_q = sum(len(st.qtypes) for st, *_ in scored)
    flagged_count = sum(1 for _, sc, *_ in scored if sc >= 50)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>dnsmirage - DNS Exfiltration Report</title>
<style>
body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; margin: 2em; }}
h1 {{ color: #58a6ff; }}
h2 {{ color: #79c0ff; margin-top: 2em; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
th {{ background: #161b22; color: #58a6ff; padding: 0.5em 1em; text-align: left; }}
td {{ padding: 0.4em 1em; border-bottom: 1px solid #21262d; }}
.tunnel {{ background: rgba(248, 81, 73, 0.15); }}
.suspicious {{ background: rgba(210, 153, 34, 0.15); }}
.normal {{ background: rgba(46, 160, 67, 0.05); }}
.tunnel td:nth-child(5) {{ color: #f85149; font-weight: bold; }}
.suspicious td:nth-child(5) {{ color: #d29922; }}
.normal td:nth-child(5) {{ color: #2ea043; }}
.summary {{ background: #161b22; border: 1px solid #30363d; padding: 1em; border-radius: 6px; }}
</style>
</head>
<body>
<h1>dnsmirage - DNS Tunneling/Exfiltration Report</h1>
<div class="summary">
<p>Total queries: <strong>{total_q}</strong> | Domains analyzed: <strong>{len(scored)}</strong> |
Flagged: <strong style="color:#f85149">{flagged_count}</strong></p>
</div>
<h2>Domain Scores</h2>
<table>
<tr><th>Score</th><th>Domain</th><th>Queries</th><th>Confidence</th>
<th>Verdict</th><th>MITRE</th><th>Signals</th></tr>
{"".join(rows_html)}
</table>
"""
    if host_rows:
        html += f"""<h2>Suspicious Source Hosts</h2>
<table>
<tr><th>Source IP</th><th>Total Queries</th><th>To Flagged Domains</th><th>Top Domains</th></tr>
{"".join(host_rows)}
</table>
"""
    html += "</body></html>\n"
    out_path = Path(path)
    out_path.write_text(html)
    print(f"HTML report -> {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        prog="dnsmirage",
        description=(
            "Detect DNS tunneling and exfiltration in logs or pcaps. "
            "Auto-detects BIND, dnsmasq, Zeek dns.log, Suricata eve.json, and tcpdump formats."
        )
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # generate subcommand
    g = sub.add_parser("generate", help="write a realistic sample log (normal + tunnel traffic)")
    g.add_argument("-o", "--out", default="sample_dns.log",
                   help="output path (default: sample_dns.log)")
    g.add_argument("-n", "--queries", type=int, default=700,
                   help="total number of queries to generate (default: 700)")
    g.add_argument("--seed", type=int, default=None,
                   help="random seed for reproducible output")

    # analyze subcommand
    a = sub.add_parser(
        "analyze",
        help="score a DNS log or pcap for exfiltration - auto-detects format"
    )
    a.add_argument("logfile", nargs="?", default="sample_dns.log",
                   help="DNS log file (auto-detects: BIND/dnsmasq/Zeek/Suricata/tcpdump)")
    a.add_argument("--pcap", help="parse a .pcap file (stdlib struct only, no scapy)")
    a.add_argument("--allowlist", metavar="FILE",
                   help="file of trusted domains to skip (one per line)")
    a.add_argument("--json", metavar="FILE",
                   help="write JSON report to FILE")
    a.add_argument("--csv", metavar="FILE",
                   help="write CSV report to FILE")
    a.add_argument("--html", metavar="FILE",
                   help="write HTML report to FILE")
    a.add_argument("--top", type=int, default=20,
                   help="show top N domains in rich/plain output (default: 20)")

    args = p.parse_args(argv)

    if args.cmd == "generate":
        generate(Path(args.out), total_queries=args.queries, seed=args.seed)
        return 0

    # analyze
    allowlist: set[str] = set()
    if args.allowlist:
        allowlist = load_allowlist(Path(args.allowlist))
        print(f"allowlist loaded: {len(allowlist)} trusted domains")

    if args.pcap:
        records = load_pcap(Path(args.pcap))
    else:
        log_path = Path(args.logfile)
        if not log_path.exists():
            sys.exit(f"file not found: {log_path}")
        records = load_log(log_path)

    if not records:
        print("no DNS records parsed - check format")
        return 0

    scored, host_stats = analyze(records, allowlist=allowlist)

    # Output
    if args.json:
        render_json(scored, host_stats, args.json)
    if args.csv:
        render_csv(scored, args.csv)
    if args.html:
        render_html(scored, host_stats, args.html)
    if not (args.json and args.csv and args.html):
        render_rich(scored, host_stats)

    return 1 if any(sc >= 70 for _, sc, *_ in scored) else 0


if __name__ == "__main__":
    raise SystemExit(main())
