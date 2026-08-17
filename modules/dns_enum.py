"""
DNS enumeration.

Resolves a wide spread of DNS record types against the target domain and
returns one structured row per answer.  Inspired by classic recon scripts
but adapted to ReconPilot's callback contract:

  • Runs every record type in every group concurrently via asyncio.
  • One result row per RR  →  {group, type, value, risk}
  • Surfaces DMARC + SPF posture, flags missing DMARC/SPF as MEDIUM.

Targets shaped like ``host:port`` or full URLs are normalised internally —
DNS doesn't care about scheme/port, and asking ``example.com:8080`` of a
resolver just fails with garbage errors.  We log the stripping so the user
sees what happened.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Callable

from utils.logger import ReconLogger
from utils.process_control import stopped
from utils.parser import split_host_port

try:
    import dns.asyncresolver
    import dns.resolver
    _HAS_DNSPY = True
except ImportError:
    _HAS_DNSPY = False

# ── Configuration ────────────────────────────────────────────────────────────
# No ReconPilot-imposed DNS timeout. Resolver defaults are used.

# Grouped record types — same spirit as your reference script, deduped and
# pruned to the types resolvers / authoritative servers actually return.
DNS_GROUPS: dict[str, list[str]] = {
    "core":     ["A", "AAAA", "CNAME", "PTR", "NS", "SOA", "MX"],
    "security": [
        "CAA", "DNSKEY", "CDNSKEY", "CDS", "DS", "RRSIG",
        "NSEC", "NSEC3", "NSEC3PARAM", "TLSA", "SSHFP",
        "SMIMEA", "OPENPGPKEY",
    ],
    "mail":     ["TXT", "SRV", "NAPTR"],
    "network":  ["LOC", "SVCB", "HTTPS", "AFSDB", "KX", "URI"],
    "zone":     ["DNAME"],
    "info":     ["HINFO", "RP", "CERT"],
}


def _is_ip_literal(host: str) -> bool:
    """Quick check — true if `host` parses as an IPv4 or IPv6 literal."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def run_dns_enum(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
) -> None:
    """
    Enumerate DNS for ``target``.  ``done_callback`` receives a list of dicts:
        {"group", "type", "value", "risk"}
    where ``risk`` ∈ {"", "OK", "MEDIUM", "HIGH"}.
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not _HAS_DNSPY:
            line_callback(
                "[DNS] ✘ 'dnspython' not installed (pip install dnspython)."
            )
            done_callback([])
            return

        # Strip scheme/port — DNS is domain-only. We log the normalisation so
        # it's not a silent magic transformation.
        host, port = split_host_port(target)
        if not host:
            line_callback(f"[DNS] ✘ Could not parse target: {target!r}")
            done_callback([])
            return
        if port or target != host:
            line_callback(
                f"[DNS] target {target!r} normalised to domain={host} "
                "(DNS lookups are scheme/port-agnostic)"
            )

        if _is_ip_literal(host):
            line_callback(
                f"[DNS] {host} is an IP literal — domain enumeration N/A. "
                "(Reverse PTR is covered by the LiveHost module.)"
            )
            done_callback([])
            return

        line_callback(f"[DNS] ▶  Enumerating records for {host}")

        rows = asyncio.run(_enumerate(host, line_callback, log))
        log.info(f"[DNS] {len(rows)} record row(s) for {host}")
        done_callback(rows)

    threading.Thread(target=_run, daemon=True).start()


async def _enumerate(domain: str, line_cb, log) -> list[dict]:
    """Resolve every type in every group in parallel; return ordered rows."""
    res = dns.asyncresolver.Resolver()

    # First, do a cheap NXDOMAIN sanity check on the apex via SOA. If the
    # domain itself doesn't exist, no point firing 30+ more queries.
    try:
        await res.resolve(domain, "SOA")
    except dns.resolver.NXDOMAIN:
        line_cb(f"[DNS] ✘ {domain} → NXDOMAIN (domain does not exist).")
        return [{"group": "core", "type": "DOMAIN",
                 "value": "NXDOMAIN — domain does not exist",
                 "risk": "HIGH"}]
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        # No SOA but other records may still exist — keep going.
        pass
    except Exception as exc:
        log.warning(f"[DNS] SOA probe failed: {exc}")

    # Fan out every (group, rrtype) query.
    queries = [(g, t) for g, types in DNS_GROUPS.items() for t in types]
    tasks   = [_query_one(res, domain, t) for g, t in queries]
    answers = await asyncio.gather(*tasks, return_exceptions=False)

    rows: list[dict] = []
    txt_strings: list[str] = []          # we mine these for SPF/DKIM hints

    for (group, rrtype), values in zip(queries, answers):
        for v in values:
            rows.append({"group": group, "type": rrtype,
                         "value": v, "risk": ""})
            if rrtype == "TXT":
                txt_strings.append(v)

    # DMARC (a TXT record on _dmarc.<domain>)
    try:
        dmarc_vals = await _query_one(res, f"_dmarc.{domain}", "TXT")
    except Exception:
        dmarc_vals = []
    if dmarc_vals:
        for v in dmarc_vals:
            rows.append({"group": "DMARC", "type": "DMARC",
                         "value": v, "risk": "OK"})
    else:
        rows.append({"group": "DMARC", "type": "DMARC",
                     "value": "Not configured",
                     "risk": "MEDIUM"})

    # SPF posture from TXT records on the apex
    spf = next((s for s in txt_strings if "v=spf1" in s.lower()), None)
    if spf:
        rows.append({"group": "DMARC", "type": "SPF",
                     "value": spf, "risk": "OK"})
    else:
        rows.append({"group": "DMARC", "type": "SPF",
                     "value": "Not configured",
                     "risk": "MEDIUM"})

    # DNSSEC posture
    has_dnskey = any(r["type"] == "DNSKEY" for r in rows)
    rows.append({
        "group":  "security",
        "type":   "DNSSEC",
        "value":  "DNSKEY present" if has_dnskey else "no DNSKEY visible",
        "risk":   "OK" if has_dnskey else "",
    })

    # Stable display order: group precedence then type, but always lift
    # the apex-defining rows (A/AAAA/SOA/NS) above the rest in 'core'.
    group_order = {g: i for i, g in enumerate(
        ["core", "DMARC", "mail", "security", "network", "zone", "info"]
    )}
    core_priority = {"A": 0, "AAAA": 1, "SOA": 2, "NS": 3,
                     "CNAME": 4, "MX": 5, "PTR": 6}
    rows.sort(key=lambda r: (
        group_order.get(r["group"], 99),
        core_priority.get(r["type"], 50),
        r["type"], r["value"],
    ))

    line_cb(f"[DNS] ✔  {len(rows)} record row(s) collected.")
    return rows


async def _query_one(res, name: str, rrtype: str) -> list[str]:
    """One resolver call → list of stringified answers (never raises)."""
    try:
        ans = await res.resolve(name, rrtype)
        out = []
        for rr in ans:
            try:
                out.append(rr.to_text())
            except Exception:
                out.append(str(rr))
        return out
    except (dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoMetaqueries,
            dns.exception.Timeout):
        return []
    except Exception:
        # Unknown rrtype on older dnspython, etc — swallow and continue.
        return []
