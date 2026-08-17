"""
SSL/TLS certificate enumeration.

Connects to <host>:<port> (defaults to 443), performs an unverified TLS
handshake, pulls the server's leaf certificate in DER form, and reports:

    • Negotiated TLS protocol + cipher suite
    • Subject DN (CN, O, OU, …) and Issuer DN
    • Cert version + serial number + signature algorithm
    • Validity window (notBefore / notAfter) + days remaining
    • Subject Alternative Names (DNS, IP)
    • Health flags: expired, expiring-soon (<30d), self-signed, weak protocol

Streams rows to the UI as (category, field, value) so the SSL/TLS tab can
render the cert as a flat property list.

Per project rule (only nmap strips the port), this module *uses* the port
from the user's target verbatim — `192.168.1.10:8443` connects to 8443,
`example.com` defaults to 443.
"""
from __future__ import annotations

import json
import socket
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from utils.logger import ReconLogger
from utils.process_control import stopped
from utils.parser import split_host_port

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# No hard TCP/TLS timeout: the handshake runs until it succeeds/fails naturally or Stop Scan is pressed.
DEFAULT_PORT = 443
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
EXPIRY_WARN_DAYS = 30


def _dn_to_dict(name) -> dict[str, str]:
    """Flatten an x509.Name (Subject / Issuer) into {attr_name: value}."""
    out: dict[str, str] = {}
    for attr in name:
        try:
            out[attr.oid._name] = str(attr.value)
        except Exception:
            out[str(attr.oid.dotted_string)] = str(attr.value)
    return out


def _extract_sans(cert) -> dict[str, list[str]]:
    """Pull DNS + IP entries out of the SubjectAlternativeName extension."""
    dns: list[str] = []
    ips: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        for entry in ext:
            if isinstance(entry, x509.DNSName):
                dns.append(entry.value)
            elif isinstance(entry, x509.IPAddress):
                ips.append(str(entry.value))
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    return {"dns": dns, "ips": ips}


def run_ssl_cert(
    target:        str,
    output_dir:    str,
    log:           ReconLogger,
    line_callback: Callable[[str], None],
    done_callback: Callable[[list], None],
    stop_evt:      threading.Event | None = None,
) -> None:
    """
    Inspect the TLS certificate served by <target> and report structured rows.
    done_callback receives a list of dicts shaped:
        {"category", "field", "value", "risk"}
    where risk is one of: "" (info), "OK", "MEDIUM", "HIGH".
    """

    def _run():
        if stopped(stop_evt):
            done_callback([])
            return
        if not _HAS_CRYPTO:
            line_callback(
                "[SSLCert] ✘ 'cryptography' library not installed "
                "(pip install cryptography)."
            )
            done_callback([])
            return

        host, port_str = split_host_port(target)
        port = int(port_str) if port_str else DEFAULT_PORT
        if not host:
            line_callback(f"[SSLCert] ✘ Could not parse target: {target!r}")
            done_callback([])
            return

        line_callback(f"[SSLCert] ▶  Probing TLS handshake on {host}:{port} …")

        # ── 1. Reachability check (TCP) ───────────────────────────────────
        try:
            with socket.create_connection((host, port)):
                pass
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
            line_callback(f"[SSLCert] ✘ Port {port} unreachable: {exc}")
            log.warning(f"[SSLCert] TCP reach fail: {exc}")
            done_callback([])
            return

        # ── 2. TLS handshake ─────────────────────────────────────────────
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE     # we want the cert even if invalid

        proto: str | None = None
        cipher_tuple: tuple | None = None
        der_cert: bytes | None = None
        try:
            with socket.create_connection((host, port)) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    proto        = tls_sock.version()
                    cipher_tuple = tls_sock.cipher()
                    der_cert     = tls_sock.getpeercert(binary_form=True)
        except ssl.SSLError as exc:
            line_callback(f"[SSLCert] ✘ TLS handshake failed: {exc}")
            log.warning(f"[SSLCert] TLS fail on {host}:{port}: {exc}")
            done_callback([])
            return
        except Exception as exc:
            line_callback(f"[SSLCert] ✘ Connection error: {exc}")
            log.warning(f"[SSLCert] connect fail on {host}:{port}: {exc}")
            done_callback([])
            return

        if not der_cert:
            line_callback("[SSLCert] ✘ Server presented no certificate.")
            done_callback([])
            return

        # ── 3. Parse the leaf certificate ─────────────────────────────────
        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
        except Exception as exc:
            line_callback(f"[SSLCert] ✘ Could not parse certificate: {exc}")
            done_callback([])
            return

        subject = _dn_to_dict(cert.subject)
        issuer  = _dn_to_dict(cert.issuer)
        sans    = _extract_sans(cert)

        # Validity (timezone-aware fields exist on cryptography>=42)
        if hasattr(cert, "not_valid_before_utc"):
            nvb = cert.not_valid_before_utc
            nva = cert.not_valid_after_utc
        else:
            nvb = cert.not_valid_before.replace(tzinfo=timezone.utc)
            nva = cert.not_valid_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_remaining = (nva - now).days
        expired        = now > nva
        not_yet_valid  = now < nvb
        self_signed    = subject == issuer

        try:
            sig_alg = cert.signature_hash_algorithm.name.upper()
        except Exception:
            sig_alg = "unknown"

        # ── 4. Build structured rows for the UI table ─────────────────────
        def _risk_for_protocol(p: str | None) -> str:
            if not p:                       return ""
            if p in WEAK_PROTOCOLS:         return "HIGH"
            if p == "TLSv1.2":              return "MEDIUM"
            return "OK"

        rows: list[dict] = []
        def add(category: str, field: str, value, risk: str = ""):
            rows.append({
                "category": category,
                "field":    field,
                "value":    "" if value is None else str(value),
                "risk":     risk,
            })

        # Connection
        add("Connection", "Host",     f"{host}:{port}")
        add("Connection", "Protocol", proto, risk=_risk_for_protocol(proto))
        if cipher_tuple:
            cipher_name, cipher_proto, cipher_bits = cipher_tuple
            add("Connection", "Cipher",      cipher_name)
            add("Connection", "Cipher Bits", cipher_bits,
                risk="HIGH" if cipher_bits < 128 else "OK")

        # Subject
        for k, v in subject.items():
            add("Subject", k, v)

        # Issuer
        for k, v in issuer.items():
            add("Issuer", k, v)

        # Validity
        add("Validity", "Not Before", nvb.strftime("%Y-%m-%d %H:%M:%S UTC"))
        add("Validity", "Not After",  nva.strftime("%Y-%m-%d %H:%M:%S UTC"))
        if expired:
            add("Validity", "Status", f"EXPIRED ({-days_remaining} days ago)",
                risk="HIGH")
        elif not_yet_valid:
            add("Validity", "Status", "NOT YET VALID", risk="HIGH")
        elif days_remaining <= EXPIRY_WARN_DAYS:
            add("Validity", "Status",
                f"expires in {days_remaining} days", risk="MEDIUM")
        else:
            add("Validity", "Days Remaining", days_remaining, risk="OK")

        # Certificate metadata
        add("Certificate", "Version",        cert.version.name)
        add("Certificate", "Serial",         f"{cert.serial_number:x}")
        add("Certificate", "Signature Algo", sig_alg,
            risk="HIGH" if sig_alg in {"MD5", "SHA1"} else "OK")
        add("Certificate", "Self-Signed",    "yes" if self_signed else "no",
            risk="MEDIUM" if self_signed else "OK")

        # SAN
        if sans["dns"]:
            add("SAN", "DNS", ", ".join(sans["dns"]))
        if sans["ips"]:
            add("SAN", "IP",  ", ".join(sans["ips"]))
        if not sans["dns"] and not sans["ips"]:
            add("SAN", "(none)", "—", risk="MEDIUM")

        # ── 5. Persist raw JSON to disk for the reporter / users ──────────
        try:
            out_path = Path(output_dir) / "ssl_cert.json"
            out_path.write_text(
                json.dumps({
                    "target":   f"{host}:{port}",
                    "protocol": proto,
                    "cipher":   list(cipher_tuple) if cipher_tuple else None,
                    "subject":  subject,
                    "issuer":   issuer,
                    "not_before": nvb.isoformat(),
                    "not_after":  nva.isoformat(),
                    "days_remaining": days_remaining,
                    "expired":     expired,
                    "self_signed": self_signed,
                    "signature_algorithm": sig_alg,
                    "san":     sans,
                    "version": cert.version.name,
                    "serial":  f"{cert.serial_number:x}",
                    "rows":    rows,
                }, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            log.debug(f"[SSLCert] could not write ssl_cert.json: {exc}")

        # ── 6. Summary line + done ────────────────────────────────────────
        summary_bits = [f"{proto or '?'}"]
        if cipher_tuple:
            summary_bits.append(cipher_tuple[0])
        cn = subject.get("commonName", "—")
        summary_bits.append(f"CN={cn}")
        if expired:
            summary_bits.append("⚠ EXPIRED")
        elif days_remaining <= EXPIRY_WARN_DAYS:
            summary_bits.append(f"⚠ {days_remaining}d left")
        line_callback("[SSLCert] ✔  " + "  |  ".join(summary_bits))
        log.info(f"[SSLCert] {len(rows)} fields extracted from {host}:{port}")
        done_callback(rows)

    threading.Thread(target=_run, daemon=True).start()
