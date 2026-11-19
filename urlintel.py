"""
urlintel.py - public-infrastructure analysis for URLs found in complaints.

Everything here inspects a link - never people. By default it only applies
structural phishing heuristics to the text of the URL and makes no network
requests. Optional live DNS/TLS checks are off unless explicitly enabled, and
refuse any host that resolves to a non-public address.
"""

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "club", "online", "site", "live", "buzz",
    "icu", "cam", "click", "link", "work", "loan", "win", "tk", "ml", "ga",
    "cf", "gq", "rest", "quest", "monster", "download", "racing", "date",
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "account",
    "update", "confirm", "password", "kyc", "otp", "sbi", "hdfc", "icici",
    "refund", "claim", "bonus", "free", "winner", "support",
}

# Brand -> official registrable domains. Mentioning the brand while resolving
# to anything else is the strongest single phishing signal we check.
IMPERSONATED_BRANDS = {
    "sbi": {"onlinesbi.sbi", "sbi.co.in", "onlinesbi.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "gpay": {"pay.google.com"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "npci": {"npci.org.in"},
    "uidai": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in"},
}


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registrable(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) <= 2:
        return host.lower()
    if parts[-2] in {"co", "com", "org", "net", "ac", "gov", "edu"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def heuristic_signals(url: str) -> list:
    """Structural red flags. Returns a list of (signal, points, detail)."""
    signals = []
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    if not host:
        return [("unparseable", 30, "could not extract a host from this URL")]
    full = url.lower()

    if _is_ip_literal(host):
        signals.append(("ip-literal-host", 30, "host is a raw IP address"))
    if "xn--" in host:
        signals.append(("punycode", 30, "punycode can mimic another domain"))
    if "@" in parsed.netloc:
        signals.append(("at-symbol", 35, "'@' hides the real destination"))
    if len(host.split(".")) - len(_registrable(host).split(".")) > 3:
        signals.append(("deep-subdomains", 15, "subdomain chain buries the real domain"))

    tokens = set(re.split(r"[^a-z]+", full))
    hits = sorted(tokens & SUSPICIOUS_KEYWORDS)
    if hits:
        signals.append(("suspicious-keywords", min(5 * len(hits), 15),
                        "contains: " + ", ".join(hits[:6])))

    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        signals.append(("risky-tld", 10, f"'.{tld}' is a frequently abused TLD"))
    if parsed.scheme == "http" and hits:
        signals.append(("http-credentials", 15, "plain HTTP on a login-flavoured page"))
    if len(url) > 75:
        signals.append(("long-url", 5, f"{len(url)} characters long"))
    if _registrable(host).count("-") >= 2:
        signals.append(("hyphenated-domain", 10, "multiple hyphens in the domain"))

    registrable = _registrable(host)
    for brand in sorted(IMPERSONATED_BRANDS):
        if brand in full and registrable not in IMPERSONATED_BRANDS[brand]:
            signals.append(("brand-impersonation", 40,
                            f"mentions '{brand}' but the domain is '{registrable}'"))
            break
    return signals


MAX_URL_LENGTH = 2048


def _public_addresses(host: str) -> list:
    """Resolve host and return its addresses only if EVERY one is a public,
    globally routable IP. Loopback, private, link-local, reserved and
    multicast targets raise ValueError so the server cannot be pointed at
    internal networks."""
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    addrs = sorted({info[4][0] for info in infos})
    if not addrs:
        raise OSError("no addresses")
    for addr in addrs:
        if not ipaddress.ip_address(addr.split("%")[0]).is_global:
            raise ValueError("resolves to a non-public address; check blocked")
    return addrs


def dns_lookup(host: str, timeout: float = 4.0) -> dict:
    """Live A/AAAA resolution. Only used when live checks are explicitly
    enabled; refuses hosts that resolve to non-public addresses."""
    result = {"live": False, "addresses": [], "error": ""}
    try:
        result.update(live=True, addresses=_public_addresses(host)[:8])
    except ValueError as exc:
        result["error"] = str(exc)
    except socket.gaierror:
        result["error"] = "does not resolve (NXDOMAIN or no network)"
    except OSError as exc:
        result["error"] = str(exc)
    return result


def tls_expiry(host: str, timeout: float = 4.0) -> dict:
    """Live TLS certificate check: issuer and days until expiry."""
    result = {"live": False, "error": ""}
    ctx = ssl.create_default_context()
    try:
        # Connect to the already-validated public IP, not the name, so a DNS
        # answer cannot change between the safety check and the connection.
        ip = _public_addresses(host)[0]
        with socket.create_connection((ip, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
        issuer = ", ".join(f"{k}={v}" for rdn in cert.get("issuer", ()) for k, v in rdn)
        not_after = cert.get("notAfter", "")
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        result.update(live=True, issuer=issuer, valid_to=not_after, days_left=days)
    except ValueError as exc:
        result["error"] = str(exc)
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        result["error"] = f"no valid TLS on 443 ({exc})"
    return result


def analyze_url(url: str, live: bool = False, timeout: float = 4.0) -> dict:
    """URL profile. Offline structural heuristics by default; DNS/TLS checks
    run only when live=True (opt-in, local use, public hosts only)."""
    url = (url or "")[:MAX_URL_LENGTH]
    signals = heuristic_signals(url)
    score = sum(points for _, points, _ in signals)
    verdict = "LIKELY PHISHING" if score >= 50 else ("SUSPICIOUS" if score >= 25 else "NO STRONG SIGNALS")

    normalised = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "http://" + url
    host = (urlparse(normalised.strip()).hostname or "").lower()

    report = {
        "url": url,
        "host": host,
        "score": score,
        "verdict": verdict,
        "signals": [{"signal": s, "points": p, "detail": d} for s, p, d in signals],
        "method": ("structural heuristics + live public infrastructure checks"
                   if live else "structural heuristics only (offline, nothing is fetched)"),
    }
    if live and host and not _is_ip_literal(host):
        report["dns"] = dns_lookup(host, timeout)
        report["tls"] = tls_expiry(host, timeout)
    return report
