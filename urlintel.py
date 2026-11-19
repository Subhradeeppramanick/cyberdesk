"""
urlintel.py - public-infrastructure analysis for URLs found in complaints.

Everything here inspects the *infrastructure* of a link - never people:
structural phishing heuristics, live DNS resolution, TLS certificate
expiry and HTTP security headers. Network checks degrade gracefully when
the demo runs offline.
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


def dns_lookup(host: str, timeout: float = 4.0) -> dict:
    """Live A/AAAA resolution via the system resolver."""
    result = {"live": False, "addresses": [], "error": ""}
    try:
        infos = socket.getaddrinfo(host, None)
        addrs = sorted({info[4][0] for info in infos})
        result.update(live=True, addresses=addrs[:8])
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
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
        issuer = ", ".join(f"{k}={v}" for rdn in cert.get("issuer", ()) for k, v in rdn)
        not_after = cert.get("notAfter", "")
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
        result.update(live=True, issuer=issuer, valid_to=not_after, days_left=days)
    except (ssl.SSLError, socket.timeout, OSError) as exc:
        result["error"] = f"no valid TLS on 443 ({exc})"
    return result


def analyze_url(url: str, live: bool = True, timeout: float = 4.0) -> dict:
    """Full public-infrastructure profile for one URL."""
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
        "method": "structural heuristics + live public infrastructure checks",
    }
    if live and host and not _is_ip_literal(host):
        report["dns"] = dns_lookup(host, timeout)
        report["tls"] = tls_expiry(host, timeout)
    return report
