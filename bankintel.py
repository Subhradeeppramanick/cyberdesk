"""
bankintel.py - IFSC validation and bank-branch lookup.

IFSC codes identify bank *branches*, not people, so this module is safe to
run live. It validates the code format, then tries the public IFSC API at
ifsc.razorpay.com (built on RBI-published data) and falls back to a small
bundled offline sample when there is no network. Every response is labelled
with its source so nobody mistakes a demo fallback for a live lookup.
"""

import json
import re
import urllib.request

IFSC_PATTERN = re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$")
LIVE_API = "https://ifsc.razorpay.com/{code}"

# Small offline sample, verified against the public IFSC API on 2026-11-19.
# Used only when the network is unavailable, and always labelled as a sample.
OFFLINE_SAMPLE = {
    "SBIN0000001": {
        "BANK": "State Bank of India", "BRANCH": "KOLKATA MAIN",
        "CITY": "KOLKATA", "STATE": "WEST BENGAL",
        "ADDRESS": "SAMRIDDHI BHAWAN, 1 STRAND ROAD, KOLKATA 700 001",
        "UPI": True, "NEFT": True, "RTGS": True, "IMPS": True,
    },
    "HDFC0000123": {
        "BANK": "HDFC Bank", "BRANCH": "MADURAI - TAMIL NADU",
        "CITY": "MADURAI", "STATE": "TAMIL NADU",
        "ADDRESS": "NO. 7-A WEST VELI STREET, MADURAI, TAMIL NADU 625 001",
        "UPI": True, "NEFT": True, "RTGS": True, "IMPS": True,
    },
    "ICIC0000001": {
        "BANK": "ICICI Bank", "BRANCH": "CHENNAI CENOTAPH ROAD",
        "CITY": "CHENNAI", "STATE": "TAMIL NADU",
        "ADDRESS": "ICICI BANK LTD., NO. 1, CENOTAPH ROAD, CHENNAI 600 018",
        "UPI": True, "NEFT": True, "RTGS": True, "IMPS": True,
    },
}


def validate_ifsc(code: str) -> bool:
    return bool(IFSC_PATTERN.match((code or "").strip().upper()))


def lookup_ifsc(code: str, timeout: float = 5.0, live: bool = True) -> dict:
    code = (code or "").strip().upper()
    if not validate_ifsc(code):
        return {
            "ifsc": code, "valid_format": False, "found": False,
            "error": "Invalid format. An IFSC is 4 letters, a 0, then 6 letters/digits.",
            "source": "format check",
        }

    if live:
        try:
            req = urllib.request.Request(
                LIVE_API.format(code=code),
                headers={"User-Agent": "CyberDesk-Demo/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return {
                "ifsc": code, "valid_format": True, "found": True,
                "bank": data.get("BANK"), "branch": data.get("BRANCH"),
                "city": data.get("CITY"), "state": data.get("STATE"),
                "address": data.get("ADDRESS"),
                "upi": data.get("UPI"), "neft": data.get("NEFT"),
                "rtgs": data.get("RTGS"), "imps": data.get("IMPS"),
                "source": "live: ifsc.razorpay.com (RBI-published data)",
            }
        except Exception:
            pass  # fall through to the offline sample

    sample = OFFLINE_SAMPLE.get(code)
    if sample:
        return {
            "ifsc": code, "valid_format": True, "found": True,
            "bank": sample["BANK"], "branch": sample["BRANCH"],
            "city": sample["CITY"], "state": sample["STATE"],
            "address": sample["ADDRESS"],
            "upi": sample["UPI"], "neft": sample["NEFT"],
            "rtgs": sample["RTGS"], "imps": sample["IMPS"],
            "source": "offline sample (network unavailable)",
        }

    return {
        "ifsc": code, "valid_format": True, "found": False,
        "error": "Not found. The live registry may be unreachable from this demo.",
        "source": "offline sample (network unavailable)",
    }
