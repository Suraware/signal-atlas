"""Small normalization helpers shared by storage and public-feed adapters."""

import math
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

IDENTIFIER = re.compile(r"^(?:CVE-\d{4}-\d{4,12}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|[A-Z][A-Z0-9._-]{1,30}-[0-9][A-Z0-9._-]{1,70})$", re.IGNORECASE)
CVE_IN_TEXT = re.compile(r"\bCVE-\d{4}-\d{4,12}\b", re.IGNORECASE)
SEVERITIES = {"UNKNOWN": 0, "LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def utcnow() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_id(identifier: str) -> str:
    value = str(identifier).strip()
    if not IDENTIFIER.fullmatch(value):
        raise ValueError("Use a CVE, GHSA, or OSV identifier (up to 100 characters).")
    return "GHSA-" + value[5:].lower() if value.upper().startswith("GHSA-") else value.upper()


def safe_url(value: str) -> str | None:
    try:
        parts = urlsplit(str(value))
        if parts.scheme.lower() not in {"https", "http"} or not parts.hostname or parts.username or parts.password:
            return None
        if len(value) > 2048 or any(ord(c) < 32 for c in value):
            return None
        return value
    except (ValueError, TypeError):
        return None


def number(value, maximum=10.0):
    try:
        result = float(value)
        return result if math.isfinite(result) and 0 <= result <= maximum else None
    except (TypeError, ValueError):
        return None


def severity_from_score(score) -> str:
    value = number(score)
    if value is None:
        return "UNKNOWN"
    return "CRITICAL" if value >= 9 else "HIGH" if value >= 7 else "MEDIUM" if value >= 4 else "LOW"


def unique(values):
    return list(dict.fromkeys(values))


def normalize_record(record: dict) -> dict:
    identifier = normalize_id(record["id"])
    aliases = [identifier]
    for alias in record.get("aliases", []):
        try:
            aliases.append(normalize_id(alias))
        except ValueError:
            continue
    aliases = unique(aliases)
    canonical = next((alias for alias in aliases if alias.startswith("CVE-")), identifier)
    score = number(record.get("cvss"))
    severity = str(record.get("severity", "UNKNOWN")).upper()
    severity = "MEDIUM" if severity == "MODERATE" else severity
    if severity not in SEVERITIES:
        severity = severity_from_score(score)
    if severity == "UNKNOWN" and score is not None:
        severity = severity_from_score(score)
    references = []
    for ref in record.get("references", []):
        ref = {"url": ref, "label": "Reference"} if isinstance(ref, str) else ref
        if not isinstance(ref, dict) or not safe_url(ref.get("url", "")):
            continue
        references.append({"url": ref["url"], "label": str(ref.get("label", "Reference"))[:180], "type": str(ref.get("type", "reference"))[:80]})
    references = list({ref["url"]: ref for ref in references}.values())
    result = {
        "id": canonical,
        "aliases": aliases,
        "title": str(record.get("title") or identifier)[:500],
        "description": str(record.get("description") or "")[:50000],
        "severity": severity,
        "cvss": score,
        "epss": number(record.get("epss"), 1),
        "epss_percentile": number(record.get("epss_percentile"), 1),
        "epss_date": record.get("epss_date"),
        "kev": bool(record.get("kev", False)),
        "kev_date": record.get("kev_date"),
        "due_date": record.get("due_date"),
        "ransomware": str(record.get("ransomware") or "Unknown")[:80],
        "required_action": str(record.get("required_action") or "")[:10000],
        "exploit_count": max(0, int(number(record.get("exploit_count"), 100000) or 0)),
        "vendors": unique(str(v)[:200] for v in record.get("vendors", []) if v)[:100],
        "products": unique(str(v)[:200] for v in record.get("products", []) if v)[:100],
        "cwes": unique(str(v)[:80] for v in record.get("cwes", []) if re.fullmatch(r"CWE-\d+", str(v)))[:100],
        "packages": unique(str(v)[:300] for v in record.get("packages", []) if v)[:100],
        "published": str(record.get("published") or "")[:40] or None,
        "modified": str(record.get("modified") or "")[:40] or None,
        "references": references[:200],
    }
    return result


def merge_records(left: dict, right: dict) -> dict:
    if not left:
        return dict(right)
    result = dict(left)
    for field in ("aliases", "vendors", "products", "cwes", "packages"):
        result[field] = unique(left.get(field, []) + right.get(field, []))
    result["references"] = list({ref["url"]: ref for ref in left.get("references", []) + right.get("references", [])}.values())[:200]
    if left.get("title") == left.get("id") or (right.get("title") != right.get("id") and len(right.get("title", "")) > len(left.get("title", ""))):
        result["title"] = right["title"]
    if len(right.get("description", "")) > len(left.get("description", "")):
        result["description"] = right["description"]
    if SEVERITIES[right.get("severity", "UNKNOWN")] > SEVERITIES[left.get("severity", "UNKNOWN")]:
        result["severity"] = right["severity"]
    scores = [v for v in (left.get("cvss"), right.get("cvss")) if v is not None]
    result["cvss"] = max(scores) if scores else None
    if right.get("epss") is not None:
        for field in ("epss", "epss_percentile", "epss_date"):
            result[field] = right.get(field)
    result["kev"] = left.get("kev", False) or right.get("kev", False)
    result["exploit_count"] = max(left.get("exploit_count", 0), right.get("exploit_count", 0))
    for field in ("kev_date", "due_date", "required_action"):
        if right.get(field):
            result[field] = right[field]
    if right.get("ransomware") not in (None, "Unknown"):
        result["ransomware"] = right["ransomware"]
    published = [v for v in (left.get("published"), right.get("published")) if v]
    modified = [v for v in (left.get("modified"), right.get("modified")) if v]
    result["published"] = min(published) if published else None
    result["modified"] = max(modified) if modified else None
    return result
