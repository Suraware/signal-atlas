"""Fixed public endpoints and their source-specific normalization contracts."""

import csv
import io
import re
from dataclasses import dataclass

from .models import CVE_IN_TEXT, normalize_record, number, severity_from_score, unique


class SourceError(Exception):
    """An external service returned an invalid or unavailable response."""


@dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    description: str
    mode: str
    ttl: int
    interval: float
    limit: str


SOURCES = {
    "cisa": Source("cisa", "CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "Confirmed exploitation catalog, remediation actions, and ransomware context.", "feed", 3600, 60, "Full KEV catalog; cached for 1 hour."),
    "github": Source("github", "GitHub Advisories", "https://api.github.com/advisories", "Reviewed advisories with CVE aliases and affected package information.", "feed", 3600, 60, "Latest 60 reviewed advisories; unauthenticated GitHub limit is 60 requests/hour/IP."),
    "nvd": Source("nvd", "NIST NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0", "CVSS scores, weaknesses, affected products, and reference links.", "feed + lookup", 3600, 6.5, "50 recently modified CVEs; no-key NVD budget is 5 requests/30 seconds."),
    "exploitdb": Source("exploitdb", "Exploit-DB metadata", "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", "Public proof-of-concept metadata only. Does not download or run exploits.", "feed", 86400, 300, "CSV capped at 16 MiB; indexes the 200 most recent CVE groups, not the whole exploit corpus."),
    "epss": Source("epss", "FIRST EPSS", "https://api.first.org/data/v1/epss", "Daily probability of observed exploitation in the next 30 days, not severity.", "batch + lookup", 86400, 3, "Up to 100 locally cached CVEs per refresh; preserves each score's date."),
    "cve": Source("cve", "CVE.org", "https://cveawg.mitre.org/api/cve", "Primary CVE Program records, CNA descriptions, and source references.", "lookup", 3600, 0.5, "One locally selected CVE per refresh; targeted record enrichment on demand."),
    "circl": Source("circl", "CIRCL Vulnerability-Lookup", "https://vulnerability.circl.lu/api/cve", "A public mirror/correlation source for vulnerability records.", "lookup", 3600, 3, "One locally selected CVE per refresh; respects reported rate limits."),
    "osv": Source("osv", "OSV.dev", "https://api.osv.dev/v1", "Open-source advisories and exact-version dependency queries.", "lookup + audit", 3600, 0.2, "One advisory per refresh; audits query at most 100 exact package versions."),
}


def _list(payload, key):
    if not isinstance(payload, dict) or not isinstance(payload.get(key), list):
        raise SourceError(f"Expected a public {key} list; the source schema or access rules may have changed.")
    return payload[key]


def _reference(url, label, kind="advisory"):
    return {"url": url, "label": label, "type": kind}


def _cisa(payload):
    records = []
    for item in _list(payload, "vulnerabilities")[:5000]:
        record = {
            "id": item["cveID"], "title": item.get("vulnerabilityName"), "description": item.get("shortDescription"),
            "kev": True, "kev_date": item.get("dateAdded"), "published": item.get("dateAdded"),
            "due_date": item.get("dueDate"), "required_action": item.get("requiredAction"),
            "ransomware": item.get("knownRansomwareCampaignUse", "Unknown"),
            "vendors": [item.get("vendorProject")], "products": [item.get("product")], "cwes": item.get("cwes", []),
            "references": [_reference("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "CISA known exploited catalog", "known-exploitation")],
        }
        for url in re.findall(r"https?://[^\s;<>]+", item.get("notes", "")):
            record["references"].append(_reference(url.rstrip(".,)"), "CISA linked reference"))
        records.append((normalize_record(record), item))
    return records


def _epss(payload):
    records = []
    for item in _list(payload, "data")[:1000]:
        probability = number(item.get("epss"), 1)
        if probability is None:
            raise SourceError("EPSS returned a non-finite or out-of-range probability.")
        records.append((normalize_record({
            "id": item["cve"], "epss": probability, "epss_percentile": item.get("percentile"), "epss_date": item.get("date"),
            "references": [_reference("https://www.first.org/epss/", "FIRST EPSS probability model", "risk-model")],
        }), item))
    return records


def _cve(payload):
    if not isinstance(payload, dict) or not payload.get("cveMetadata", {}).get("cveId"):
        raise SourceError("Expected a CVE Program record.")
    metadata = payload["cveMetadata"]
    if metadata.get("state") == "REJECTED":
        return []
    containers = payload.get("containers", {})
    cna = containers.get("cna", {})
    all_containers = [cna, *containers.get("adp", [])]
    scores, cwes, references = [], [], []
    for container in all_containers:
        for metric in container.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                value = number(metric.get(key, {}).get("baseScore"))
                if value is not None:
                    scores.append(value)
        for problem in container.get("problemTypes", []):
            for description in problem.get("descriptions", []):
                cwes.extend(re.findall(r"CWE-\d+", description.get("cweId", "") or description.get("description", "")))
        references.extend(_reference(ref.get("url", ""), "CVE record reference", ", ".join(ref.get("tags", [])) or "advisory") for ref in container.get("references", []))
    score = max(scores) if scores else None
    description = "\n\n".join(item.get("value", "") for item in cna.get("descriptions", []) if item.get("lang", "en").startswith("en"))
    affected = cna.get("affected", [])
    identifier = metadata["cveId"]
    references.insert(0, _reference("https://www.cve.org/CVERecord?id=" + identifier, "CVE.org primary record"))
    record = {
        "id": identifier, "title": cna.get("title") or description or identifier, "description": description,
        "cvss": score, "severity": severity_from_score(score), "cwes": unique(cwes),
        "vendors": [item.get("vendor") for item in affected if item.get("vendor") not in ("n/a", "N/A")],
        "products": [item.get("product") for item in affected if item.get("product") not in ("n/a", "N/A")],
        "published": metadata.get("datePublished"), "modified": metadata.get("dateUpdated"), "references": references,
    }
    return [(normalize_record(record), payload)]


def _nvd(payload):
    records = []
    for wrapper in _list(payload, "vulnerabilities")[:2000]:
        item = wrapper["cve"]
        if item.get("vulnStatus") == "Rejected":
            continue
        scores = []
        for metrics in item.get("metrics", {}).values():
            for metric in metrics:
                score = number(metric.get("cvssData", {}).get("baseScore"))
                if score is not None:
                    scores.append(score)
        score = max(scores) if scores else None
        description = "\n".join(d.get("value", "") for d in item.get("descriptions", []) if d.get("lang") == "en")
        cwes = [d.get("value") for weak in item.get("weaknesses", []) for d in weak.get("description", [])]
        vendors, products = [], []
        for config in item.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if cpe.get("vulnerable") and len(parts) >= 5:
                        vendors.append(parts[3])
                        products.append(parts[4])
        refs = [_reference("https://nvd.nist.gov/vuln/detail/" + item["id"], "NVD vulnerability detail")]
        refs.extend(_reference(ref.get("url", ""), "NVD linked reference", ", ".join(ref.get("tags", [])) or "reference") for ref in item.get("references", []))
        records.append((normalize_record({
            "id": item["id"], "title": description or item["id"], "description": description,
            "cvss": score, "severity": severity_from_score(score), "cwes": cwes, "vendors": vendors, "products": products,
            "published": item.get("published"), "modified": item.get("lastModified"), "references": refs,
        }), item))
    return records


def _github(payload):
    items = [payload] if isinstance(payload, dict) and payload.get("ghsa_id") else payload
    if not isinstance(items, list):
        raise SourceError("Expected a GitHub public advisory list.")
    records = []
    for item in items[:100]:
        if item.get("withdrawn_at"):
            continue
        aliases = [item["ghsa_id"], *[d.get("value", "") for d in item.get("identifiers", [])]]
        if item.get("cve_id"):
            aliases.append(item["cve_id"])
        refs = [_reference(item.get("html_url", ""), "GitHub Security Advisory")]
        refs.extend(_reference(url, "GitHub linked reference") for url in item.get("references", []))
        packages = [v.get("package", {}) for v in item.get("vulnerabilities", [])]
        records.append((normalize_record({
            "id": item.get("cve_id") or item["ghsa_id"], "aliases": aliases,
            "title": item.get("summary"), "description": item.get("description"), "severity": item.get("severity"),
            "cvss": (item.get("cvss") or {}).get("score"), "cwes": [c.get("cwe_id") for c in item.get("cwes", [])],
            "packages": [p.get("ecosystem", "unknown") + ":" + p.get("name", "") for p in packages if p.get("name")],
            "published": item.get("published_at"), "modified": item.get("updated_at"), "references": refs,
        }), item))
    return records


def _osv(payload):
    if not isinstance(payload, dict) or not payload.get("id"):
        raise SourceError("Expected a public OSV advisory record.")
    if payload.get("withdrawn"):
        return []
    packages = [item.get("package", {}) for item in payload.get("affected", [])]
    specific = payload.get("database_specific", {})
    refs = [_reference("https://osv.dev/vulnerability/" + payload["id"], "OSV advisory")]
    refs.extend(_reference(item.get("url", ""), "OSV linked reference", item.get("type", "reference").lower()) for item in payload.get("references", []))
    record = {
        "id": payload["id"], "aliases": payload.get("aliases", []), "title": payload.get("summary"), "description": payload.get("details"),
        "severity": specific.get("severity", "UNKNOWN"), "cwes": specific.get("cwe_ids", []),
        "packages": [p.get("ecosystem", "unknown") + ":" + p.get("name", "") for p in packages if p.get("name")],
        "published": payload.get("published"), "modified": payload.get("modified"), "references": refs,
    }
    return [(normalize_record(record), payload)]


def _exploitdb(payload):
    if not isinstance(payload, str):
        raise SourceError("Expected the public Exploit-DB metadata CSV.")
    reader = csv.DictReader(io.StringIO(payload))
    if not reader.fieldnames or not {"id", "description", "codes"}.issubset(reader.fieldnames):
        raise SourceError("Exploit-DB CSV lacks CVE correlation fields.")
    groups = {}
    for index, row in enumerate(reader):
        if index > 100000:
            raise SourceError("Exploit-DB metadata exceeds the 100,000-row safety cap.")
        if not row.get("id", "").isdigit():
            continue
        for identifier in unique(match.upper() for match in CVE_IN_TEXT.findall(row.get("codes", ""))):
            groups.setdefault(identifier, []).append(row)
    chosen = sorted(groups, key=lambda identifier: max(row.get("date_published", "") for row in groups[identifier]), reverse=True)[:200]
    records = []
    for identifier in chosen:
        rows = groups[identifier]
        latest = max(rows, key=lambda row: row.get("date_published", ""))
        references = [_reference("https://www.exploit-db.com/exploits/" + row["id"], "Public PoC metadata #" + row["id"], "public-poc") for row in rows[:20]]
        records.append((normalize_record({"id": identifier, "title": latest["description"], "exploit_count": len(rows), "references": references, "published": latest.get("date_published")}), {"metadata": rows[:20], "total_entries": len(rows)}))
    return records


def parse_source(source_id, payload):
    parsers = {"cisa": _cisa, "epss": _epss, "cve": _cve, "circl": _cve, "nvd": _nvd, "github": _github, "osv": _osv, "exploitdb": _exploitdb}
    if source_id not in parsers:
        raise ValueError("Unknown public source.")
    try:
        return parsers[source_id](payload)
    except (KeyError, TypeError, AttributeError, ValueError, csv.Error) as exc:
        raise SourceError(f"Invalid {source_id} response: {str(exc)[:160]}") from exc
