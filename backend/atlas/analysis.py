"""Bounded read-only file inspection. Nothing in this module executes user input."""

import hashlib
import ipaddress
import json
import math
import re
import struct
from collections import Counter
from pathlib import PurePosixPath
from urllib.parse import unquote

from .models import safe_url, unique

MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 200000
MAX_PACKAGES = 100
MAX_PACKETS = 10000
EXACT_VERSION = re.compile(r"^[0-9][0-9A-Za-z.!+_-]{0,100}$")


def parse_manifest(format, content):
    if not isinstance(content, str) or len(content) > MAX_MANIFEST:
        raise ValueError("The manifest must be text under 200,000 characters.")
    packages, skipped, warnings = [], [], []
    seen = set()

    def add(ecosystem, name, version):
        if not isinstance(name, str) or not name or len(name) > 300:
            raise ValueError("Package names must contain 1–300 characters.")
        if not isinstance(version, str) or not EXACT_VERSION.fullmatch(version):
            skipped.append({"name": name, "reason": "Not an exact version; provide a lockfile or an exact pin."})
            return
        key = (ecosystem, name, version)
        if key in seen:
            return
        if len(packages) >= MAX_PACKAGES:
            raise ValueError("At most 100 unique exact package versions can be audited at once.")
        seen.add(key)
        packages.append({"ecosystem": ecosystem, "name": name, "version": version})

    if format == "requirements":
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ";" in line:
                warnings.append("Environment markers are not evaluated; exact pins are checked regardless of the marker.")
            expression = line.split(";", 1)[0].split("#", 1)[0].strip()
            match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9,._ -]+\])?\s*==\s*([^\s]+)", expression)
            if match:
                add("PyPI", match[1], match[2])
            else:
                skipped.append({"name": expression[:120], "reason": "Only exact name==version pins are supported. Includes, URLs, and commands are never followed."})
    elif format in {"npm", "cyclonedx"}:
        try:
            payload = json.loads(content)
        except (ValueError, RecursionError) as exc:
            raise ValueError("The manifest is not valid JSON. Paste a package file or a CycloneDX JSON document.") from exc
        if not isinstance(payload, dict):
            raise ValueError("The manifest must be a JSON object.")
        if format == "npm":
            if "packages" in payload:
                if not isinstance(payload["packages"], dict):
                    raise ValueError("package-lock.json packages must be an object.")
                for path, item in payload["packages"].items():
                    if not path or "node_modules/" not in path:
                        continue
                    if not isinstance(item, dict):
                        raise ValueError("Each locked package must be a JSON object.")
                    add("npm", path.rsplit("node_modules/", 1)[-1], item.get("version"))
            elif payload.get("lockfileVersion") == 1:
                def visit(items, depth=0):
                    if not isinstance(items, dict) or depth > 30:
                        raise ValueError("The npm dependency tree is invalid or nested too deeply.")
                    for name, item in items.items():
                        if not isinstance(item, dict):
                            raise ValueError("Each locked package must be a JSON object.")
                        add("npm", name, item.get("version"))
                        visit(item.get("dependencies", {}), depth + 1)
                visit(payload.get("dependencies", {}))
            else:
                for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    items = payload.get(section, {})
                    if not isinstance(items, dict):
                        raise ValueError(f"{section} must be a package-to-version object.")
                    for name, version in items.items():
                        add("npm", name, version)
        else:
            if payload.get("bomFormat") != "CycloneDX" or not isinstance(payload.get("components"), list):
                raise ValueError("Provide a CycloneDX JSON BOM containing components.")
            ecosystems = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "cargo": "crates.io", "golang": "Go", "nuget": "NuGet", "gem": "RubyGems"}
            for component in payload["components"][:10000]:
                if not isinstance(component, dict):
                    raise ValueError("Each BOM component must be an object.")
                purl = component.get("purl", "")
                match = re.fullmatch(r"pkg:([^/]+)/([^?#]+)(?:\?[^#]*)?(?:#.*)?", purl) if isinstance(purl, str) else None
                if not match or match[1] not in ecosystems:
                    skipped.append({"name": str(component.get("name", "Unknown component"))[:120], "reason": "Missing or unsupported package URL ecosystem."})
                    continue
                coordinate = unquote(match[2])
                name, separator, purl_version = coordinate.rpartition("@")
                if not separator:
                    name = coordinate
                if match[1] == "maven":
                    name = name.replace("/", ":")
                add(ecosystems[match[1]], name, component.get("version") or purl_version)
    else:
        raise ValueError("Choose requirements, npm, or cyclonedx format.")
    if not packages and not skipped:
        raise ValueError("No dependencies were found. Provide exact package versions.")
    return {"format": format, "packages": packages, "skipped": skipped[:100], "warnings": unique(warnings)}


def _packet(packet, link_type):
    offset, ethertype = 0, None
    if link_type == 1:
        if len(packet) < 14:
            return None
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        offset = 14
        for _ in range(2):
            if ethertype in (0x8100, 0x88A8) and len(packet) >= offset + 4:
                ethertype = struct.unpack_from("!H", packet, offset + 2)[0]
                offset += 4
    elif link_type in {101, 228, 229}:
        ethertype = 0x86DD if packet and packet[0] >> 4 == 6 else 0x0800
    elif link_type == 113 and len(packet) >= 16:
        ethertype, offset = struct.unpack_from("!H", packet, 14)[0], 16
    else:
        return None
    if ethertype == 0x0800 and len(packet) >= offset + 20:
        header_len = (packet[offset] & 15) * 4
        if header_len < 20 or len(packet) < offset + header_len:
            return None
        source = str(ipaddress.IPv4Address(packet[offset + 12:offset + 16]))
        target = str(ipaddress.IPv4Address(packet[offset + 16:offset + 20]))
        protocol = packet[offset + 9]
        fragmented = struct.unpack_from("!H", packet, offset + 6)[0] & 0x1FFF
        offset += header_len
    elif ethertype == 0x86DD and len(packet) >= offset + 40:
        source = str(ipaddress.IPv6Address(packet[offset + 8:offset + 24]))
        target = str(ipaddress.IPv6Address(packet[offset + 24:offset + 40]))
        protocol, fragmented = packet[offset + 6], False
        offset += 40
    else:
        return None
    name = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(protocol, f"IP/{protocol}")
    if protocol in (6, 17) and not fragmented and len(packet) >= offset + 4:
        source_port, target_port = struct.unpack_from("!HH", packet, offset)
        source = f"[{source}]:{source_port}" if ":" in source else f"{source}:{source_port}"
        target = f"[{target}]:{target_port}" if ":" in target else f"{target}:{target_port}"
    return {"source": source, "destination": target, "protocol": name}


def _capture(data, pcapng=False):
    packets, protocols, flows, warnings = 0, Counter(), {}, []
    captured_bytes, truncated, link_type = 0, False, None

    def consume(packet, link):
        nonlocal packets, captured_bytes
        packets += 1
        captured_bytes += len(packet)
        parsed = _packet(packet, link)
        protocols[parsed["protocol"] if parsed else "Other/undecoded"] += 1
        if parsed:
            key = (parsed["source"], parsed["destination"], parsed["protocol"])
            if key in flows:
                flows[key]["packets"] += 1
                flows[key]["bytes"] += len(packet)
            elif len(flows) < 2000:
                flows[key] = {**parsed, "packets": 1, "bytes": len(packet)}

    if pcapng:
        offset, endian, interfaces = 0, "<", []
        blocks = 0
        while offset + 12 <= len(data) and packets < MAX_PACKETS and blocks < 20000:
            blocks += 1
            if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
                bom = data[offset + 8:offset + 12]
                if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                    warnings.append("Invalid PCAPNG byte-order marker.")
                    truncated = True
                    break
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                interfaces = []
            kind, length = struct.unpack_from(endian + "II", data, offset)
            if length < 12 or length % 4 or offset + length > len(data):
                warnings.append("Truncated or invalid PCAPNG block length.")
                truncated = True
                break
            if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
                warnings.append("PCAPNG block trailer does not match its length.")
                truncated = True
                break
            body = data[offset + 8:offset + length - 4]
            if kind == 1 and len(body) >= 8:
                if len(interfaces) >= 256:
                    warnings.append("Interface count exceeded the safety cap.")
                    break
                interfaces.append(struct.unpack_from(endian + "H", body)[0])
            elif kind == 6 and len(body) >= 20:
                interface_id, _, _, size, _ = struct.unpack_from(endian + "IIIII", body)
                if interface_id >= len(interfaces) or size > len(body) - 20:
                    warnings.append("Enhanced packet references an invalid interface or truncated payload.")
                    truncated = True
                    break
                link_type = interfaces[interface_id]
                consume(body[20:20 + size], link_type)
            elif kind == 3 and len(body) >= 4 and interfaces:
                size = min(struct.unpack_from(endian + "I", body)[0], len(body) - 4)
                link_type = interfaces[0]
                consume(body[4:4 + size], link_type)
            offset += length
        if offset != len(data) and packets < MAX_PACKETS and not truncated:
            warnings.append("Unparsed trailing capture bytes or block-limit reached.")
    else:
        magic = data[:4]
        endian = "<" if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
        if len(data) < 24:
            return {"format": "PCAP", "packet_count": 0, "captured_bytes": 0, "protocols": [], "conversations": [], "truncated": True, "warnings": ["The global PCAP header is truncated."]}
        major, minor, _, _, snaplen, link_type = struct.unpack_from(endian + "HHIIII", data, 4)
        if (major, minor) != (2, 4):
            warnings.append("This PCAP version is not 2.4; decoding is best-effort.")
        offset = 24
        while offset + 16 <= len(data) and packets < MAX_PACKETS:
            _, _, size, original = struct.unpack_from(endian + "IIII", data, offset)
            offset += 16
            if size > len(data) - offset or size > MAX_FILE:
                warnings.append("A packet's declared length exceeds available bytes.")
                truncated = True
                break
            if size > snaplen or size > original:
                warnings.append("Captured packet length exceeds snaplen or original packet length.")
            consume(data[offset:offset + size], link_type)
            offset += size
        if offset != len(data) and packets < MAX_PACKETS and not truncated:
            warnings.append("The final packet header is truncated.")
            truncated = True
    if packets == MAX_PACKETS:
        warnings.append("Only the first 10,000 packets were decoded.")
    if protocols.get("Other/undecoded"):
        warnings.append("Some frames use unsupported link types, IPv6 extension headers, or non-IP protocols.")
    return {
        "format": "PCAPNG" if pcapng else "PCAP", "packet_count": packets, "captured_bytes": captured_bytes,
        "link_type": link_type, "protocols": [{"name": name, "count": count} for name, count in protocols.most_common()],
        "conversations": sorted(flows.values(), key=lambda flow: flow["packets"], reverse=True)[:100],
        "truncated": truncated, "warnings": unique(warnings),
    }


def analyze_file(filename, data):
    if not data:
        raise ValueError("Choose a non-empty file.")
    if len(data) > MAX_FILE:
        raise ValueError("Files must be at most 8 MiB.")
    filename = PurePosixPath(str(filename).replace("\\", "/")).name[:200] or "artifact"
    magic = data[:4]
    classic_pcap = magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
    pcapng = magic == b"\x0a\x0d\x0d\x0a"
    file_type = "Unrecognized / data"
    if data.startswith(b"MZ"):
        file_type = "PE/DOS executable header"
    elif data.startswith(b"\x7fELF"):
        file_type = "ELF executable/object"
    elif magic in {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"}:
        file_type = "Mach-O / universal object header"
    elif data.startswith(b"PK\x03\x04"):
        file_type = "ZIP container (not decompressed)"
    elif data.startswith(b"%PDF"):
        file_type = "PDF document (not rendered)"
    elif classic_pcap or pcapng:
        file_type = "PCAPNG network capture" if pcapng else "PCAP network capture"
    elif all(byte in {9, 10, 13} or 32 <= byte < 127 for byte in data[:4096]):
        file_type = "Text / source code"
    counts = Counter(data)
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values())
    sample = data[:1024 * 1024]
    strings = [match.group()[:240].decode("ascii") for match in re.finditer(rb"[\x20-\x7e]{6,}", sample)][:200]
    text = sample.decode("utf-8", errors="replace")
    urls = unique(url.rstrip(".,;)\"'") for url in re.findall(r"https?://[^\s<>\"'\x00-\x20]+", text))
    urls = [url for url in urls if safe_url(url)][:100]
    ips = []
    for value in unique(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))[:1000]:
        try:
            ips.append(str(ipaddress.IPv4Address(value)))
        except ipaddress.AddressValueError:
            continue
    rules = [
        (r"powershell|/bin/(?:ba)?sh|cmd\.exe", "Shell / command interpreter reference", "May be legitimate; inspect the calling context."),
        (r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory", "Process manipulation API reference", "Static API strings are not proof that the function is executed."),
        (r"pickle\.loads|yaml\.load\s*\(", "Unsafe deserialization candidate", "Check whether untrusted input reaches this call and whether a safe loader is used."),
        (r"\beval\s*\(|\bexec\s*\(|shell\s*=\s*True", "Dynamic execution candidate", "Check data flow and input validation before treating this as a vulnerability."),
        (r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false", "TLS verification disabled candidate", "Review whether certificate verification is disabled for external requests."),
    ]
    signals = []
    for pattern, label, reason in rules:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            signals.append({"label": label, "reason": reason, "line": text[:match.start()].count("\n") + 1, "match": match.group()[:100]})
    warnings = ["Static indicators are leads, not a verdict. No code was executed and no file was sent to an external service."]
    if len(data) > len(sample):
        warnings.append("Strings and heuristic rules inspect only the first 1 MiB; hashes and entropy cover the full file.")
    if entropy > 7.5:
        warnings.append("High entropy may indicate encryption, compression, or packing; it does not prove malicious behavior.")
    result = {
        "filename": filename, "size": len(data), "file_type": file_type, "entropy": round(entropy, 3),
        "sha256": hashlib.sha256(data).hexdigest(), "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(), "strings": strings, "sampled_bytes": len(sample),
        "indicators": {"urls": urls, "ipv4": unique(ips)[:100]}, "signals": signals, "warnings": warnings, "execution": "never",
    }
    if classic_pcap or pcapng:
        result["capture"] = _capture(data, pcapng)
    return result
