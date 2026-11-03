import struct

import pytest
from atlas.analysis import analyze_file, parse_manifest


def test_requirements_only_audits_exact_versions_and_does_not_follow_includes():
    result = parse_manifest("requirements", "requests==2.19.0\nurllib3>=1.2\n-r secrets.txt\nFlask[async]==2.0.0; python_version >= '3.9'\n")
    assert result["packages"] == [
        {"ecosystem": "PyPI", "name": "requests", "version": "2.19.0"},
        {"ecosystem": "PyPI", "name": "Flask", "version": "2.0.0"},
    ]
    assert len(result["skipped"]) == 2
    assert any("marker" in warning.lower() for warning in result["warnings"])


def test_npm_lockfile_reads_nested_scoped_packages_and_deduplicates():
    content = '{"lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/@scope/tool":{"version":"1.2.3"},"node_modules/other/node_modules/lodash":{"version":"4.17.20"}}}'
    result = parse_manifest("npm", content)
    assert result["packages"] == [
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"},
        {"ecosystem": "npm", "name": "@scope/tool", "version": "1.2.3"},
    ]


def test_package_json_ranges_are_skipped_not_guessed():
    result = parse_manifest("npm", '{"dependencies":{"lodash":"4.17.20","react":"^19.0.0","other":"workspace:*"}}')
    assert result["packages"] == [{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}]
    assert {row["name"] for row in result["skipped"]} == {"react", "other"}


def test_cyclonedx_uses_package_urls_not_arbitrary_component_labels():
    result = parse_manifest("cyclonedx", '{"bomFormat":"CycloneDX","components":[{"type":"library","name":"log4j-core","version":"2.14.1","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},{"name":"unknown","version":"1.0"}]}')
    assert result["packages"] == [{"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"}]
    assert len(result["skipped"]) == 1


def test_malformed_and_oversized_manifests_are_bounded():
    with pytest.raises(ValueError):
        parse_manifest("npm", "{bad JSON")
    with pytest.raises(ValueError):
        parse_manifest("requirements", "a==1\n" * 50000)
    with pytest.raises(ValueError):
        parse_manifest("requirements", "\n".join(f"p{i}==1.0" for i in range(101)))


def test_binary_hashes_strings_and_indicators_are_static_and_never_executed(tmp_path):
    payload = b"MZ\x00\x00hello powershell https://example.org/payload 192.0.2.3\x00"
    result = analyze_file("../../sample.exe", payload)
    assert result["filename"] == "sample.exe"
    assert result["size"] == len(payload)
    assert len(result["sha256"]) == 64
    assert result["file_type"].startswith("PE")
    assert result["indicators"]["ipv4"] == ["192.0.2.3"]
    assert result["execution"] == "never"
    marker = tmp_path / "should-not-exist"
    analyze_file("sample.py", f"open({str(marker)!r}, 'w').write('executed')".encode())
    assert not marker.exists()


def capture_fixture():
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ip = b"\x45\x00" + struct.pack("!H", 28) + b"\x00\x00\x00\x00\x40\x11\x00\x00" + bytes([192, 0, 2, 1, 8, 8, 8, 8])
    udp = struct.pack("!HHHH", 12345, 53, 8, 0)
    packet = ethernet + ip + udp
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    return header + struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet


def test_pcap_decodes_conversations_and_reports_truncation():
    data = capture_fixture()
    result = analyze_file("traffic.pcap", data)
    capture = result["capture"]
    assert capture["packet_count"] == 1
    assert capture["conversations"][0]["source"] == "192.0.2.1:12345"
    assert capture["conversations"][0]["destination"] == "8.8.8.8:53"
    assert capture["protocols"] == [{"name": "UDP", "count": 1}]
    truncated = analyze_file("bad.pcap", data[:-3])["capture"]
    assert truncated["truncated"] is True
    assert truncated["warnings"]


def test_pcap_declared_gigabyte_length_does_not_allocate_or_crash():
    header = capture_fixture()[:24]
    capture = analyze_file("bad.pcap", header + struct.pack("<IIII", 0, 0, 0xFFFFFFFF, 0xFFFFFFFF))["capture"]
    assert capture["packet_count"] == 0
    assert capture["truncated"] is True


def test_empty_file_is_rejected_and_strings_are_bounded():
    with pytest.raises(ValueError):
        analyze_file("empty", b"")
    result = analyze_file("lots.txt", b"x" * 100000)
    assert len(result["strings"][0]) <= 240


def test_pcapng_enhanced_packet_block_is_decoded():
    packet = capture_fixture()[40:]
    def block(kind, body):
        body += b"\x00" * (-len(body) % 4)
        length = len(body) + 12
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    enhanced = block(6, struct.pack("<IIIII", 0, 0, 0, len(packet), len(packet)) + packet)
    capture = analyze_file("traffic.pcapng", section + interface + enhanced)["capture"]
    assert capture["packet_count"] == 1
    assert capture["format"] == "PCAPNG"


def test_source_code_signals_are_findings_not_malware_verdicts():
    result = analyze_file("script.py", b"import pickle\nvalue = pickle.loads(user_input)\n")
    assert any("deserial" in signal["label"].lower() for signal in result["signals"])
    assert any("not a verdict" in warning.lower() for warning in result["warnings"])
