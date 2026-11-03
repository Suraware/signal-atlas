import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

ROOT = Path(__file__).resolve().parents[1]


def project_copy(tmp_path, *, environment=True, interface=True):
    root = tmp_path / "project with spaces"
    root.mkdir()
    if (ROOT / "start.sh").is_file():
        shutil.copyfile(ROOT / "start.sh", root / "start.sh")
    shutil.copytree(ROOT / "backend", root / "backend", ignore=shutil.ignore_patterns("__pycache__"))
    if environment:
        (root / ".venv").symlink_to(Path(sys.prefix), target_is_directory=True)
    if interface:
        (root / "frontend" / "dist").mkdir(parents=True)
        (root / "frontend" / "dist" / "index.html").write_text("<title>Local launcher fixture</title>")
    return root


def test_launcher_helps_from_a_different_working_directory(tmp_path):
    root = project_copy(tmp_path)
    result = subprocess.run(["bash", str(root / "start.sh"), "--help"], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--lan" in result.stdout
    assert "--data-dir" in result.stdout
    assert not (root / "data").exists()


def test_launcher_reports_missing_environment_without_downloading_or_creating_data(tmp_path):
    root = project_copy(tmp_path, environment=False)
    result = subprocess.run(["bash", str(root / "start.sh")], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1
    assert "uv sync --frozen --extra dev" in result.stderr
    assert not (root / ".venv").exists()
    assert not (root / "data").exists()


def test_launcher_requires_built_local_assets_before_starting(tmp_path):
    root = project_copy(tmp_path, interface=False)
    result = subprocess.run(["bash", str(root / "start.sh")], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode == 1
    assert "npm --prefix frontend run build" in result.stderr
    assert not (root / "data").exists()


def test_launcher_serves_same_origin_api_and_assets_with_the_requested_data_directory(tmp_path):
    root = project_copy(tmp_path)
    data = tmp_path / "isolated research data"
    with socket.socket() as port_socket:
        port_socket.bind(("127.0.0.1", 0))
        port = port_socket.getsockname()[1]
    process = subprocess.Popen(
        ["bash", str(root / "start.sh"), "--port", str(port), "--data-dir", str(data)],
        cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    opener = build_opener(ProxyHandler({}))
    try:
        deadline = time.monotonic() + 10
        while True:
            assert process.poll() is None, process.communicate()
            try:
                with opener.open(f"http://127.0.0.1:{port}/api/health", timeout=1) as response:
                    health = json.load(response)
                break
            except URLError:
                assert time.monotonic() < deadline, "The launcher did not start its local server."
                time.sleep(0.05)
        assert health["storage"] == "local"
        assert health["refresh_seconds"] == 0
        with opener.open(f"http://127.0.0.1:{port}/", timeout=1) as response:
            assert b"Local launcher fixture" in response.read()
        assert (data / "atlas.sqlite3").is_file()
        assert not (root / "data").exists()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
