"""API-surface tests: boot the real server and probe its edges.

These cover the input handling that used to drop connections rather than
answer them. No live network calls and no OS auth logs, so they are safe in CI.
"""
from __future__ import annotations

import contextlib
import io
import socket
import sys
import tempfile
import time
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import securitysuite.config as config_module
import securitysuite.nvd as nvd_module
from securitysuite.__main__ import log_when_windowless, running_instance
from securitysuite.config import load_config
from securitysuite.engine import YaraEngine
from securitysuite.net import HttpError, get_json, post_json
from securitysuite.nvd import NvdClient
from securitysuite.server import MAX_BODY, serve
from securitysuite.store import EventStore
from securitysuite.telemetry import AuthTelemetry
from securitysuite.watcher import Monitor
from securitysuite.virustotal import VtClient


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def get(base: str, path: str):
    """Return (status, body). A dropped connection is reported as status None."""
    try:
        with urllib.request.urlopen(base + path, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception:
        return None, b""


def post(base: str, path: str, payload: dict | None = None, *,
         content_type: str = "application/json", extra_headers: dict | None = None):
    headers = {"Content-Type": content_type, **(extra_headers or {})}
    data = json.dumps(payload or {}).encode("utf-8")
    request = urllib.request.Request(base + path, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception:
        return None, b""


def main() -> int:
    # The intel adapters must never follow a caller-controlled local or
    # cleartext URL. These checks happen before any connection is attempted.
    for target in ("http://example.test/data", "file:///tmp/data.json", "https:///",
                   "https://user:pass@example.test/data"):
        for request in (lambda: get_json(target), lambda: post_json(target, {})):
            try:
                request()
                raise AssertionError("unsafe URL was accepted: " + target)
            except ValueError:
                pass

    # A rejected NVD key must fall back to the supported public endpoint
    # instead of disabling vulnerability intelligence.
    original_nvd_get_json = nvd_module.get_json
    nvd_calls = []

    def fake_nvd_get_json(url, headers=None, timeout=30.0):
        nvd_calls.append(dict(headers or {}))
        if headers and headers.get("apiKey"):
            raise HttpError(404)
        return {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-TEST"}}]}

    nvd_module.get_json = fake_nvd_get_json
    try:
        fallback_client = NvdClient(tempfile.mkdtemp(prefix="ss_nvd_fallback_"),
                                    "a" * 32)
        fallback_payload = fallback_client._get({"resultsPerPage": 1})
        assert_true(fallback_payload["totalResults"] == 1,
                    "NVD public fallback did not return data")
        assert_true(len(nvd_calls) == 2 and "apiKey" in nvd_calls[0]
                    and "apiKey" not in nvd_calls[1],
                    "NVD fallback did not remove the rejected key")
    finally:
        nvd_module.get_json = original_nvd_get_json

    tmp = Path(tempfile.mkdtemp(prefix="ss_api_"))
    watch = tmp / "watch"
    watch.mkdir()
    original_env_file = config_module.ENV_FILE
    original_env = {name: os.environ.get(name) for name in config_module.API_KEY_NAMES}
    config_module.ENV_FILE = tmp / ".env"

    cfg = load_config()
    cfg.watch_paths = [str(watch)]
    cfg.findings_log = str(tmp / "findings.ndjson")
    cfg.triage_file = str(tmp / "triage.json")
    cfg.port = free_port()

    engine = YaraEngine(cfg.rules_dir, cfg.max_file_bytes)
    store = EventStore(cfg.findings_log, cfg.triage_file, 500)
    telemetry = AuthTelemetry(cfg.auth_log_path, 5, 0, 25)
    monitor = Monitor(cfg, engine, store, telemetry, None)
    nvd = NvdClient(str(tmp / "nvd"))
    vt = VtClient("", str(tmp / "vt"))
    sample = None
    for i in range(40):
        event = store.add({"event_type": "yara_match", "severity": "high",
                           "file_path": "/x/%d" % i, "matches": []})
        if sample is None:
            sample = event

    httpd = serve(cfg, engine, store, telemetry, monitor, nvd=nvd, vt=vt)
    base = "http://127.0.0.1:%d" % cfg.port
    try:
        time.sleep(0.5)

        # A malformed integer parameter must be answered, not met with a
        # dropped socket. These raised ValueError out of the handler, so the
        # client saw a connection reset and no response at all.
        for path in ("/api/findings?limit=abc", "/api/findings?limit=",
                     "/api/findings?limit=9e99", "/api/iocs?limit=notanumber",
                     "/api/findings?limit=-5", "/api/nvd/cves?limit=xyz"):
            status, _ = get(base, path)
            assert_true(status is not None,
                        "connection dropped instead of answering %s" % path)
            # 503 is a legitimate answer when an optional adapter is absent;
            # what must never happen is a crash or a dropped socket.
            assert_true(status in (200, 400, 404, 503),
                        "%s returned %s" % (path, status))

        # An oversized limit must be clamped rather than serialising the world.
        status, body = get(base, "/api/findings?limit=999999999")
        assert_true(status == 200, "clamped limit should still succeed")

        # The icon lives in assets/, not web/; this route always 404'd.
        status, body = get(base, "/favicon.ico")
        assert_true(status == 200, "favicon should be served, got %s" % status)
        assert_true(len(body) > 0, "favicon body was empty")

        # Core reads still work.
        for path in ("/", "/console", "/briefing", "/settings", "/app.js",
                     "/styles.css", "/briefing.js", "/briefing.css", "/studio.js",
                     "/studio.css", "/settings.js", "/settings.css",
                     "/assets/security-studio.png", "/assets/security-studio-icon.png", "/api/state",
                     "/api/rules", "/api/findings", "/api/iocs", "/api/model",
                     "/api/intel", "/api/logs", "/api/settings"):
            status, _ = get(base, path)
            assert_true(status == 200, "%s returned %s" % (path, status))

        # Writes must still refuse a body that is not JSON (CSRF rail).
        request = urllib.request.Request(
            base + "/api/monitor", data=b'{"action":"pause"}',
            headers={"Content-Type": "text/plain"}, method="POST")
        try:
            urllib.request.urlopen(request, timeout=10)
            raise AssertionError("non-JSON POST was accepted")
        except urllib.error.HTTPError as exc:
            assert_true(exc.code == 403, "expected 403, got %d" % exc.code)

        status, _ = post(base, "/api/monitor", {"action": "pause"},
                         extra_headers={"Origin": "https://example.invalid"})
        assert_true(status == 403, "cross-origin POST should be rejected")

        status, body = post(base, "/api/monitor", {"action": "pause"})
        assert_true(status == 200 and json.loads(body)["paused"],
                    "monitor pause did not succeed")
        status, body = post(base, "/api/monitor", {"action": "resume"})
        assert_true(status == 200 and not json.loads(body)["paused"],
                    "monitor resume did not succeed")

        status, _ = post(base, "/api/scan", {})
        assert_true(status == 400, "empty scan request should be rejected")

        vt_key = "VT_TEST_" + "a" * 32
        nvd_key = "NVD_TEST_" + "b" * 32
        status, body = post(base, "/api/settings", {
            "virustotal_api_key": vt_key,
            "nvd_api_key": nvd_key,
        })
        assert_true(status == 200, "API key settings should save")
        assert_true(vt_key.encode() not in body and nvd_key.encode() not in body,
                    "settings response exposed an API key")
        status, body = get(base, "/api/settings")
        assert_true(status == 200 and b'"virustotal_configured": true' in body,
                    "settings status should report configured keys")
        assert_true(vt_key.encode() not in body and nvd_key.encode() not in body,
                    "settings status exposed an API key")
        assert_true(nvd.limiter.min_interval == 0.8,
                    "NVD key update did not activate the keyed rate limit")
        assert_true(config_module.ENV_FILE.read_text(encoding="utf-8").count("_API_KEY=") == 2,
                    "local key file was not written as expected")
        status, _ = post(base, "/api/settings", {"nvd_api_key": "too-short"})
        assert_true(status == 400, "invalid API key should be rejected")
        status, body = post(base, "/api/settings", {
            "remove_virustotal": True, "remove_nvd": True,
        })
        assert_true(status == 200 and b'"nvd_configured": false' in body,
                    "saved keys should be removable")
        status, body = post(base, "/api/model/predict", {
            "vulnerability_type": "SQL injection",
            "impact": "Sensitive data exposure on an internet-facing service",
            "cvss": 9.1,
        })
        assert_true(status == 200 and b'"mode": "deterministic"' in body,
                    "risk model endpoint did not return an explainable result")
        status, _ = post(base, "/api/model/predict", {"impact": "missing type"})
        assert_true(status == 400, "invalid risk model request should be rejected")

        status, body = post(base, "/api/triage", {
            "id": sample["id"], "status": "acknowledged", "note": "API test",
        })
        assert_true(status == 200 and b'"acknowledged"' in body,
                    "triage route did not update the sample event")
        status, _ = post(base, "/api/findings/clear", {})
        assert_true(status == 409, "clear route must require confirmation")
        status, _ = post(base, "/api/findings/clear", {"confirm": True})
        assert_true(status == 200, "confirmed clear route did not succeed")

        oversized = urllib.request.Request(
            base + "/api/monitor", data=b"x" * (MAX_BODY + 1),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(oversized, timeout=10)
        except urllib.error.HTTPError as exc:
            assert_true(exc.code == 400, "oversized body should receive a 400")
        except Exception as exc:
            raise AssertionError("oversized body dropped the connection: " + str(exc)) from exc

        stream = urllib.request.urlopen(base + "/api/stream", timeout=10)
        try:
            assert_true(stream.status == 200, "SSE stream did not open")
        finally:
            stream.close()

        # /api/state reports stream health.
        status, body = get(base, "/api/state")
        assert_true(b"dropped_subscribers" in body,
                    "/api/state should report stream health")

        # A client that hangs up mid-request is routine - browsers drop idle
        # keep-alive sockets constantly - and on Windows it surfaces as
        # ConnectionAbortedError (WinError 10053). It must not print a
        # traceback to the console as if the server had failed.
        for dropped in (ConnectionAbortedError(10053, "aborted"),
                        ConnectionResetError(10054, "reset"),
                        BrokenPipeError(32, "broken pipe")):
            captured = io.StringIO()
            with contextlib.redirect_stderr(captured):
                try:
                    raise dropped
                except OSError:
                    httpd.handle_error(None, ("127.0.0.1", 0))
            assert_true(captured.getvalue() == "",
                        type(dropped).__name__ + " printed a traceback: "
                        + captured.getvalue()[:200])

        # A real failure must still be reported, not swallowed with the rest.
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            try:
                raise RuntimeError("genuine failure")
            except RuntimeError:
                httpd.handle_error(None, ("127.0.0.1", 0))
        assert_true("genuine failure" in captured.getvalue(),
                    "a genuine handler error was hidden")

        # A second launch must find this instance before starting its own
        # monitor - and must not mistake another workspace, or nothing, for it.
        assert_true(running_instance(base, cfg.findings_log),
                    "running instance for this workspace was not recognised")
        assert_true(not running_instance(base, str(tmp / "other" / "findings.ndjson")),
                    "an instance for another workspace was taken for this one")
        assert_true(not running_instance("http://127.0.0.1:%d" % free_port(), cfg.findings_log),
                    "an empty port was taken for a running instance")

        # Under pythonw there is no stdout or stderr. Output must land in the
        # log rather than vanish, and a console run must be left alone.
        saved = sys.stdout, sys.stderr
        log_path = tmp / "windowless" / "securitysuite.log"
        try:
            assert_true(not log_when_windowless(log_path),
                        "redirected although a console was present")
            sys.stdout = sys.stderr = None
            assert_true(log_when_windowless(log_path), "did not redirect without a console")
            print("windowless status line")
            sys.stderr.write("windowless error line\n")
        finally:
            redirected = sys.stdout
            sys.stdout, sys.stderr = saved
            if redirected not in (None, saved[0]):
                redirected.close()
        logged = log_path.read_text(encoding="utf-8")
        assert_true("windowless status line" in logged and "windowless error line" in logged,
                    "windowless output did not reach the log: " + logged[-200:])

        print("API tests passed")
        return 0
    finally:
        httpd.shutdown()
        config_module.ENV_FILE = original_env_file
        for name, value in original_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


if __name__ == "__main__":
    raise SystemExit(main())
