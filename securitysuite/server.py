"""Dashboard HTTP server - standard library only, no web framework needed.

Serves the static dashboard, a small JSON API, and a Server-Sent Events stream
that pushes findings to the browser the moment they are written.
"""
from __future__ import annotations

import json
import queue
import sys
import threading
import time
import traceback
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import save_api_keys
from .ioc import summarise, to_csv
from .net import HttpError, get_json
from .risk import RiskRecommender
from .store import now_iso

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
ASSET_DIR = Path(__file__).resolve().parent.parent / "assets"
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
}
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    ),
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
MAX_BODY = 64 * 1024
MAX_REJECT_DRAIN = 128 * 1024
# Cache the VirusTotal key reachability probe; it is a blocking network call
# on a request path the dashboard polls.
VT_STATUS_TTL = 120.0
_VT_STATUS_CACHE: dict = {}
_VT_STATUS_LOCK = threading.Lock()
MAX_ACCESS_LOG = 160
FIREWALL_LOGS = (
    ("windows_firewall", Path("C:/Windows/System32/LogFiles/Firewall/pfirewall.log")),
    ("ufw", Path("/var/log/ufw.log")),
    ("kernel", Path("/var/log/kern.log")),
)
RISK_MODEL = RiskRecommender()

INTEL_SOURCES = (
    ("vuls", "https://github.com/future-architect/vuls", "bridge"),
    ("nvd", "https://nvd.nist.gov/", "catalog"),
    ("kev", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "catalog"),
    ("osv", "https://osv.dev/", "catalog"),
    ("github", "https://github.com/advisories", "catalog"),
    ("virustotal", "https://www.virustotal.com/", "optional"),
)


class Context:
    """Everything the request handler needs, injected onto the server object."""

    def __init__(self, cfg, engine, store, telemetry, monitor, nvd=None,
                 osv=None, vt=None, remediator=None, guidance=None):
        self.cfg = cfg
        self.engine = engine
        self.store = store
        self.telemetry = telemetry
        self.monitor = monitor
        self.nvd = nvd
        self.osv = osv
        self.vt = vt
        self.remediator = remediator
        self.guidance = guidance


class Handler(BaseHTTPRequestHandler):
    server_version = "SecuritySuite"
    protocol_version = "HTTP/1.1"

    @property
    def ctx(self) -> Context:
        return self.server.ctx  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):
        """Silence per-request logging; the dashboard is the console.

        The previous body returned early when the path was *not* /api/stream
        and fell through to nothing when it was, so it logged nothing either
        way and the condition was dead. Errors still surface: _guard() prints
        tracebacks and log_error() is untouched.
        """
        return

    # ----------------------------------------------------------- primitives
    def _host_allowed(self) -> bool:
        """Block DNS-rebinding: only localhost names may talk to the API."""
        raw = (self.headers.get("Host") or "").strip()
        if not raw:
            return True
        try:
            host = (urlparse("//" + raw).hostname or "").lower()
        except ValueError:
            return False
        return host in ("localhost", "127.0.0.1", "::1", "")

    def _csrf_ok(self) -> tuple:
        """Reject cross-origin writes.

        `_body()` never checked Content-Type, so a POST with
        `Content-Type: text/plain` is a CORS *simple request* - no preflight -
        and any page the operator happened to have open could fire one at
        127.0.0.1. It could not read the reply, but a deletion does not need a
        reply. Requiring application/json forces a preflight this server does
        not answer, so the browser blocks it before do_POST is reached.
        """
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return False, "Content-Type must be application/json"
        origin = self.headers.get("Origin")
        if origin:
            host = urlparse(origin).hostname or ""
            if host.lower() not in ("localhost", "127.0.0.1", "::1"):
                return False, "cross-origin request refused"
        site = (self.headers.get("Sec-Fetch-Site") or "").lower()
        if site and site not in ("same-origin", "none"):
            return False, "cross-site request refused"
        return True, ""

    def _send(self, code: int, body: bytes, content_type: str, extra: dict | None = None):
        self._record_access(code)
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _record_access(self, code: int):
        log = getattr(self.server, "access_log", None)  # type: ignore[attr-defined]
        if log is None:
            return
        path = urlparse(getattr(self, "path", "")).path or "/"
        client = self.client_address[0] if self.client_address else ""
        log.append({
            "timestamp": now_iso(),
            "method": self.command,
            "path": path,
            "status": code,
            "client": client,
            "agent": (self.headers.get("User-Agent") or "")[:80],
        })

    def _json(self, payload, code: int = 200):
        self._send(code, json.dumps(payload, default=str).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            self.close_connection = True
            return {}
        if length <= 0 or length > MAX_BODY:
            # A small overage can be drained before replying so well-behaved
            # clients receive a clean validation response. For a large body,
            # close instead of spending unbounded time or memory on input the
            # application will never accept.
            if MAX_BODY < length <= MAX_REJECT_DRAIN:
                self.rfile.read(length)
            elif length > MAX_BODY:
                self.close_connection = True
            return {}
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}
        # A JSON body may legally be a list, string or number, but every caller
        # here indexes it like a mapping.
        return payload if isinstance(payload, dict) else {}

    def _discard_small_body(self) -> None:
        """Consume a rejected request body when it is safely bounded.

        CSRF rejection happens before JSON parsing. Leaving even a small body
        unread makes the next HTTP/1.1 request on the same socket look like
        malformed request syntax, which can surface to clients as a reset.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            self.close_connection = True
            return
        if length > MAX_BODY:
            self.close_connection = True
        elif length > 0:
            self.rfile.read(length)

    @staticmethod
    def _int_param(raw, default: int, low: int, high: int) -> int:
        """Parse a caller-supplied integer, clamped, never raising.

        These were bare ``int(...)`` calls. ``?limit=abc`` raised ValueError out
        of the handler, which killed the connection without sending any
        response at all - the browser saw a network error, not a 400 - and left
        an unbounded ``limit`` free to serialise the entire ring buffer.
        """
        try:
            value = int(str(raw).strip())
        except (TypeError, ValueError):
            return default
        return max(low, min(high, value))

    def _guard(self, handler) -> None:
        """Run a route so no exception escapes as a silently dropped socket."""
        try:
            handler()
        except ConnectionError:
            pass                                  # client hung up; nothing to say
        except Exception:
            traceback.print_exc()
            try:
                self._json({"error": "internal error"}, 500)
            except OSError:
                pass                              # response already began

    def _static(self, name: str):
        web_root = WEB_DIR.resolve()
        target = (web_root / name).resolve()
        # is_relative_to, not startswith: a sibling directory named "web-evil"
        # satisfies a string prefix test against "web".
        if not target.is_relative_to(web_root) or not target.is_file():
            self._json({"error": "not found"}, 404)
            return
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    def _asset(self, name: str):
        """Serve a file from assets/ (the app icon lives there, not in web/)."""
        root = ASSET_DIR.resolve()
        target = (root / name).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            self._json({"error": "not found"}, 404)
            return
        ctype = CONTENT_TYPES.get(target.suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), ctype)

    # --------------------------------------------------------------- routes
    def do_GET(self):
        self._guard(self._handle_get)

    def do_HEAD(self):
        self._guard(self._handle_get)

    def do_POST(self):
        self._guard(self._handle_post)

    def _handle_get(self):
        if not self._host_allowed():
            self._json({"error": "host not allowed"}, 403)
            return
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if route == "/":
            self._static("studio.html")
        elif route == "/console":
            self._static("index.html")
        elif route == "/briefing":
            self._static("briefing.html")
        elif route == "/settings":
            self._static("settings.html")
        elif route in ("/app.js", "/styles.css", "/briefing.js", "/briefing.css",
                       "/studio.js", "/studio.css", "/settings.js", "/settings.css"):
            self._static(route.lstrip("/"))
        elif route in ("/assets/securitysuite.png", "/assets/security-studio.png",
                       "/assets/security-studio-icon.png"):
            self._asset(route.rsplit("/", 1)[-1])
        elif route == "/favicon.ico":
            self._asset("security-studio.ico")
        elif route == "/api/state":
            self._json(self._state())
        elif route == "/api/findings":
            findings = self.ctx.store.events(
                limit=self._int_param(params.get("limit"), 200, 1, 2000),
                severity=params.get("severity"),
                event_type=params.get("type"),
                status=params.get("status"),
                search=params.get("q"),
            )
            if self.ctx.remediator is not None:
                findings = self.ctx.remediator.annotate_many(findings)
            self._json(
                {
                    "findings": findings
                }
            )
        elif route == "/api/rules":
            self._json(self.ctx.engine.info())
        elif route == "/api/telemetry":
            self._json(self.ctx.telemetry.recent(force=params.get("force") == "1"))
        elif route == "/api/logs":
            self._json(self._logs())
        elif route == "/api/model":
            self._json(RISK_MODEL.schema())
        elif route == "/api/settings":
            self._json({
                "virustotal_configured": bool(getattr(self.ctx.vt, "api_key", "")),
                "nvd_configured": bool(getattr(self.ctx.nvd, "api_key", "")),
                "storage": ".env (local and git-ignored)",
            })
        elif route == "/api/intel":
            self._json(self._intel())
        elif route == "/api/iocs":
            events = self.ctx.store.events(limit=2000, event_type="yara_match")
            data = summarise(events)
            kind = (params.get("type") or "").strip()
            if kind and kind != "all":
                data["indicators"] = [i for i in data["indicators"] if i["type"] == kind]
            scope = (params.get("scope") or "").strip()
            if scope == "external":
                data["indicators"] = [
                    i for i in data["indicators"]
                    if i["type"] != "ipv4" or i.get("scope") == "external"]
            limit = self._int_param(params.get("limit"), 300, 1, 2000)
            data["shown"] = min(limit, len(data["indicators"]))
            data["indicators"] = data["indicators"][:limit]
            data["source_findings"] = len(events)
            if params.get("format") == "csv":
                body = to_csv(data["indicators"]).encode("utf-8")
                self._send(200, body, "text/csv; charset=utf-8",
                           {"Content-Disposition": 'attachment; filename="iocs.csv"'})
                return
            self._json(data)
        elif route == "/api/remediate":
            if self.ctx.remediator is None:
                self._json({"error": "remediation not enabled"}, 503)
                return
            self._json(self.ctx.remediator.status())
        elif route == "/api/remediate/guidance":
            if self.ctx.guidance is None:
                self._json({"error": "guidance not enabled"}, 503)
                return
            finding_id = (params.get("id") or "").strip()
            if not finding_id:
                self._json({"error": "id is required"}, 400)
                return
            finding = self.ctx.store.find(finding_id)
            if finding is None:
                self._json({"error": "unknown finding"}, 404)
                return
            self._json(self.ctx.guidance.for_finding(finding))
        elif route == "/api/vt":
            self._json(self.ctx.vt.status() if self.ctx.vt
                       else {"source": "virustotal", "status": "disabled"})
        elif route == "/api/vt/capabilities":
            if self.ctx.vt is None:
                self._json({"error": "virustotal adapter not enabled"}, 503)
                return
            refresh = params.get("refresh") == "1"
            # An explicit refresh may block; the dashboard poll never does.
            self._json(self.ctx.vt.capabilities(refresh=refresh, block=refresh))
        elif route == "/api/vt/file":
            if self.ctx.vt is None:
                self._json({"error": "virustotal adapter not enabled"}, 503)
                return
            digest = (params.get("hash") or "").strip()
            if not digest:
                self._json({"error": "hash is required"}, 400)
                return
            self._json(self.ctx.vt.lookup_hash(digest))
        elif route in ("/api/vt/livehunt", "/api/vt/retrohunt"):
            if self.ctx.vt is None:
                self._json({"error": "virustotal adapter not enabled"}, 503)
                return
            feature = "livehunt" if route.endswith("livehunt") else "retrohunt"
            result = self.ctx.vt.hunting(feature)
            self._json(result, 200 if result.get("available") else 402)
        elif route == "/api/osv":
            self._json(self.ctx.osv.status() if self.ctx.osv
                       else {"source": "osv", "status": "disabled"})
        elif route == "/api/osv/query":
            if self.ctx.osv is None:
                self._json({"error": "osv adapter not enabled"}, 503)
                return
            self._json(self.ctx.osv.query({
                "commit": params.get("commit", ""),
                "purl": params.get("purl", ""),
                "package": params.get("package", ""),
                "ecosystem": params.get("ecosystem", ""),
                "version": params.get("version", ""),
            }))
        elif route == "/api/nvd":
            self._json(self._nvd_status())
        elif route == "/api/nvd/cves":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            self._json({"cves": self.ctx.nvd.cached_records(
                limit=self._int_param(params.get("limit"), 100, 1, 1000),
                severity=params.get("severity", ""))})
        elif route == "/api/nvd/cve":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            cve_id = (params.get("id") or "").strip()
            if not cve_id:
                self._json({"error": "id is required"}, 400)
                return
            self._json(self.ctx.nvd.fetch_cve(cve_id))
        elif route == "/api/nvd/search":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            query = (params.get("q") or "").strip()
            if not query:
                self._json({"error": "q is required"}, 400)
                return
            self._json(self.ctx.nvd.search(
                query, self._int_param(params.get("limit"), 20, 1, 200)))
        elif route == "/api/stream":
            self._stream()
        else:
            self._json({"error": "not found"}, 404)

    def _handle_post(self):
        if not self._host_allowed():
            self._json({"error": "host not allowed"}, 403)
            return
        route = urlparse(self.path).path.rstrip("/") or "/"
        allowed, why = self._csrf_ok()
        if not allowed:
            self._discard_small_body()
            self._json({"error": why}, 403)
            return
        body = self._body()

        if route == "/api/settings":
            updates = {}
            fields = (
                ("virustotal_api_key", "remove_virustotal", "VIRUSTOTAL_API_KEY"),
                ("nvd_api_key", "remove_nvd", "NVD_API_KEY"),
            )
            for field, remove_field, env_name in fields:
                if body.get(remove_field) is True:
                    updates[env_name] = ""
                elif field in body and str(body.get(field) or "").strip():
                    updates[env_name] = str(body[field]).strip()
            if not updates:
                self._json({"error": "enter a key or select a key to remove"}, 400)
                return
            try:
                status = save_api_keys(updates)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
            if "VIRUSTOTAL_API_KEY" in updates and self.ctx.vt is not None:
                self.ctx.vt.set_api_key(updates["VIRUSTOTAL_API_KEY"])
                self.ctx.cfg.virustotal_api_key = updates["VIRUSTOTAL_API_KEY"]
                with _VT_STATUS_LOCK:
                    _VT_STATUS_CACHE.clear()
            if "NVD_API_KEY" in updates and self.ctx.nvd is not None:
                self.ctx.nvd.set_api_key(updates["NVD_API_KEY"])
                self.ctx.cfg.nvd_api_key = updates["NVD_API_KEY"]
            self._json({
                "saved": True,
                "virustotal_configured": status["VIRUSTOTAL_API_KEY"],
                "nvd_configured": status["NVD_API_KEY"],
            })
        elif route == "/api/model/predict":
            try:
                result = RISK_MODEL.assess(body)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
            context = self._model_context(result["input"])
            nvd_record = (context.get("nvd") or {}).get("record") or {}
            if nvd_record.get("kev") and not result["input"]["known_exploited"]:
                enriched = dict(body)
                enriched["known_exploited"] = True
                result = RISK_MODEL.assess(enriched)
            result["context"] = context
            self._json(result)
        elif route == "/api/scan":
            target = str(body.get("path", "")).strip()
            if not target:
                self._json({"error": "path is required"}, 400)
                return
            self._json(self.ctx.monitor.scan_path(target))
        elif route == "/api/monitor":
            action = str(body.get("action", "")).lower()
            if action == "pause":
                self.ctx.monitor.pause()
            elif action in ("resume", "start"):
                self.ctx.monitor.resume()
            else:
                self._json({"error": "action must be pause or resume"}, 400)
                return
            status = self.ctx.monitor.status()
            self.ctx.store.broadcast(
                {"event_type": "monitor", "timestamp": now_iso(),
                 "message": "Monitor " + ("paused" if status["paused"] else "resumed")}
            )
            self._json(status)
        elif route == "/api/rules/reload":
            info = self.ctx.engine.reload()
            self.ctx.store.broadcast(
                {"event_type": "monitor", "timestamp": now_iso(),
                 "message": "Reloaded " + str(info["rule_count"]) + " rules"}
            )
            self._json(info)
        elif route == "/api/findings/clear":
            # Every other destructive route demands an explicit confirm; this
            # one wipes the whole dashboard, so it does too.
            if not body.get("confirm"):
                self._json({"error": "confirmation required",
                            "detail": "resend with confirm=true"}, 409)
                return
            self._json(self.ctx.store.clear())
        elif route == "/api/osv/query":
            if self.ctx.osv is None:
                self._json({"error": "osv adapter not enabled"}, 503)
                return
            self._json(self.ctx.osv.query(body))
        elif route == "/api/nvd/sync":
            if self.ctx.nvd is None:
                self._json({"error": "nvd adapter not enabled"}, 503)
                return
            days = self._int_param(body.get("days"),
                                   getattr(self.ctx.cfg, "nvd_sync_days", 3), 1, 120)
            result = self.ctx.nvd.sync(days, getattr(self.ctx.cfg, "nvd_max_records", 4000))
            self.ctx.store.broadcast({
                "event_type": "monitor", "timestamp": now_iso(),
                "message": "NVD sync: " + str(result.get("cached", 0)) + " CVEs cached"
                           if "error" not in result else "NVD sync failed: " + result["error"],
            })
            self._json(result)
        elif route == "/api/remediate":
            if self.ctx.remediator is None:
                self._json({"error": "remediation not enabled"}, 503)
                return
            finding_id = str(body.get("id", "")).strip()
            if not finding_id:
                self._json({"error": "id is required"}, 400)
                return
            result = self.ctx.remediator.act(
                finding_id,
                str(body.get("action", "quarantine")),
                confirm=bool(body.get("confirm")),
                dry_run=bool(body.get("dry_run")),
                allow_directory=bool(body.get("allow_directory")),
            )
            # A refusal is a considered answer, not a server fault: 409.
            if result.get("ok"):
                code = 200
            elif result.get("refused") == "unknown finding":
                code = 404
            elif result.get("refused") == "unknown action":
                code = 400
            else:
                code = 409
            self._json(result, code)
        elif route == "/api/remediate/bulk":
            if self.ctx.remediator is None:
                self._json({"error": "remediation not enabled"}, 503)
                return
            result = self.ctx.remediator.bulk(
                severity=str(body.get("severity", "")),
                extensions=body.get("extensions") or [],
                action=str(body.get("action", "quarantine")),
                confirm=bool(body.get("confirm")),
                dry_run=body.get("dry_run", True) is not False,
                limit=self._int_param(body.get("limit"), 50, 1, 500),
            )
            self._json(result)
        elif route == "/api/triage":
            updated = self.ctx.store.set_status(
                str(body.get("id", "")),
                str(body.get("status", "acknowledged")),
                str(body.get("note", "")),
            )
            if updated is None:
                self._json({"error": "finding not found"}, 404)
                return
            self._json(updated)
        else:
            self._json({"error": "not found"}, 404)

    # ---------------------------------------------------------------- state
    def _state(self) -> dict:
        cfg = self.ctx.cfg
        return {
            "stats": self.ctx.store.stats(),
            "monitor": self.ctx.monitor.status(),
            "engine": self.ctx.engine.info(),
            "stream": {
                "dropped_subscribers": getattr(self.ctx.store, "dropped_subscribers", 0),
            },
            "telemetry": self.ctx.telemetry.recent(),
            "config": {
                "watch_paths": cfg.watch_paths,
                "lookback_minutes": cfg.lookback_minutes,
                "max_file_mb": cfg.max_file_mb,
                "poll_interval": cfg.poll_interval,
                "findings_log": cfg.findings_log,
            },
            "server_time": now_iso(),
        }

    def _nvd_status(self) -> dict:
        if self.ctx.nvd is None:
            return {"source": "nvd", "status": "disabled"}
        return self.ctx.nvd.status()

    def _model_context(self, data: dict) -> dict:
        """Optional authoritative lookups for identifiers supplied in the form."""
        context = {
            "nvd": {"status": "not_requested"},
            "osv": {"status": "not_requested"},
            "virustotal": {"status": "not_requested"},
        }
        cve = data.get("cve", "")
        if cve:
            if self.ctx.nvd is None:
                context["nvd"] = {"status": "disabled"}
            else:
                record = self.ctx.nvd.fetch_cve(cve)
                context["nvd"] = {
                    "status": "error" if record.get("error") else "ok",
                    "record": record,
                }
        purl = data.get("purl", "")
        if purl:
            if self.ctx.osv is None:
                context["osv"] = {"status": "disabled"}
            else:
                result = self.ctx.osv.query({"purl": purl})
                context["osv"] = {
                    "status": "error" if result.get("error") else "ok",
                    "result": result,
                }
        digest = data.get("sha256", "")
        if digest:
            if self.ctx.vt is None or not self.ctx.vt.configured:
                context["virustotal"] = {"status": "disabled"}
            else:
                result = self.ctx.vt.lookup_hash(digest)
                context["virustotal"] = {
                    "status": "error" if result.get("error") else "ok",
                    "result": result,
                }
        return context

    def _vt_key_status(self, vt_key: str) -> str:
        """Reachability of the configured VirusTotal key, cached.

        This is a blocking outbound request. Uncached, every /api/intel GET
        parked a server thread on it for up to two seconds, and the dashboard
        polls that endpoint.
        """
        now = time.time()
        with _VT_STATUS_LOCK:
            cached = _VT_STATUS_CACHE.get(vt_key)
            if cached and now - cached[0] < VT_STATUS_TTL:
                return cached[1]
        try:
            get_json("https://www.virustotal.com/api/v3/users/me",
                     headers={"x-apikey": vt_key}, timeout=2)
            status = "online"
        except HttpError as exc:
            status = ("rejected" if exc.status in (401, 403)
                      else "rate limited" if exc.status == 429 else "configured")
        except (TimeoutError, OSError):
            status = "offline"
        with _VT_STATUS_LOCK:
            _VT_STATUS_CACHE[vt_key] = (now, status)
        return status

    def _intel(self) -> dict:
        """Return source adapters without ever returning credentials to clients."""
        vt_key = str(getattr(self.ctx.cfg, "virustotal_api_key", "") or "").strip()
        vt_status = self._vt_key_status(vt_key) if vt_key else "optional"
        nvd_state = self._nvd_status()
        nvd_cached = int(nvd_state.get("cached") or 0)
        nvd_status = "offline" if nvd_state.get("last_error") else (
            "syncing" if nvd_state.get("syncing") else
            "online" if nvd_cached else "catalog")

        sources = []
        for source_id, url, status in INTEL_SOURCES:
            entry = {
                "id": source_id,
                "url": url,
                "status": vt_status if source_id == "virustotal" else status,
                "configured": bool(vt_key) if source_id == "virustotal" else True,
            }
            if source_id == "virustotal" and self.ctx.vt is not None:
                vt_state = self.ctx.vt.status()
                vt_tier = vt_state.get("tier", "public")
                entry["tier"] = vt_tier
                entry["hunting"] = vt_state.get("hunting_available", False)
                entry["detail"] = (
                    "enterprise: hunting available" if vt_state.get("hunting_available")
                    else "public tier: hash lookups only"
                    if vt_state.get("configured") else "no key configured")
            if source_id == "osv" and self.ctx.osv is not None:
                osv_state = self.ctx.osv.status()
                entry["status"] = ("offline" if osv_state.get("last_error")
                                   else "online" if osv_state.get("cached_queries")
                                   else "ready")
                entry["cached"] = osv_state.get("cached_queries", 0)
                entry["detail"] = (str(osv_state.get("cached_queries", 0))
                                   + " queries cached")
            if source_id == "nvd":
                entry["status"] = nvd_status
                entry["cached"] = nvd_cached
                entry["last_sync"] = nvd_state.get("last_sync")
                entry["detail"] = (str(nvd_cached) + " CVEs cached"
                                   if nvd_cached else "not synced yet")
            sources.append(entry)
        return {
            "status": "live" if vt_status == "online" else "linked",
            "synced_at": now_iso(),
            "sources": sources,
        }

    # ------------------------------------------------------------------ logs
    def _logs(self) -> dict:
        events = self.ctx.store.events(limit=500, event_type="all")
        firewall = self._firewall()
        return {
            "synced_at": now_iso(),
            "behavior": self._behavior(events, firewall),
            "server": {
                "requests": list(reversed(list(
                    getattr(self.server, "access_log", [])  # type: ignore[attr-defined]
                )))[:60],
            },
            "firewall": firewall,
        }

    def _behavior(self, events: list[dict], firewall: dict) -> dict:
        by_type = Counter(str(e.get("event_type", "unknown")) for e in events)
        remediation = [e for e in events if e.get("event_type") == "remediation"]
        destructive = [
            e for e in remediation
            if str(e.get("action", "")).lower() in ("delete", "purge")
            or str(e.get("outcome", "")).lower() in ("deleted", "purged")
        ]
        refused = [e for e in remediation if e.get("refused")]
        return {
            "events": len(events),
            "detections": by_type.get("yara_match", 0),
            "clean_scans": by_type.get("scan", 0),
            "errors": by_type.get("error", 0),
            "remediation": len(remediation),
            "destructive_actions": len(destructive),
            "refused_actions": len(refused),
            "firewall_blocks": firewall.get("blocked", 0),
            "recent_delete": destructive[:6],
        }

    def _firewall(self) -> dict:
        for source, path in FIREWALL_LOGS:
            if not path.exists():
                continue
            try:
                lines = self._tail_lines(path)
            except OSError as exc:
                return {
                    "status": "error",
                    "source": source,
                    "path": str(path),
                    "detail": str(exc),
                    "events": [],
                    "blocked": 0,
                    "allowed": 0,
                }
            events = self._parse_firewall(source, path, lines)
            blocked = sum(1 for e in events if e.get("action") == "block")
            allowed = sum(1 for e in events if e.get("action") == "allow")
            return {
                "status": "ok",
                "source": source,
                "path": str(path),
                "events": events[-40:],
                "blocked": blocked,
                "allowed": allowed,
            }
        tried = ", ".join(str(path) for _, path in FIREWALL_LOGS)
        return {
            "status": "unavailable",
            "source": "firewall_log",
            "detail": "no firewall log found; enable Windows Firewall logging or UFW logging",
            "tried": tried,
            "events": [],
            "blocked": 0,
            "allowed": 0,
        }

    def _tail_lines(self, path: Path, size: int = 200_000) -> list[str]:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            end = handle.tell()
            handle.seek(max(0, end - size))
            return handle.read().decode("utf-8", errors="replace").splitlines()

    def _parse_firewall(self, source: str, path: Path, lines: list[str]) -> list[dict]:
        events = []
        for line in lines:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            lower = text.lower()
            if "drop" in lower or "block" in lower or "deny" in lower:
                action = "block"
            elif "allow" in lower:
                action = "allow"
            else:
                continue
            parts = text.split()
            stamp = " ".join(parts[:2]) if len(parts) >= 2 else ""
            src = next((p.split("=", 1)[1] for p in parts if p.startswith("SRC=")), "")
            dst = next((p.split("=", 1)[1] for p in parts if p.startswith("DST=")), "")
            if source == "windows_firewall" and len(parts) >= 8:
                src = src or parts[4]
                dst = dst or parts[5]
            events.append({
                "timestamp": stamp,
                "source": source,
                "path": str(path),
                "action": action,
                "src": src,
                "dst": dst,
                "line": text[:220],
            })
        return events

    # ------------------------------------------------------------------ SSE
    def _stream(self):
        if self.command == "HEAD":
            # do_HEAD shares this router; without this a HEAD /api/stream would
            # enter the loop below and hold a thread open forever.
            self._send(200, b"", "text/event-stream")
            return
        self._record_access(200)
        sub = self.ctx.store.subscribe()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last_stats = 0.0
        try:
            self._sse("hello", {"server_time": now_iso()})
            while True:
                try:
                    event = sub.get(timeout=1.0)
                    if event.get("__stream__") == "overflow":
                        # We fell too far behind and the store detached us.
                        # Close so EventSource reconnects onto a fresh
                        # subscription; staying open would mean showing a
                        # "live" dashboard that receives nothing.
                        self._sse("overflow", {"reason": "client fell behind"})
                        break
                    self._sse("event", event)
                except queue.Empty:
                    pass
                if time.time() - last_stats >= 2.0:
                    self._sse(
                        "stats",
                        {
                            "stats": self.ctx.store.stats(),
                            "monitor": self.ctx.monitor.status(),
                        },
                    )
                    last_stats = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            self.ctx.store.unsubscribe(sub)

    def _sse(self, name: str, payload: dict):
        data = json.dumps(payload, default=str)
        self.wfile.write(("event: " + name + "\ndata: " + data + "\n\n").encode("utf-8"))
        self.wfile.flush()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        """Stay quiet when a client hangs up; report everything else.

        Browsers drop idle keep-alive and stream sockets all the time. On
        Windows that arrives as ConnectionAbortedError (WinError 10053), often
        while the server is still reading the request line - before any route
        runs, so ``_guard`` never sees it - and the stock handler prints a full
        traceback that reads like a crash. ConnectionError covers the abort,
        reset and broken-pipe cases alike.
        """
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


def serve(cfg, engine, store, telemetry, monitor, nvd=None, osv=None,
          vt=None, remediator=None, guidance=None) -> DashboardServer:
    httpd = DashboardServer((cfg.host, cfg.port), Handler)
    httpd.ctx = Context(cfg, engine, store, telemetry, monitor, nvd, osv, vt,
                        remediator, guidance)  # type: ignore[attr-defined]
    httpd.access_log = deque(maxlen=MAX_ACCESS_LOG)  # type: ignore[attr-defined]
    thread = threading.Thread(target=httpd.serve_forever, name="securitysuite-http",
                              daemon=True)
    thread.start()
    return httpd
