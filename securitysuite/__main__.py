"""Entry point: python -m securitysuite [options]"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from .config import ROOT, load_config
from .engine import YaraEngine
from .nvd import NvdClient
from .guidance import Guidance
from .osv import OsvClient
from .remediate import Remediator
from .server import serve
from .store import EventStore
from .telemetry import AuthTelemetry
from .virustotal import VtClient
from .watcher import Monitor

BANNER = r"""
  ___  ___  ___ _   _ ___ ___ _______   __  ___ _   _ ___ _____ ___
 / __|| __|/ __| | | | _ \_ _|_   _\ \ / / / __| | | |_ _|_   _| __|
 \__ \| _|| (__| |_| |   /| |  | |  \ V /  \__ \ |_| || |  | | | _|
 |___/|___|\___|\___/|_|_\___| |_|   |_|   |___/\___/|___| |_| |___|
"""


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="securitysuite",
    description="Security Studio: YARA-backed SOC detection with a live dashboard.",
    )
    parser.add_argument("--host", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="dashboard port (default 8900)")
    parser.add_argument("--watch", action="append", metavar="DIR",
                        help="directory to monitor (repeatable, replaces config)")
    parser.add_argument("--rules", metavar="DIR", help="rules directory")
    parser.add_argument("--scan", metavar="PATH",
                        help="scan a file or directory, print JSON, exit")
    parser.add_argument("--headless", action="store_true",
                        help="monitor only, no dashboard server")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open a browser window")
    parser.add_argument("--scan-existing", action="store_true",
                        help="scan files already present at startup")
    return parser.parse_args(argv)


def build(args):
    cfg = load_config()
    if args.host:
        cfg.host = args.host
    if args.port:
        cfg.port = args.port
    if args.watch:
        cfg.watch_paths = args.watch
    if args.rules:
        cfg.rules_dir = args.rules
    if args.scan_existing:
        cfg.scan_existing_on_start = True

    engine = YaraEngine(cfg.rules_dir, cfg.max_file_bytes)
    store = EventStore(cfg.findings_log, cfg.triage_file, cfg.history_limit)
    telemetry = AuthTelemetry(
        cfg.auth_log_path, cfg.lookback_minutes,
        cfg.telemetry_cache_seconds, cfg.max_telemetry_events,
    )
    nvd = NvdClient(cfg.nvd_cache_dir, cfg.nvd_api_key)
    osv = OsvClient(cfg.osv_cache_dir)
    vt = VtClient(cfg.virustotal_api_key, cfg.vt_cache_dir)
    remediator = Remediator(cfg, store, nvd)
    guidance = Guidance(cfg.guidance_cache_dir, nvd)
    monitor = Monitor(cfg, engine, store, telemetry, remediator)
    return cfg, engine, store, telemetry, monitor, nvd, osv, vt, remediator, guidance


LOG_FILE = ROOT / "data" / "securitysuite.log"
LOG_ROLL_BYTES = 5 * 1024 * 1024


def log_when_windowless(path: Path = LOG_FILE) -> bool:
    """Send output to a log file when there is no console to send it to.

    The desktop shortcut runs pythonw.exe so that no console window opens.
    pythonw gives the process no stdout or stderr at all - they are None - so
    every status line, alert and traceback, including why the suite refused
    to start, would vanish. Returns True when it redirected.
    """
    if sys.stdout is not None and sys.stderr is not None:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.stat().st_size > LOG_ROLL_BYTES:
            os.replace(path, path.with_name(path.name + ".1"))
    except OSError:
        pass
    stream = open(path, "a", encoding="utf-8", buffering=1)  # line-buffered
    stream.write("\n==== " + time.strftime("%Y-%m-%d %H:%M:%S %z")
                 + " Security Studio (pid " + str(os.getpid()) + ")\n")
    sys.stdout = sys.stderr = stream
    return True


def running_instance(url: str, findings_log: str) -> bool:
    """Is a Security Studio for this same workspace already serving at url?

    Matching on the findings log, not just a response on the port, keeps an
    unrelated service on 8900 from being mistaken for ours.
    """
    try:
        with urllib.request.urlopen(url + "/api/state", timeout=1.5) as response:
            state = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return False
    theirs = str((state.get("config") or {}).get("findings_log", ""))
    return bool(theirs) and (os.path.normcase(os.path.abspath(theirs))
                             == os.path.normcase(os.path.abspath(findings_log)))


def main(argv=None) -> int:
    log_when_windowless()
    args = parse_args(argv)
    cfg, engine, store, telemetry, monitor, nvd, osv, vt, remediator, guidance = build(args)

    info = engine.info()
    print(BANNER)
    print("[*] Rules      : " + str(info["rule_count"]) + " loaded from " + info["rules_dir"]
          + (" (FALLBACK RULE ONLY)" if info["using_fallback"] else ""))
    for err in info["load_errors"]:
        print("[!] Rule error : " + err["file"] + " -> " + err["error"])
    telemetry_state = telemetry.recent()
    print("[*] Telemetry  : " + telemetry_state["source"] + " -> "
          + telemetry_state["status"]
          + (" (" + telemetry_state.get("detail", "") + ")"
             if telemetry_state.get("detail") else ""))

    nvd_state = nvd.status()
    print("[*] NVD        : " + str(nvd_state.get("cached", 0)) + " CVEs cached, "
          + nvd_state["rate_limit"] + ", tls via " + nvd_state["tls_bundle"]
          + (" (last sync " + nvd_state["last_sync"] + ")" if nvd_state.get("last_sync") else ""))

    if cfg.auto_remediate:
        print("[!] AUTO-REMEDIATE ARMED: " + cfg.auto_remediate_action
              + " at severity " + cfg.auto_remediate_severity
              + " - files will be acted on without confirmation")
    else:
        print("[*] Remediate  : manual only (auto-remediate off)")

    if args.scan:
        result = monitor.scan_path(args.scan)
        print(json.dumps(result, indent=2))
        return 0 if "error" not in result else 1

    # Before the monitor starts, not after the bind fails: a second monitor on
    # the same folders would scan every file twice and, with auto-remediation
    # armed, race the first one to quarantine it. Without a console window a
    # second double-click is the likely way to get here, so it opens the
    # dashboard that is already running.
    url = "http://" + cfg.host + ":" + str(cfg.port)
    if not args.headless and running_instance(url, cfg.findings_log):
        print("[*] Dashboard already running: " + url)
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except (OSError, webbrowser.Error):
                pass
        return 0

    monitor.start()
    print("[*] Watching   : " + ", ".join(cfg.watch_paths))
    print("[*] Findings   : " + cfg.findings_log)

    httpd = None
    if not args.headless:
        try:
            httpd = serve(cfg, engine, store, telemetry, monitor, nvd, osv, vt,
                          remediator, guidance)
        except OSError as exc:
            print("[-] Could not bind " + cfg.host + ":" + str(cfg.port) + " -> " + str(exc))
            monitor.stop()
            return 1
        print("[*] Dashboard  : " + url)
        if not args.no_browser:
            try:
                webbrowser.open(url)
            except (OSError, webbrowser.Error):
                pass

    print("[*] Ctrl-C to stop.\n")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        monitor.stop()
        if httpd is not None:
            httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
