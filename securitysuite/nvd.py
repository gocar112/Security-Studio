"""NVD CVE API 2.0 adapter with a local cache.

    https://services.nvd.nist.gov/rest/json/cves/2.0

Unlike the VirusTotal adapter, NVD needs no credential: an API key only raises
the rate limit (5 requests per 30 s without, 50 per 30 s with). Set NVD_API_KEY
in .env to use one.

The API is offset paginated - ``startIndex`` and ``resultsPerPage`` (max 2000) -
and the full corpus is ~390,000 CVEs, so this adapter never tries to mirror it.
It syncs a trailing window of recently modified CVEs into ``nvds/`` and fetches
individual records on demand.
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .net import HttpError, RateLimiter, get_json, ssl_source

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS_PER_PAGE = 2000
MAX_WINDOW_DAYS = 120           # NVD rejects date ranges wider than this
CVE_ID_PREFIX = "CVE-"
# Bumped when normalise() changes shape, so stale cache entries are
# treated as a miss rather than silently served without new fields.
SCHEMA = 3
PATCH_TAGS = {"Patch", "Vendor Advisory", "Mitigation"}

SEVERITY_MAP = {                # NVD CVSS severity -> suite severity
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "info",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(when: datetime) -> str:
    """NVD wants ISO-8601 with milliseconds and no timezone suffix."""
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def normalise(entry: dict) -> dict:
    """Flatten one NVD record into the compact shape the dashboard consumes."""
    cve = entry.get("cve", entry)
    metrics = cve.get("metrics", {})

    score, severity, vector, version = None, None, "", ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if not items:
            continue
        data = items[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or items[0].get("baseSeverity")
        vector = data.get("vectorString", "")
        version = data.get("version", key)
        break

    description = ""
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", "")
            break

    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value", "")
            if value.startswith("CWE-") and value not in weaknesses:
                weaknesses.append(value)

    patch_refs = []
    for ref in cve.get("references", []) or []:
        tags = set(ref.get("tags") or [])
        if tags & PATCH_TAGS:
            patch_refs.append({"url": ref.get("url", ""),
                               "tags": sorted(tags & PATCH_TAGS)})

    return {
        "schema": SCHEMA,
        "id": cve.get("id", ""),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "status": cve.get("vulnStatus", ""),
        "score": score,
        "cvss_severity": (severity or "").upper(),
        "severity": SEVERITY_MAP.get((severity or "").upper(), "info"),
        "cvss_version": version,
        "vector": vector,
        "cwe": weaknesses[:4],
        "description": description[:600],
        "references": len(cve.get("references", []) or []),
        "patch_refs": patch_refs[:8],
        "kev": bool(cve.get("cisaExploitAdd")),
        "kev_name": cve.get("cisaVulnerabilityName", ""),
        "exploit_added": cve.get("cisaExploitAdd", ""),
        "kev_required_action": cve.get("cisaRequiredAction", ""),
        "kev_action_due": cve.get("cisaActionDue", ""),
        "source": cve.get("sourceIdentifier", ""),
    }


class NvdClient:
    """Talks to the NVD CVE API and keeps a small local cache under nvds/."""

    def __init__(self, cache_dir: str, api_key: str = "", timeout: float = 30.0):
        self.cache_dir = Path(cache_dir)
        self.lookups_dir = self.cache_dir / "lookups"
        self.index_path = self.cache_dir / "index.json"
        self.feed_path = self.cache_dir / "cves.ndjson"
        self.api_key = (api_key or os.getenv("NVD_API_KEY", "")).strip()
        self.timeout = timeout
        # 5 requests / 30 s without a key, 50 / 30 s with one; stay under both.
        self.limiter = RateLimiter(0.8 if self.api_key else 6.5)
        self._lock = threading.Lock()
        self._syncing = False
        self.last_error: str | None = None
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.lookups_dir.mkdir(parents=True, exist_ok=True)

    def set_api_key(self, api_key: str) -> None:
        """Apply a key immediately, including the matching request cadence."""
        self.api_key = (api_key or "").strip()
        self.limiter = RateLimiter(0.8 if self.api_key else 6.5)

    # ------------------------------------------------------------------ http
    def _headers(self) -> dict:
        return {"apiKey": self.api_key} if self.api_key else {}

    def _get(self, params: dict) -> dict:
        # NVD has valueless boolean parameters (hasKev, hasCert, isVulnerable):
        # they must appear as a bare key, so True means "emit the flag alone".
        parts = []
        for key, value in params.items():
            if value is True:
                parts.append(str(key))
            elif value not in (None, "", False):
                parts.append(str(key) + "=" +
                             str(value).replace(" ", "%20").replace(":", "%3A"))
        query = "&".join(parts)
        self.limiter.wait()
        url = BASE_URL + "?" + query
        try:
            return get_json(url, headers=self._headers(), timeout=self.timeout)
        except HttpError as exc:
            # NVD remains available without a key. A revoked or malformed key
            # can currently surface as either 403 or 404, so degrade to the
            # documented public cadence instead of disabling intelligence.
            if not self.api_key or exc.status not in (403, 404):
                raise
            self.api_key = ""
            self.limiter = RateLimiter(6.5)
            self.last_error = (
                "configured NVD API key was rejected; using the public rate limit"
            )
            self.limiter.wait()
            return get_json(url, headers={}, timeout=self.timeout)

    # --------------------------------------------------------------- queries
    def fetch_cve(self, cve_id: str, use_cache: bool = True) -> dict:
        """One CVE by id, cached on disk after the first fetch."""
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith(CVE_ID_PREFIX):
            return {"error": "not a CVE id: " + cve_id}

        cached = self.lookups_dir / (cve_id + ".json")
        if use_cache and cached.exists():
            try:
                record = json.loads(cached.read_text(encoding="utf-8"))
                if record.get("schema") == SCHEMA:
                    record["cached"] = True
                    return record
                # Written before the shape changed; re-fetch rather than serve
                # a record missing the patch references.
            except (OSError, json.JSONDecodeError):
                pass

        try:
            payload = self._get({"cveId": cve_id})
        except HttpError as exc:
            self.last_error = str(exc)
            return {"error": str(exc), "id": cve_id}

        items = payload.get("vulnerabilities") or []
        if not items:
            return {"error": "not found", "id": cve_id}
        record = normalise(items[0])
        try:
            cached.write_text(json.dumps(record, indent=1), encoding="utf-8")
        except OSError:
            pass
        record["cached"] = False
        return record

    def search(self, keyword: str, limit: int = 20) -> dict:
        """Keyword search against the live API (NVD does the matching)."""
        limit = max(1, min(int(limit), 200))
        try:
            payload = self._get({
                "keywordSearch": keyword,
                "resultsPerPage": limit,
                "startIndex": 0,
            })
        except HttpError as exc:
            self.last_error = str(exc)
            return {"error": str(exc), "results": []}
        return {
            "query": keyword,
            "total": payload.get("totalResults", 0),
            "results": [normalise(v) for v in payload.get("vulnerabilities", [])],
        }

    # ------------------------------------------------------------------ sync
    def sync(self, days: int = 7, max_records: int = 4000) -> dict:
        """Pull CVEs modified in the trailing window into the local cache."""
        with self._lock:
            if self._syncing:
                return {"error": "a sync is already running"}
            self._syncing = True
        try:
            return self._sync(days, max_records)
        finally:
            with self._lock:
                self._syncing = False

    def _sync(self, days: int, max_records: int) -> dict:
        days = max(1, min(int(days), MAX_WINDOW_DAYS))
        end = _now()
        start = end - timedelta(days=days)
        started = _now()

        records: list[dict] = []
        start_index = 0
        total = None
        pages = 0

        while True:
            try:
                payload = self._get({
                    "lastModStartDate": _stamp(start),
                    "lastModEndDate": _stamp(end),
                    "resultsPerPage": MAX_RESULTS_PER_PAGE,
                    "startIndex": start_index,
                })
            except HttpError as exc:
                self.last_error = str(exc)
                if records:
                    break          # keep the partial result rather than losing it
                return {"error": str(exc), "synced": 0}

            pages += 1
            total = payload.get("totalResults", 0)
            batch = payload.get("vulnerabilities", []) or []
            if not batch:
                break
            records.extend(normalise(v) for v in batch)
            start_index += len(batch)
            if start_index >= min(total, max_records) or len(records) >= max_records:
                break

        self.last_error = None
        return self._write_cache(records, start, end, total or len(records), pages, started)

    def _write_cache(self, records, start, end, total, pages, started) -> dict:
        severities: dict = {}
        for record in records:
            key = record.get("severity", "info")
            severities[key] = severities.get(key, 0) + 1

        try:
            with self.feed_path.open("w", encoding="utf-8") as handle:
                for record in records:
                    handle.write(json.dumps(record) + "\n")
        except OSError as exc:
            return {"error": "could not write cache: " + str(exc), "synced": 0}

        index = {
            "last_sync": started.astimezone().isoformat(timespec="seconds"),
            "window_start": start.astimezone().isoformat(timespec="seconds"),
            "window_end": end.astimezone().isoformat(timespec="seconds"),
            "window_days": (end - start).days,
            "cached": len(records),
            "total_in_window": total,
            "truncated": len(records) < total,
            "pages_fetched": pages,
            "by_severity": severities,
            "last_sync_used_key": bool(self.api_key),
            "elapsed_seconds": round((_now() - started).total_seconds(), 1),
        }
        try:
            self.index_path.write_text(json.dumps(index, indent=1), encoding="utf-8")
        except OSError:
            pass
        return index

    # ---------------------------------------------------------------- status
    def cached_records(self, limit: int = 100, severity: str = "") -> list[dict]:
        if not self.feed_path.exists():
            return []
        out = []
        try:
            with self.feed_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if severity and severity != "all" and record.get("severity") != severity:
                        continue
                    out.append(record)
        except OSError:
            return []
        out.sort(key=lambda r: (r.get("score") or 0), reverse=True)
        return out[:limit]

    def status(self) -> dict:
        index = {}
        if self.index_path.exists():
            try:
                index = json.loads(self.index_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                index = {}
        # Spread the cached index FIRST so live state always wins. The index
        # records what was true at the last sync; it must never shadow what is
        # true now - a stale "api_key": false there once made a configured key
        # report as absent.
        index.pop("api_key", None)          # superseded by last_sync_used_key
        return {
            **index,
            "source": "nvd",
            "base_url": BASE_URL,
            "cache_dir": str(self.cache_dir),
            "api_key": bool(self.api_key),
            "rate_limit": "50/30s (key)" if self.api_key else "5/30s (no key)",
            "tls_bundle": ssl_source(),
            "syncing": self._syncing,
            "lookups_cached": len(list(self.lookups_dir.glob("*.json"))),
            "last_error": self.last_error,
        }
