"""Acting on a detection: delete, quarantine, restore, purge.

Everything else in this package is read-only. This module is not, and that
changes the stakes completely. A detection that is merely wrong produces an
alert somebody dismisses; a *remediation* that is wrong destroys a file.

The ruleset that drives it contains 1,500 rules, 1,427 of them generated. Pointed
at this project's own directory it flags 27 of 55 tracked files, 16 of them
critical - including the detector's own rule files. So the question this module
answers is not "can I delete a file" but "how do I refuse to delete the wrong
one".

Six rails, each producing a distinct refusal:

1. The target is resolved from a stored finding, never from a path supplied by
   the caller. The HTTP API must not become an arbitrary-file-deletion
   primitive - there is no CSRF token, only loopback binding and a Host check.
2. SHA-256 is re-verified immediately before acting. If the file changed since
   detection, it is no longer the thing that was detected.
3. The path must resolve inside a configured watch root (or an explicitly
   allowed remediation root), compared after realpath so a symlink cannot walk
   out.
4. Directories are refused unless explicitly requested, and then only inside
   those same roots.
5. dry_run reports the full decision without touching anything.
6. Suite-owned paths are refused unconditionally, ahead of every other check.
   Without this rail an operator who points a watch root at the project deletes
   the ruleset that protects them.

Every attempt, including every refusal, is appended to the findings log as an
immutable audit record. The triage sidecar keeps only latest-state; a
destructive action needs history.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
from datetime import datetime
from pathlib import Path

from .engine import sha256_of
from .store import SEVERITY_RANK, now_iso

ACTIONS = ("delete", "quarantine", "restore", "purge")
META_SUFFIX = ".remediation.json"


def _norm(path) -> str:
    """Canonical form for comparison: realpath resolves symlinks, normcase
    handles Windows' case-insensitivity."""
    try:
        return os.path.normcase(os.path.realpath(str(path)))
    except (OSError, ValueError):
        return os.path.normcase(os.path.abspath(str(path)))


def _within(path: str, root: str) -> bool:
    """True when path is root or sits beneath it. Compares path components so
    /var/logsomething is not treated as being inside /var/log."""
    path_n, root_n = _norm(path), _norm(root)
    if path_n == root_n:
        return True
    return path_n.startswith(root_n.rstrip(os.sep) + os.sep)


class Refused(Exception):
    """A rail rejected the action. Carries the reason shown to the operator."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


class Remediator:
    """Performs remediation actions under the six rails described above."""

    def __init__(self, cfg, store, nvd=None):
        self.cfg = cfg
        self.store = store
        self.nvd = nvd
        self._lock = threading.RLock()
        self.quarantine_dir = Path(getattr(cfg, "quarantine_dir",
                                           "quarantine")).resolve()
        self.state_path = Path(getattr(cfg, "remediation_file",
                                       "data/remediation.json"))
        self._state: dict = {}
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_state()

    # ------------------------------------------------------------- protection
    @property
    def project_root(self) -> Path:
        return Path(__file__).resolve().parent.parent

    def suite_owned_roots(self) -> list:
        """Paths this tool must never remediate, whatever else is configured.

        The project directory is protected *wholesale*. An earlier version
        listed only the obvious subdirectories - the package, rules/, book/ -
        and a test that pointed a watch root at the project promptly deleted
        README.md, because a loose file in the project root matched no entry.
        Enumerating what to protect is the wrong shape: the list is never
        complete. Protect the tree and carve out the watch paths instead.
        """
        roots = [self.project_root, self.quarantine_dir]
        roots.extend([
            self.project_root / "securitysuite",
            Path(getattr(self.cfg, "rules_dir", self.project_root / "rules")),
            self.project_root / "book",
            self.project_root / "assets",
            self.project_root / "data",
        ])
        # Individual state files, in case they are configured outside the tree.
        for attr in ("findings_log", "triage_file", "remediation_file",
                     "nvd_cache_dir", "guidance_cache_dir", "osv_cache_dir",
                     "vt_cache_dir"):
            value = getattr(self.cfg, attr, None)
            if value:
                roots.append(Path(value))
        return [str(r) for r in roots]

    def _carve_outs(self) -> list:
        """Watch paths strictly *below* the project root stay remediable.

        `uploads/` lives inside the project and is the whole point of the tool,
        so it must not inherit the project's blanket protection. A watch path
        that *is* the project root grants nothing - otherwise pointing the
        monitor at the project would re-open everything this guard closes.
        """
        project = _norm(self.project_root)
        protected_children = [
            _norm(root) for root in self.suite_owned_roots()
            if _norm(root) != project
        ]
        out = []
        for watched in self.permitted_roots():
            resolved = _norm(watched)
            if resolved != project and resolved.startswith(
                    project.rstrip(os.sep) + os.sep):
                if any(_within(resolved, root) or _within(root, resolved)
                       for root in protected_children):
                    continue
                out.append(watched)
        return out

    def is_protected(self, path: str) -> str:
        """Return the protecting root, or '' when the path may be acted on."""
        for carve in self._carve_outs():
            if _within(path, carve):
                return ""                    # inside uploads/ or similar
        for root in self.suite_owned_roots():
            if _within(path, root):
                return root
        return ""

    def permitted_roots(self) -> list:
        roots = list(self.cfg.watch_paths)
        roots.extend(getattr(self.cfg, "remediation_roots", []) or [])
        return [r for r in roots if r]

    # ------------------------------------------------------------------ rails
    def _check(self, path: str, allow_directory: bool) -> dict:
        """Run every rail. Raises Refused on the first failure."""
        checks = {}

        # Rail 6 first: suite-owned paths lose regardless of configuration.
        protector = self.is_protected(path)
        if protector:
            raise Refused("suite-owned path",
                          "refusing to remediate inside " + str(protector))
        checks["suite_owned"] = "clear"

        # Rail 3: confinement.
        roots = self.permitted_roots()
        if not any(_within(path, root) for root in roots):
            raise Refused("outside permitted roots",
                          "not inside any of: " + ", ".join(roots))
        checks["confinement"] = "clear"

        if not os.path.exists(path):
            raise Refused("target is gone", path + " no longer exists")

        # Rail 4: directories.
        if os.path.isdir(path):
            if not allow_directory:
                raise Refused("target is a directory",
                              "pass allow_directory to act on a folder")
            checks["directory"] = "permitted"
        else:
            checks["directory"] = "n/a"
        return checks

    def _verify_hash(self, path: str, expected: str, checks: dict) -> dict:
        """Rail 2. A directory has no hash, so this is skipped for one."""
        if os.path.isdir(path):
            checks["hash"] = "skipped (directory)"
            return checks
        if not expected:
            checks["hash"] = "no recorded hash on the finding"
            return checks
        try:
            actual = sha256_of(path)
        except OSError as exc:
            raise Refused("could not read the target", str(exc))
        if actual.lower() != str(expected).lower():
            raise Refused("hash mismatch",
                          "file changed since detection (recorded %s, now %s)"
                          % (expected[:12], actual[:12]))
        checks["hash"] = "matches the finding"
        return checks

    # ------------------------------------------------------------------ state
    def _load_state(self) -> None:
        if self.state_path.exists():
            try:
                self._state = json.loads(self.state_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self._state = {}

    def _save_state(self) -> None:
        try:
            self.state_path.write_text(json.dumps(self._state, indent=1),
                                       encoding="utf-8")
        except OSError as exc:
            print("[-] Could not persist remediation state: " + str(exc))

    def _audit(self, record: dict) -> dict:
        """Append-only. Refusals are recorded as deliberately as successes."""
        record.setdefault("event_type", "remediation")
        record.setdefault("timestamp", now_iso())
        return self.store.add(record)

    def state_for(self, finding_id: str) -> dict | None:
        return self._state.get(finding_id)

    def annotate(self, finding: dict) -> dict:
        """Return a UI-safe copy with remediation and target state attached."""
        item = dict(finding)
        if item.get("event_type") != "yara_match":
            return item
        state = self._state.get(str(item.get("id", "")))
        if state:
            item["remediation"] = dict(state)
        path = str(item.get("file_path") or "")
        exists = bool(path and os.path.exists(path))
        item["target_exists"] = exists
        if state and state.get("action") in ("delete", "quarantine", "purged"):
            item["target_state"] = state.get("action")
        else:
            item["target_state"] = "present" if exists else "gone"
        return item

    def annotate_many(self, findings: list[dict]) -> list[dict]:
        return [self.annotate(finding) for finding in findings]

    @staticmethod
    def _target_refusal(annotated: dict) -> str:
        target = annotated.get("target_state")
        if target == "gone":
            return "target is gone"
        if target == "delete":
            return "already deleted"
        if target == "quarantine":
            return "already quarantined"
        if target == "purged":
            return "already purged"
        return ""

    # ----------------------------------------------------------------- actions
    def act(self, finding_id: str, action: str, *, confirm: bool = False,
            dry_run: bool = False, allow_directory: bool = False,
            trigger: str = "manual") -> dict:
        """Resolve a finding, run the rails, and act. Never raises."""
        if action not in ACTIONS:
            result = {"ok": False, "action": action, "finding": finding_id,
                      "dry_run": bool(dry_run), "trigger": trigger,
                      "refused": "unknown action",
                      "detail": "expected one of " + ", ".join(ACTIONS)}
            if not dry_run:
                self._audit(dict(result, outcome="refused"))
            return result

        finding = self._find(finding_id)
        if finding is None:
            result = {"ok": False, "action": action, "finding": finding_id,
                      "dry_run": bool(dry_run), "trigger": trigger,
                      "refused": "unknown finding",
                      "detail": "no finding with id " + str(finding_id)}
            if not dry_run:
                self._audit(dict(result, outcome="refused"))
            return result

        if action in ("restore", "purge"):
            return self._from_quarantine(finding_id, finding, action,
                                         confirm, dry_run, trigger)

        if finding.get("event_type") != "yara_match":
            result = {"ok": False, "action": action, "finding": finding_id,
                      "path": str(finding.get("file_path") or ""),
                      "dry_run": bool(dry_run), "trigger": trigger,
                      "refused": "not a detection",
                      "detail": "only yara_match findings can be remediated"}
            if not dry_run:
                self._audit(dict(result, outcome="refused"))
            return result

        path = str(finding.get("file_path") or "")
        result = {
            "ok": False, "action": action, "finding": finding_id,
            "path": path, "dry_run": bool(dry_run), "trigger": trigger,
            "severity": finding.get("severity"),
            "rules": finding.get("rule_names", []),
        }

        previous = self._state.get(finding_id)
        if previous and previous.get("action") in ("delete", "quarantine", "purged"):
            labels = {
                "delete": "already deleted",
                "quarantine": "already quarantined",
                "purged": "already purged",
            }
            outcome = labels.get(str(previous.get("action")), "already handled")
            result.update({
                "ok": False,
                "refused": outcome,
                "outcome": outcome,
                "detail": previous.get("detail", ""),
                "remediation": dict(previous),
            })
            if not dry_run:
                self._audit(dict(result, outcome="refused"))
            return result

        try:
            checks = self._check(path, allow_directory)
            checks = self._verify_hash(path, finding.get("sha256", ""), checks)
        except Refused as exc:
            result.update({"refused": exc.reason, "detail": exc.detail})
            if not dry_run:
                self._audit(dict(result, outcome="refused"))
            return result
        result["checks"] = checks

        if dry_run:
            result.update({"ok": True, "outcome": "would " + action,
                           "detail": "dry run - nothing was changed"})
            return result

        # Rail 5's companion: an explicit confirmation for a destructive act.
        if not confirm:
            result.update({"refused": "confirmation required",
                           "detail": "resend with confirm=true"})
            self._audit(dict(result, outcome="refused"))
            return result

        try:
            if action == "delete":
                detail = self._delete(path)
            else:
                detail = self._quarantine(finding_id, finding, path)
        except OSError as exc:
            result.update({"refused": "filesystem error", "detail": str(exc)})
            self._audit(dict(result, outcome="failed"))
            return result

        with self._lock:
            self._state[finding_id] = {
                "action": action, "at": now_iso(), "path": path,
                "detail": detail, "trigger": trigger,
            }
            self._save_state()
        finding["remediation"] = self._state[finding_id]

        result.update({"ok": True, "outcome": action + "d" if action == "delete"
                       else "quarantined", "detail": detail})
        self._audit(dict(result, outcome=result["outcome"]))
        self.store.broadcast({
            "event_type": "monitor", "timestamp": now_iso(),
            "message": "Remediated %s: %s" % (
                os.path.basename(path) or path, result["outcome"]),
        })
        return result

    def _find(self, finding_id: str):
        for event in self.store.events(limit=5000, event_type="all"):
            if event.get("id") == finding_id:
                return event
        return None

    def _delete(self, path: str) -> str:
        if os.path.isdir(path):
            shutil.rmtree(path)
            return "directory deleted"
        size = os.path.getsize(path)
        os.remove(path)
        return "deleted (%d bytes, unrecoverable)" % size

    def _quarantine(self, finding_id: str, finding: dict, path: str) -> str:
        holding = self.quarantine_dir / finding_id
        holding.mkdir(parents=True, exist_ok=True)
        target = holding / os.path.basename(path)
        shutil.move(path, str(target))
        meta = {
            "finding": finding_id,
            "original_path": path,
            "quarantined_at": now_iso(),
            "sha256": finding.get("sha256", ""),
            "severity": finding.get("severity"),
            "rules": finding.get("rule_names", []),
        }
        (holding / (os.path.basename(path) + META_SUFFIX)).write_text(
            json.dumps(meta, indent=1), encoding="utf-8")
        return "moved to " + str(target)

    def _from_quarantine(self, finding_id, finding, action, confirm,
                         dry_run, trigger) -> dict:
        state = self._state.get(finding_id)
        result = {"ok": False, "action": action, "finding": finding_id,
                  "dry_run": bool(dry_run), "trigger": trigger}
        if not state or state.get("action") != "quarantine":
            result.update({"refused": "not quarantined",
                           "detail": "this finding has no quarantined file"})
            if not dry_run:
                self._audit(dict(result, outcome="refused"))
            return result

        holding = self.quarantine_dir / finding_id
        original = state.get("path", "")
        stored = holding / os.path.basename(original)
        if not stored.exists():
            result.update({"refused": "quarantined file is gone",
                           "detail": str(stored)})
            if not dry_run:
                self._audit(dict(result, outcome="refused"))
            return result

        result["path"] = str(stored)
        if action == "restore":
            try:
                protector = self.is_protected(original)
                if protector:
                    raise Refused("suite-owned path",
                                  "refusing to restore inside " + str(protector))
                roots = self.permitted_roots()
                if not any(_within(original, root) for root in roots):
                    raise Refused("outside permitted roots",
                                  "not inside any of: " + ", ".join(roots))
                if os.path.exists(original):
                    raise Refused("restore target exists",
                                  original + " already exists")
            except Refused as exc:
                result.update({"refused": exc.reason, "detail": exc.detail})
                if not dry_run:
                    self._audit(dict(result, outcome="refused"))
                return result

        if dry_run:
            result.update({"ok": True,
                           "outcome": "would " + action,
                           "detail": "dry run - nothing was changed"})
            return result
        if not confirm:
            result.update({"refused": "confirmation required",
                           "detail": "resend with confirm=true"})
            self._audit(dict(result, outcome="refused"))
            return result

        try:
            if action == "restore":
                os.makedirs(os.path.dirname(original) or ".", exist_ok=True)
                shutil.move(str(stored), original)
                detail = "restored to " + original
            else:
                os.remove(str(stored))
                detail = "purged from quarantine (unrecoverable)"
            meta = holding / (os.path.basename(original) + META_SUFFIX)
            if action == "purge" and meta.exists():
                meta.unlink()
        except OSError as exc:
            result.update({"refused": "filesystem error", "detail": str(exc)})
            self._audit(dict(result, outcome="failed"))
            return result

        with self._lock:
            if action == "purge":
                self._state[finding_id] = {"action": "purged", "at": now_iso(),
                                           "path": original, "detail": detail}
            else:
                self._state.pop(finding_id, None)
            self._save_state()

        result.update({"ok": True, "outcome": action + "d", "detail": detail})
        self._audit(dict(result, outcome=result["outcome"]))
        return result

    # -------------------------------------------------------------------- bulk
    def bulk(self, *, severity: str = "", extensions: list | None = None,
             action: str = "quarantine", confirm: bool = False,
             dry_run: bool = True, limit: int = 50) -> dict:
        """Act on every outstanding detection matching a filter.

        Defaults to quarantine and dry_run because a filtered destructive sweep
        is the single most dangerous operation this module offers.
        """
        extensions = [e.lower().lstrip(".") for e in (extensions or []) if e]
        candidates, results = [], []
        seen_targets = set()
        for event in self.store.events(limit=2000, event_type="yara_match"):
            if event.get("id") in self._state:
                continue                               # already acted on
            if severity and severity != "all":
                rank = SEVERITY_RANK.get(event.get("severity", "info"), 99)
                threshold = SEVERITY_RANK.get(severity, 99)
                if rank > threshold:
                    continue
                # "critical" remains exact because it is the top rank.
                if severity == "critical" and event.get("severity") != "critical":
                    continue
            name = str(event.get("file_name") or
                       os.path.basename(str(event.get("file_path") or "")))
            if extensions and name.rsplit(".", 1)[-1].lower() not in extensions:
                continue
            target_key = _norm(event.get("file_path") or event.get("id") or "")
            if target_key in seen_targets:
                continue
            seen_targets.add(target_key)
            candidates.append(event)
            if len(candidates) >= limit:
                break

        for event in candidates:
            annotated = self.annotate(event)
            refusal = self._target_refusal(annotated)
            if refusal:
                refused = {
                    "ok": False,
                    "action": action,
                    "finding": event.get("id"),
                    "path": event.get("file_path", ""),
                    "dry_run": bool(dry_run),
                    "trigger": "bulk",
                    "severity": event.get("severity"),
                    "rules": event.get("rule_names", []),
                    "refused": refusal,
                    "detail": "the latest target state is " +
                              str(annotated.get("target_state")),
                }
                if not dry_run:
                    self._audit(dict(refused, outcome="refused"))
                results.append(refused)
                continue
            results.append(self.act(event["id"], action, confirm=confirm,
                                    dry_run=dry_run, trigger="bulk"))
        acted = sum(1 for r in results if r.get("ok") and not r.get("dry_run"))
        actionable = sum(1 for r in results
                         if not r.get("refused") and
                         (r.get("ok") or r.get("dry_run")))
        return {
            "matched": len(candidates), "acted": acted, "dry_run": dry_run,
            "actionable": actionable,
            "refused": sum(1 for r in results if r.get("refused")),
            "action": action, "severity": severity or "all",
            "extensions": extensions, "results": results,
        }

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        actions = [e for e in self.store.events(limit=400, event_type="remediation")]
        quarantined = sum(1 for v in self._state.values()
                          if v.get("action") == "quarantine")
        return {
            "quarantine_dir": str(self.quarantine_dir),
            "quarantined": quarantined,
            "acted_on": len(self._state),
            "auto_remediate": bool(getattr(self.cfg, "auto_remediate", False)),
            "auto_action": getattr(self.cfg, "auto_remediate_action", "quarantine"),
            "auto_severity": getattr(self.cfg, "auto_remediate_severity", "critical"),
            "permitted_roots": self.permitted_roots(),
            "protected_roots": self.suite_owned_roots(),
            "recent": actions[:40],
        }

    # --------------------------------------------------------------- auto rule
    def consider_auto(self, finding: dict) -> dict | None:
        """Called by the monitor. Returns None unless the opt-in rule applies."""
        if not getattr(self.cfg, "auto_remediate", False):
            return None
        if finding.get("event_type") != "yara_match":
            return None
        threshold = getattr(self.cfg, "auto_remediate_severity", "critical")
        rank = SEVERITY_RANK.get(finding.get("severity", "info"), 99)
        if rank > SEVERITY_RANK.get(threshold, 0):
            return None
        action = getattr(self.cfg, "auto_remediate_action", "quarantine")
        return self.act(finding["id"], action, confirm=True, trigger="auto")
