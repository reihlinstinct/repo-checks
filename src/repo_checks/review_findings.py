"""Bounded declarative review evidence validation. Never executes consumer code."""
import json
from pathlib import Path, PurePosixPath

MAX_BYTES = 262144
MAX_FINDINGS = 30


class InvalidEvidence(ValueError):
    """Counts-only public failure; do not include consumer values."""


def read_json(path):
    data = Path(path).read_bytes()
    if len(data) > MAX_BYTES:
        raise InvalidEvidence("input exceeds bound")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise InvalidEvidence("duplicate JSON key")
            out[key] = value
        return out
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise InvalidEvidence("invalid JSON") from exc


def safe_file(root, value):
    if not isinstance(value, str) or not value or len(value) > 240:
        raise InvalidEvidence("invalid path")
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ("", ".", "..") for x in value.split("/")) or "\\" in value or "\x00" in value:
        raise InvalidEvidence("unsafe path")
    current = Path(root)
    for part in p.parts:
        current = current / part
        if current.is_symlink():
            raise InvalidEvidence("symlink path")
    if not current.is_file() or not current.resolve().is_relative_to(Path(root).resolve()):
        raise InvalidEvidence("missing file")
    return current


def text(value, minimum=12):
    if not isinstance(value, str) or not minimum <= len(value.strip()) <= 4000:
        raise InvalidEvidence("missing substantive declaration")


def validate(root, repository, pr_number, expected, document):
    """expected is the trusted metadata set, not a consumer declaration."""
    if not isinstance(document, dict) or set(document) != {"version", "repository", "pull_request", "findings"}:
        raise InvalidEvidence("invalid manifest fields")
    if type(document["version"]) is not int or document["version"] != 1 or document["repository"] != repository or type(document["pull_request"]) is not int or document["pull_request"] != pr_number:
        raise InvalidEvidence("manifest identity mismatch")
    entries = document["findings"]
    if not isinstance(entries, list) or len(entries) > MAX_FINDINGS:
        raise InvalidEvidence("invalid findings list")
    found = set()
    manual = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise InvalidEvidence("invalid finding")
        number = entry.get("issue")
        if type(number) is not int or number <= 0 or number in found:
            raise InvalidEvidence("invalid or duplicate issue")
        found.add(number)
        mode = entry.get("mode")
        shared = {"issue", "mode", "review_url", "affected_head", "summary"}
        text(entry.get("summary"))
        import re
        url = entry.get("review_url")
        if not isinstance(url, str) or not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:pull|issues)/[1-9][0-9]*(?:#[A-Za-z0-9_-]+)?", url):
            raise InvalidEvidence("invalid review reference")
        if not re.fullmatch(r"[0-9a-f]{40}", str(entry.get("affected_head", ""))):
            raise InvalidEvidence("invalid affected head")
        if mode == "automated":
            if set(entry) != shared | {"regression_paths", "workflow", "command", "negative_control", "pass_evidence"}:
                raise InvalidEvidence("invalid automated fields")
            paths = entry["regression_paths"]
            if not isinstance(paths, list) or not 1 <= len(paths) <= 20 or not all(isinstance(x, str) for x in paths) or len(set(paths)) != len(paths):
                raise InvalidEvidence("invalid regression paths")
            for path in paths:
                safe_file(root, path)
            workflow = entry["workflow"]
            if not isinstance(workflow, str) or not workflow.startswith(".github/workflows/") or not workflow.endswith((".yml", ".yaml")):
                raise InvalidEvidence("invalid workflow reference")
            safe_file(root, workflow)
            for field in ("command", "negative_control", "pass_evidence"):
                text(entry[field])
        elif mode == "manual-limit":
            if set(entry) != shared | {"reason", "checklist", "owner", "remaining_automation"}:
                raise InvalidEvidence("invalid manual fields")
            for field in ("reason", "owner", "remaining_automation"):
                text(entry[field])
            checklist = entry["checklist"]
            if not isinstance(checklist, list) or not 1 <= len(checklist) <= 20:
                raise InvalidEvidence("invalid manual checklist")
            for item in checklist:
                text(item)
            manual += 1
        else:
            raise InvalidEvidence("invalid mode")
    if found != set(expected):
        raise InvalidEvidence("finding mappings differ from linked issues")
    return {"findings": len(found), "manual_limits": manual}
