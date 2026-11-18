"""Read-only GitHub metadata adapter for the review-findings gate."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from repo_checks.review_findings import (  # noqa: E402
    InvalidEvidence, MAX_BYTES, MAX_FINDINGS, read_json, safe_file, validate,
)


class Github:
    def __init__(self, repository, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise InvalidEvidence("invalid repository")
        self.repository = repository
        self.token = token
        self.calls = 0

    def get(self, endpoint):
        self.calls += 1
        if self.calls > MAX_FINDINGS + 4:
            raise InvalidEvidence("API request bound")
        url = "https://api.github.com/repos/" + self.repository + endpoint
        request = urllib.request.Request(url, headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        # No redirects, retries, external hosts or consumer-selected API root.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        with urllib.request.build_opener(NoRedirect).open(request, timeout=20) as response:
            if response.headers.get("Link"):
                raise InvalidEvidence("paginated metadata exceeds bound")
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise InvalidEvidence("metadata exceeds bound")
        return json.loads(raw)


def issue_references(repository, bodies):
    refs = set()
    for body in bodies:
        if not isinstance(body, str) or len(body) > MAX_BYTES:
            raise InvalidEvidence("invalid metadata body")
        refs.update(int(n) for n in re.findall(r"(?<![A-Za-z0-9_/])#([1-9][0-9]*)\b", body))
        for repo, number in re.findall(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/issues/([1-9][0-9]*)", body):
            if repo == repository:
                refs.add(int(number))
    if len(refs) > MAX_FINDINGS:
        raise InvalidEvidence("referenced issue bound")
    return refs


def collect(api, pr_number):
    pr = api.get("/pulls/" + str(pr_number))
    comments = api.get("/issues/" + str(pr_number) + "/comments?per_page=100")
    reviews = api.get("/pulls/" + str(pr_number) + "/reviews?per_page=100")
    if not isinstance(comments, list) or not isinstance(reviews, list):
        raise InvalidEvidence("invalid API lists")
    bodies = [pr.get("body") or ""] + [x.get("body") or "" for x in comments + reviews]
    findings = set()
    for number in sorted(issue_references(api.repository, bodies)):
        issue = api.get("/issues/" + str(number))
        if "pull_request" in issue:
            continue
        if any(label.get("name", "").lower() == "review-finding" for label in issue.get("labels", [])):
            findings.add(number)
    return findings, pr


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--head", required=True)
    args = parser.parse_args(argv)
    try:
        if args.pr <= 0 or not re.fullmatch(r"[0-9a-f]{40}", args.head):
            raise InvalidEvidence("invalid PR identity")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            raise InvalidEvidence("missing read token")
        findings, pr = collect(Github(args.repository, token), args.pr)
        if pr.get("head", {}).get("sha") != args.head:
            raise InvalidEvidence("head moved; rerun current head")
        path = "docs/review-findings/pr-" + str(args.pr) + ".json"
        candidate = Path(args.root) / path
        if not candidate.exists() and not candidate.is_symlink():
            if findings:
                raise InvalidEvidence("missing evidence manifest")
            # Explicit acknowledgement avoids a silent adoption pass.
            if "Review-findings: none" not in (pr.get("body") or ""):
                raise InvalidEvidence("declare findings or explicit none")
            result = {"findings": 0, "manual_limits": 0}
        else:
            result = validate(args.root, args.repository, args.pr, findings,
                              read_json(safe_file(args.root, path)))
        print("review-findings: pass; mapped=" + str(result["findings"]) + "; manual=" + str(result["manual_limits"]))
        return 0
    except (InvalidEvidence, ValueError, TypeError, KeyError, AttributeError, OSError, urllib.error.URLError):
        print("review-findings: fail; check manifest, links, labels, identity and metadata bounds")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
