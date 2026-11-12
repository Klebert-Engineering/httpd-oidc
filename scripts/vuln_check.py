#!/usr/bin/env python3
"""Daily vulnerability check for the httpd-oidc image.

Sources:
  * Apache's own advisory data (vulnerabilities-httpd.json) for httpd itself,
    matched against the httpd version running in the image.
  * A Grype JSON report of the image for OS packages (Debian), limited to
    findings with a fix available at or above a severity threshold.

The result is written as Markdown. With --issue it is synced to a single GitHub
issue (label `vulnerability-scan`): opened or updated while there are findings,
closed when everything is clear. Requires the `gh` CLI and GH_TOKEN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.request

APACHE_JSON = "https://httpd.apache.org/security/vulnerabilities-httpd.json"
APACHE_PAGE = "https://httpd.apache.org/security/vulnerabilities_24.html"
DOCKER_HUB_TAGS = "https://hub.docker.com/v2/repositories/library/httpd/tags?page_size=100&name=2.4."
LABEL = "vulnerability-scan"
MAX_ROWS = 100  # keeps the issue body below GitHub's size limit
SEVERITY_ORDER =["negligible", "low", "moderate", "medium", "important", "high", "critical"]


def parse_version(text: str) -> tuple[int, ...]:
    """'2.4.58' -> (2, 4, 58); '2.4' -> (2, 4, 0); '0' -> (0, 0, 0)."""
    nums = [int(n) for n in re.findall(r"\d+", text)[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "httpd-oidc-vuln-check"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def affected_v5(record: dict, version: tuple[int, ...]) -> bool:
    for product in record["containers"]["cna"].get("affected", []):
        if product.get("product") != "Apache HTTP Server":
            continue
        for v in product.get("versions", []):
            if v.get("status") != "affected":
                continue
            low = parse_version(v.get("version", "0"))
            if "lessThanOrEqual" in v:
                if low <= version <= parse_version(v["lessThanOrEqual"]):
                    return True
            elif "lessThan" in v:
                if low <= version < parse_version(v["lessThan"]):
                    return True
            elif version == low:
                return True
    return False


def affected_v4(record: dict, version: tuple[int, ...]) -> bool:
    for vendor in record["affects"]["vendor"]["vendor_data"]:
        for product in vendor["product"]["product_data"]:
            if product.get("product_name") != "Apache HTTP Server":
                continue
            data = product["version"]["version_data"]
            exact = {parse_version(v["version_value"]) for v in data if v["version_affected"] in ("=", "?=")}
            lows = [parse_version(v["version_value"]) for v in data if v["version_affected"] in (">=", "!<")]
            highs = [v for v in data if v["version_affected"] == "<="]
            if version in exact:
                return True
            for high in highs:
                # "Apache HTTP Server 2.4" / "2.4" names the branch; bound the range to it.
                branch = re.search(r"\d+\.\d+", high.get("version_name", ""))
                low = max(lows + [parse_version(branch.group(0)) if branch else (0, 0, 0)])
                if low <= version <= parse_version(high["version_value"]):
                    return True
    return False


def apache_findings(version_text: str, records: list[dict]) -> list[dict]:
    version = parse_version(version_text)
    findings = []
    for rec in records:
        if "containers" in rec:
            if not affected_v5(rec, version):
                continue
            cna = rec["containers"]["cna"]
            cve = rec["cveMetadata"]["cveId"]
            title = cna.get("title", "")
            severity = next((m.get("other", {}).get("content", {}).get("text") for m in cna.get("metrics", [])), "unknown")
        elif "affects" in rec:
            if not affected_v4(rec, version):
                continue
            cve = rec["CVE_data_meta"]["ID"]
            title = rec["CVE_data_meta"].get("TITLE", "")
            impact = rec.get("impact") or [{}]
            severity = (impact[0] if isinstance(impact, list) else impact).get("other", "unknown")
        else:
            continue
        findings.append({"id": cve, "severity": str(severity).lower(), "title": title})
    return sorted(findings, key=lambda f: (-severity_rank(f["severity"]), f["id"]))


def severity_rank(severity: str) -> int:
    s = severity.lower()
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else -1


def grype_findings(path: str, min_severity: str) -> list[dict]:
    with open(path) as fh:
        report = json.load(fh)
    threshold = severity_rank(min_severity)
    seen, findings = set(), []
    for match in report.get("matches", []):
        vuln, art = match["vulnerability"], match["artifact"]
        if vuln.get("fix", {}).get("state") != "fixed":
            continue
        if severity_rank(vuln.get("severity", "")) < threshold:
            continue
        key = (vuln["id"], art["name"], art["version"])
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "id": vuln["id"],
            "severity": vuln["severity"].lower(),
            "package": art["name"],
            "type": art.get("type", ""),
            "installed": art["version"],
            "fixed": ", ".join(vuln["fix"].get("versions", [])),
        })
    return sorted(findings, key=lambda f: (-severity_rank(f["severity"]), f["package"], f["id"]))


def latest_httpd_tag() -> str | None:
    try:
        tags = fetch_json(DOCKER_HUB_TAGS)["results"]
    except Exception as exc:  # informational only
        print(f"warning: could not read Docker Hub tags: {exc}", file=sys.stderr)
        return None
    versions = [t["name"] for t in tags if re.fullmatch(r"2\.4\.\d+", t["name"])]
    return max(versions, key=parse_version) if versions else None


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def dependabot_httpd_pr() -> dict | None:
    try:
        prs = json.loads(gh("pr", "list", "--state", "open", "--author", "app/dependabot",
                            "--search", "httpd in:title", "--json", "number,url,title"))
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return prs[0] if prs else None


def render(args, httpd: list[dict], packages: list[dict], latest: str | None, pr: dict | None) -> str:
    lines = [f"Daily scan of `{args.image}` (httpd {args.httpd_version}) found "
             f"{len(httpd)} httpd advisories and {len(packages)} fixable package vulnerabilities "
             f"({args.min_severity} or higher).", ""]
    if httpd or packages:
        lines += ["## What to do", ""]
    if httpd:
        target = f"`httpd:{latest}`" if latest else "the latest `httpd:2.4.x` tag"
        if pr:
            lines.append(f"1. Merge the Dependabot PR #{pr['number']} ({pr['title']}), which moves the base image to the new httpd.")
        else:
            lines.append(f"1. Change `FROM` in the `Dockerfile` to {target} and merge the PR.")
        lines.append("2. The Build workflow publishes the new image on merge to `main`; then pull and restart the proxies.")
    if packages and not httpd:
        lines.append("1. Run the Build workflow on `main` (Actions → Build → Run workflow). The rebuild installs the fixed Debian packages and republishes the image.")
        lines.append("2. Pull and restart the proxies.")
    if httpd:
        lines += ["", f"## httpd advisories (source: [Apache]({APACHE_PAGE}))", "",
                  "| CVE | Severity | Title |", "|---|---|---|"]
        lines += [f"| [{f['id']}]({APACHE_PAGE}#{f['id']}) | {f['severity']} | {f['title']} |" for f in httpd]
    if packages:
        lines += ["", "## Image packages with a fix available (source: Grype)", "",
                  "| Vulnerability | Severity | Package | Installed | Fixed in |", "|---|---|---|---|---|"]
        lines += [f"| {f['id']} | {f['severity']} | {f['package']} ({f['type']}) | {f['installed']} | {f['fixed']} |"
                  for f in packages[:MAX_ROWS]]
        if len(packages) > MAX_ROWS:
            lines.append(f"\n… and {len(packages) - MAX_ROWS} more, listed in the Security tab.")
    if args.run_url:
        lines += ["", f"Scan run: {args.run_url} — full Grype results are in the Security tab (code scanning)."]
    return "\n".join(lines)


def fingerprint(httpd: list[dict], packages: list[dict]) -> str:
    ids = sorted({f["id"] for f in httpd} | {f"{f['id']}:{f['package']}" for f in packages})
    return hashlib.sha256("\n".join(ids).encode()).hexdigest()[:16]


def sync_issue(args, body: str, fp: str, httpd: list[dict], packages: list[dict]) -> None:
    gh("label", "create", LABEL, "--force", "--color", "B60205",
       "--description", "Opened by the daily vulnerability scan")
    issues = json.loads(gh("issue", "list", "--label", LABEL, "--state", "open", "--json", "number,body"))
    issue = issues[0] if issues else None
    mention = " ".join(f"@{u}" for u in args.notify if u)
    marker = f"<!-- fingerprint: {fp} -->"

    if not httpd and not packages:
        if issue:
            gh("issue", "close", str(issue["number"]), "--comment",
               "The latest scan found nothing that needs action. Closing.")
            print(f"closed issue #{issue['number']}")
        else:
            print("no findings, no open issue")
        return

    worst = max([f["severity"] for f in httpd + packages], key=severity_rank)
    title = f"Vulnerability scan: {len(httpd) + len(packages)} finding(s), highest severity {worst}"
    full_body = f"{body}\n\n{marker}\n"
    if issue is None:
        cmd = ["issue", "create", "--title", title, "--label", LABEL, "--body", full_body]
        for user in args.notify:
            if user:
                cmd += ["--assignee", user]
        url = gh(*cmd).strip()
        number = url.rsplit("/", 1)[-1]
        if mention:
            gh("issue", "comment", number, "--body", f"{mention} the daily vulnerability scan needs your attention.")
        print(f"opened issue {url}")
        return

    number = str(issue["number"])
    gh("issue", "edit", number, "--title", title, "--body", full_body)
    if marker not in (issue.get("body") or ""):
        # Editing the body sends no notification; a comment does.
        gh("issue", "comment", number, "--body",
           f"{mention} the findings changed: {title}. The issue description is updated.".strip())
        print(f"updated issue #{number} (findings changed)")
    else:
        print(f"updated issue #{number} (findings unchanged)")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--httpd-version", required=True, help="httpd version running in the image, e.g. 2.4.71")
    p.add_argument("--image", required=True, help="image reference, for the report")
    p.add_argument("--grype", help="Grype JSON report of the image")
    p.add_argument("--apache-json", help="local copy of vulnerabilities-httpd.json (default: download)")
    p.add_argument("--min-severity", default="high", help="minimum Grype severity to report (default: high)")
    p.add_argument("--notify", default="", help="comma-separated GitHub logins to assign and mention")
    p.add_argument("--run-url", default="", help="link to the workflow run, for the report")
    p.add_argument("--issue", action="store_true", help="sync the result to the GitHub issue")
    args = p.parse_args()
    args.notify = [u.strip() for u in args.notify.split(",")]

    if args.apache_json:
        with open(args.apache_json) as fh:
            records = json.load(fh)
    else:
        records = fetch_json(APACHE_JSON)
    httpd = apache_findings(args.httpd_version, records)
    packages = grype_findings(args.grype, args.min_severity) if args.grype else []
    latest = latest_httpd_tag() if httpd else None
    pr = dependabot_httpd_pr() if httpd and args.issue else None

    body = render(args, httpd, packages, latest, pr)
    print(body)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(body + "\n")
    if args.issue:
        sync_issue(args, body, fingerprint(httpd, packages), httpd, packages)
    return 0


if __name__ == "__main__":
    sys.exit(main())
