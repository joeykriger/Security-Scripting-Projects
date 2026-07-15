"""
©AngelaMos | 2026
http_headers_scanner.py

Scan a URL and grade its HTTP security headers A–F

When a browser asks a website for a page, the server sends back the
page itself PLUS a bunch of metadata called "HTTP response headers."
Some of those headers are security-critical: they tell the browser
"only talk to me over HTTPS," "do not let other sites embed me in
an iframe," "ignore guesses about file types," and more

If a website forgets these headers, real attacks become easier:
clickjacking, MIME-sniffing, mixed-content downgrades, XSS that
otherwise would have been stopped by a good Content-Security-Policy.
This script connects to a URL, pulls the headers, and tells you which
ones are missing or weak

────────────────────────────────────────────────────────────────────
The headers we care about
────────────────────────────────────────────────────────────────────
  Strict-Transport-Security  forces HTTPS for return visits
  Content-Security-Policy    controls which scripts/styles may load
  X-Content-Type-Options     disables MIME-sniffing
  X-Frame-Options            controls iframe embedding (clickjacking)
  Referrer-Policy            limits Referer leakage
  Permissions-Policy         disables browser features the page does
                             not need (camera, microphone, etc.)

Each rule has a severity (high / medium / low). The score is the
percentage of weighted points the site earned. The grade comes from
the score: 90+ A, 80+ B, 70+ C, 60+ D, otherwise F. This mirrors the
model used by the Mozilla Observatory

────────────────────────────────────────────────────────────────────
What this script does NOT do
────────────────────────────────────────────────────────────────────
  - It does not crawl the site, only the URL you give it
  - It does not parse complex CSP directives (just checks presence)
  - It does not test for actual XSS or open redirects

This is foundational: learn the headers, then graduate to bigger
tools like Mozilla Observatory or `securityheaders.com`

────────────────────────────────────────────────────────────────────
What this file exposes
────────────────────────────────────────────────────────────────────
  HeaderRule        — one rule (header name, severity, description, ...)
  HeaderFinding     — the result of evaluating one rule
  ScanReport        — full report (url, status_code, findings, score, grade)
  evaluate_header() — run one rule against a set of headers
  scan()            — fetch a URL and run every rule
  main()            — CLI entry point used by `headers <url>`
"""

# Standard library: parse command-line flags like `--timeout 5` into
# a tidy object so we do not have to slice `sys.argv` by hand.
import argparse
# Standard library: JSON serialization for machine-readable output
import json
# Standard library: regular expressions — we use `re.search` to match
# header values against rule patterns (e.g. `max-age\s*=\s*[1-9]` for
# HSTS, which must reject `max-age=0`).
import re
# Standard library: access to interpreter internals — we use it for
# stderr writes and to exit the process with a specific status code.
import sys
# Standard library: a decorator that turns a class into a small,
# immutable data record without writing `__init__` boilerplate.
from dataclasses import asdict, dataclass
# Standard library: a type hint that pins a value to a small fixed
# set of strings (here: severity levels like "good"/"warn"). Mypy
# catches typos.
from typing import Literal

# Third-party (httpx): the HTTP client that actually fetches the URL.
# Modern replacement for `requests` — supports timeouts and HTTP/2.
import httpx
# Third-party (rich): the printer that draws colored output to the
# terminal, with full Unicode and width handling.
from rich.console import Console
# Third-party (rich): draws a bordered box around content — we use
# it for the summary banner at the top of the report.
from rich.panel import Panel
# Third-party (rich): builds the colored ASCII table that lists each
# header finding with its severity.
from rich.table import Table

# CHALLENGE 6
import hashlib
import time
from pathlib import Path

# CHALLENGE 8
import asyncio

# CHALLENGE 6
CACHE_DIR = Path.home() / ".cache" / "http-headers-scanner"
CACHE_TTL_SECONDS = 60 * 60


# =============================================================================
# Severity type — three valid values
# =============================================================================
# Literal["high", "medium", "low"] is a type hint that says "this string
# can ONLY be one of these three values." Mypy will catch typos like
# "hgih" at edit time. We chose Literal over an Enum because Carter's
# style guide prefers Literals for small fixed sets

Severity = Literal["high", "medium", "low"]
Status = Literal["ok", "weak", "missing"]


# =============================================================================
# HeaderRule — one rule we evaluate against the response
# =============================================================================


@dataclass(frozen = True, slots = True)
class HeaderRule:
    """
    A single security-header check

    `frozen=True` makes the dataclass immutable — once created, its
    fields cannot change. `slots=True` makes instances lightweight in
    memory. Together these two flags create a clean "value object"

    Fields
    ------
    header
        The HTTP header name to look for (case-insensitive)
    severity
        How important the header is. Drives the point value below
    description
        One sentence explaining what the header does. Shown in output
    recommendation
        Concrete fix the user should apply if the header is missing
    must_match
        Optional regex pattern (case-insensitive) the value MUST match.
        Use a plain word for substring matching (e.g. ``nosniff``), or a
        real regex for stricter checks. Example: ``max-age\\s*=\\s*[1-9]``
        requires ``max-age`` to be a positive integer, which rejects the
        actively-harmful ``max-age=0``. If this is set and the value
        does not match, we report `weak` instead of `ok`
    """
    header: str
    severity: Severity
    description: str
    recommendation: str
    must_match: str | None = None


# =============================================================================
# The rules table — single source of truth for what we check
# =============================================================================
# Adding a header to this list is the only change needed to extend
# the scanner. The check logic is generic — it walks this list at
# runtime and applies each rule the same way

RULES: list[HeaderRule] = [
    HeaderRule(
        header = "Strict-Transport-Security",
        severity = "high",
        description = (
            "Tells the browser to ONLY connect over HTTPS for the "
            "next N seconds, defeating SSL-stripping attacks"
        ),
        recommendation = (
            "Add: Strict-Transport-Security: "
            "max-age=31536000; includeSubDomains"
        ),
        # Require max-age to be a positive integer — `max-age=0`
        # actively disables HSTS, so we must reject it. The regex
        # accepts whitespace around `=` to tolerate `max-age = 60`.
        must_match = r"max-age\s*=\s*[1-9]",
    ),
    HeaderRule(
        header = "Content-Security-Policy",
        severity = "high",
        description = (
            "Controls which scripts, styles, frames, and connections "
            "the browser may load — the strongest XSS defense"
        ),
        recommendation = (
            "Add a Content-Security-Policy that disallows "
            "'unsafe-inline' and limits sources to trusted origins"
        ),
    ),
    HeaderRule(
        header = "X-Content-Type-Options",
        severity = "medium",
        description = (
            "Stops browsers from second-guessing the Content-Type "
            "and treating a .txt file as HTML — defeats MIME-sniffing"
        ),
        recommendation = "Add: X-Content-Type-Options: nosniff",
        # Value must literally be `nosniff`; anything else is broken.
        # `re.search("nosniff", ...)` is a substring match here — no
        # special regex characters in the pattern.
        must_match = "nosniff",
    ),
    HeaderRule(
        header = "X-Frame-Options",
        severity = "medium",
        description = (
            "Prevents another site from embedding this page in an "
            "iframe, defeating clickjacking attacks"
        ),
        recommendation = (
            "Add: X-Frame-Options: DENY (or use "
            "Content-Security-Policy: frame-ancestors 'none')"
        ),
    ),
    HeaderRule(
        header = "Referrer-Policy",
        severity = "low",
        description = (
            "Limits how much of the current URL leaks to other sites "
            "when the user clicks an outbound link"
        ),
        recommendation = (
            "Add: Referrer-Policy: strict-origin-when-cross-origin"
        ),
    ),
    HeaderRule(
        header = "Permissions-Policy",
        severity = "low",
        description = (
            "Disables browser features the page does not use "
            "(camera, microphone, geolocation, payments, etc.)"
        ),
        recommendation = (
            "Add: Permissions-Policy: "
            "camera=(), microphone=(), geolocation=()"
        ),
    ),
    HeaderRule(
        header = "Cross-Origin-Opener-Policy",
        severity = "medium",
        description = (
            "Prevents the page from being interacted with by other origins via window.opener",
        ),
        recommendation = (
            "TEST"
        ),
        must_match = "same-origin",
    )
]


# =============================================================================
# Severity → points. Drives the final score
# =============================================================================
# Each present-and-correct header earns its full points; weak presence
# earns half points; missing earns zero. Total achievable = sum of
# all rule points. The score is (earned / total) * 100, rounded

SEVERITY_POINTS: dict[Severity,
                      int] = {
                          "high": 30,
                          "medium": 15,
                          "low": 5,
                      }


# =============================================================================
# HeaderFinding — the result of evaluating one rule
# =============================================================================


@dataclass(frozen = True, slots = True)
class HeaderFinding:
    """
    Outcome of running one HeaderRule against the response headers

    Fields
    ------
    rule
        The rule we evaluated. Carrying it inside the finding means
        the renderer never has to look up the rule again
    status
        "ok"      — header is present and (if applicable) the value
                    matches must_match
        "weak"    — header is present but the value is wrong
        "missing" — header is not in the response at all
    actual_value
        Whatever the server actually sent for this header, or None
        when the header was missing entirely
    note
        Short human-readable explanation. Shown in the table next
        to the status column
    """
    rule: HeaderRule
    status: Status
    actual_value: str | None
    note: str


# =============================================================================
# ScanReport — the full result returned by scan()
# =============================================================================


@dataclass(frozen = True, slots = True)
class ScanReport:
    """
    A full scan result for one URL

    The `score` and `grade` properties are computed on demand from
    the findings, so they always reflect whatever the rules table
    looked like at scan time
    """
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding]
    raw_headers: dict[str, str]

    @property
    def score(self) -> int:
        """
        Return a 0–100 score reflecting the weighted findings

        Formula
        -------
            earned = full points for every "ok"
                   + half points for every "weak"
                   + zero  for every "missing"
            score  = round(earned / total * 100)
        """
        total = sum(SEVERITY_POINTS[r.severity] for r in RULES)
        # Guard against an empty rules table — would only matter if
        # someone deletes RULES while testing. Keeps the code total
        if total == 0:
            return 0

        earned = 0.0
        for finding in self.findings:
            full = SEVERITY_POINTS[finding.rule.severity]
            if finding.status == "ok":
                earned += full
            elif finding.status == "weak":
                earned += full / 2
            # "missing" earns 0 — no else branch needed

        # Round-half-up via int(x + 0.5) avoids Python's banker's
        # rounding, which would map round(0.5) -> 0 and round(2.5) -> 2
        # — surprising for a score that should always round up at the
        # .5 boundary
        return int((earned / total) * 100 + 0.5)

    @property
    def grade(self) -> str:
        """
        Map the score to a letter grade A–F
        """
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"


# =============================================================================
# Header evaluation — pure function, no I/O
# =============================================================================
# Splitting this out from scan() makes it trivially testable: pass in
# a rule and a dict of headers, get back a finding. No network needed


def evaluate_header(
    rule: HeaderRule,
    response_headers: dict[str,
                           str],
) -> HeaderFinding:
    """
    Apply a single HeaderRule to a set of response headers

    HTTP header names are case-insensitive per RFC 7230 — `HSTS` and
    `hsts` and `Hsts` are the same header. We normalize both sides
    to lowercase before comparing
    """
    target = rule.header.lower()

    # Walk the response headers manually instead of building a
    # case-insensitive dict. The input is always a plain dict here —
    # scan() converts httpx's Headers object before calling us, so
    # tests can pass any dict[str, str] without ceremony
    actual_value: str | None = None
    for name, value in response_headers.items():
        if name.lower() == target:
            actual_value = value
            break

    if actual_value is None:
        return HeaderFinding(
            rule = rule,
            status = "missing",
            actual_value = None,
            note = f"Header `{rule.header}` is not set",
        )

    # If the rule has no must_match check, presence is enough
    if rule.must_match is None:
        return HeaderFinding(
            rule = rule,
            status = "ok",
            actual_value = actual_value,
            note = "Present",
        )

    # Otherwise verify the value matches the required pattern.
    # re.search finds the pattern anywhere in the string — for a plain
    # word like `nosniff` that behaves as a substring check; for a
    # real regex like `max-age\s*=\s*[1-9]` it enforces a richer
    # condition (positive integer after `max-age=`)
    if re.search(rule.must_match, actual_value, re.IGNORECASE):
        return HeaderFinding(
            rule = rule,
            status = "ok",
            actual_value = actual_value,
            note = f"Present and matches `{rule.must_match}`",
        )

    return HeaderFinding(
        rule = rule,
        status = "weak",
        actual_value = actual_value,
        note = (
            f"Present but does not match `{rule.must_match}` "
            f"(got `{actual_value}`)"
        ),
    )


# =============================================================================
# scan() — fetch the URL and apply every rule
# =============================================================================


# A polite, identifiable User-Agent. Some servers block requests with
# the default httpx UA or no UA at all
DEFAULT_USER_AGENT: str = (
    "http-headers-scanner/1.0 "
    "(+https://github.com/CarterPerez-dev/Cybersecurity-Projects)"
)


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    user_agent: str = DEFAULT_USER_AGENT,
    no_cache: bool = False,  # CHALLENGE 6
) -> ScanReport:
    """
    Fetch `url` once and grade its response headers

    Parameters
    ----------
    url
        Full URL including the scheme. Bare hostnames like
        "example.com" are NOT supported because we cannot guess
        whether the user wanted http or https
    timeout
        Seconds before we give up on a slow server. Default 10
    user_agent
        Sent as the User-Agent header. Some sites serve different
        responses to bots; the default identifies us honestly

    Returns
    -------
    ScanReport
        Containing the findings, status code, and final URL after
        any redirects

    Raises
    ------
    httpx.RequestError
        On DNS failure, connection refusal, timeout, etc. The CLI
        catches these to print a clean error message
    """
    if not no_cache: # CHALLENGE 6
        cached = _load_cached_report(url)
        if cached is not None:
            return cached

    # follow_redirects=True means http://example.com → https://example.com
    # is followed automatically. We grade the FINAL URL, not the first
    # one, because that is the one users actually see
    response = httpx.get(
        url,
        timeout = timeout,
        follow_redirects = True,
        headers = {"User-Agent": user_agent},
    )

    # httpx Headers object behaves like a dict for our purposes.
    # dict(response.headers) gives us a regular dict[str, str]
    response_headers = dict(response.headers)

    # Run every rule against the response. List comprehension is
    # cleaner than a for-loop with .append() here
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    report = ScanReport( # CHALLENGE 6
        url = url,
        final_url = str(response.url),
        status_code = response.status_code,
        findings = findings,
        raw_headers = response_headers,
    )

    _save_cached_report(report, url)  # CHALLENGE 6
    return report


# CHALLENGE 8
async def scan_async(
        url: str,
        *,
        timeout: float = 10.0,
        user_agent: str = DEFAULT_USER_AGENT,
        no_cache: bool = False,
) -> ScanReport:
    if not no_cache:
        cached = _load_cached_report(url)
        if cached is not None:
            return cached
        
    async with httpx.AsyncClient() as client:
        response = await client.get(
            url,
            timeout = timeout,
            follow_redirects = True,
            headers = {"User-Agent": user_agent},
        )

    response_headers = dict(response.headers)
    findings = [evaluate_header(rule, response_headers) for rule in RULES]

    report = ScanReport(
        url = url,
        final_url = str(response.url),
        status_code = response.status_code,
        findings = findings,
        raw_headers = response_headers,
    )

    _save_cached_report(report, url)
    return report


# CHALLENGE 8
async def run_many(urls: list[str], timeout: float, no_cache: bool) -> list[ScanReport]:
    semaphore = asyncio.Semaphore(20)

    async def bounded_scan(url: str) -> ScanReport:
        async with semaphore:
            return await scan_async(url, timeout = timeout, no_cache = no_cache)
        
    tasks = [bounded_scan(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions = True)
    return results


# =============================================================================
# CLI rendering — keeps display logic out of the data layer
# =============================================================================


# How each status / severity should be colored in the terminal
STATUS_COLORS: dict[Status,
                    str] = {
                        "ok": "green",
                        "weak": "yellow",
                        "missing": "red",
                    }

GRADE_COLORS: dict[str,
                   str] = {
                       "A": "bright_green",
                       "B": "green",
                       "C": "yellow",
                       "D": "red",
                       "F": "bright_red",
                   }

GRADE_RANK: dict[str, int] = {  # CHALLENGE 5
    "A": 5,
    "B": 4,
    "C": 3,
    "D": 2,
    "F": 1,
}

def _grade_rank(grade: str) -> int:  # CHALLENGE 5
    return GRADE_RANK[grade]


def _cache_path(url: str) -> Path:  # CHALLENGE 6
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return CACHE_DIR / f"{digest}.json"


def _save_cached_report(report: ScanReport, url: str) -> None: # CHALLENGE 6
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = asdict(report)
    payload["saved_at"] = time.time()
    _cache_path(url).write_text(json.dumps(payload, indent=2))


def _load_cached_report(url: str) -> ScanReport | None: # CHALLENGE 6
    path = _cache_path(url)
    if not path.exists():
        return None
    
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    
    if time.time() - payload.get("saved_at", 0) > CACHE_TTL_SECONDS:
        return None

    return _rebuild_report_from_payload(payload)


def _rebuild_report_from_payload(payload: dict) -> ScanReport: # CHALLENGE 6
    findings = []
    for item in payload["findings"]:
        rule_data = item["rule"]
        rule = HeaderRule(
            header=rule_data["header"],
            severity=rule_data["severity"],
            description=rule_data["description"],
            recommendation=rule_data["recommendation"],
            must_match=rule_data.get("must_match"),
        )
        findings.append(
            HeaderFinding(
                rule=rule,
                status=item["status"],
                actual_value=item.get("actual_value"),
                note=item["note"],
            )
        )
    return ScanReport(
        url=payload["url"],
        final_url=payload["final_url"],
        status_code=payload["status_code"],
        findings=findings,
        raw_headers=payload["raw_headers"],
    )


def _render_report(report: ScanReport, console: Console, verbose: bool = False) -> None:
    """
    Print the scan report as a rich table plus a grade panel
    """
    if verbose:
        console.print("[bold]Raw response headers:[/bold]")
        for name in sorted(report.raw_headers):
            console.print(f"{name}: {report.raw_headers[name]}")

    # The header table — one row per rule
    table = Table(
        title = (
            f"Headers for {report.final_url} "
            f"(HTTP {report.status_code})"
        ),
        title_style = "bold cyan",
        show_lines = False,
    )
    table.add_column("header", style = "bold white", no_wrap = True)
    table.add_column("status", no_wrap = True)
    table.add_column("severity", no_wrap = True)
    table.add_column("note", style = "dim")

    for finding in report.findings:
        status_color = STATUS_COLORS[finding.status]
        table.add_row(
            finding.rule.header,
            f"[{status_color}]{finding.status}[/{status_color}]",
            finding.rule.severity,
            finding.note,
        )
    console.print(table)

    # Browsers IGNORE HSTS received over plain HTTP per RFC 6797 §8.1
    # — if the final response was served over http://, any HSTS grade
    # above is misleading. Warn so the user does not walk away with a
    # false sense of security
    if report.final_url.startswith("http://"):
        console.print(
            "[yellow]Note:[/yellow] this response was served over plain "
            "HTTP. Browsers IGNORE HSTS over HTTP, so any HSTS grade "
            "above is misleading until the site enforces HTTPS"
        )

    # CHALLENGE 7
    if (
        report.url.startswith("http://")
        and report.final_url.startswith("https://")
    ):
        console.print(
            "[yellow]Note:[/yellow] this URL started as HTTP and was upgraded "
            "to HTTPS via redirect. Without HSTS, the first request is "
            "vulnerable to interception."
        )

    # The grade panel — big, color-coded, eye-catching
    grade_color = GRADE_COLORS[report.grade]
    panel = Panel(
        f"[bold {grade_color}]Grade: {report.grade}[/bold {grade_color}]\n"
        f"Score: {report.score} / 100",
        title = "Result",
        border_style = grade_color,
    )
    console.print(panel)

    # Print recommendations for any non-ok findings, so the user has
    # an action list — what to add or fix
    actionable = [f for f in report.findings if f.status != "ok"]
    if actionable:
        console.print("\n[bold]Recommendations:[/bold]")
        for finding in actionable:
            console.print(
                f"  • [yellow]{finding.rule.header}[/yellow] "
                f"— {finding.rule.recommendation}"
            )


# =============================================================================
# argparse plumbing — broken out so tests can call it directly
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    """
    Construct the argparse parser used by main()
    """
    parser = argparse.ArgumentParser(
        prog = "headers",
        description = (
            "Scan a URL for HTTP security headers and grade the result A–F."
        ),
    )
    parser.add_argument(
        "urls",    # CHALLENGE 4
        nargs = "+",    # CHALLENGE 4
        help = "One or more full URL to scan (must include http:// or https://).",
    )
    parser.add_argument(
        "--timeout",
        type = float,
        default = 10.0,
        help =
        "Seconds to wait before giving up on the request (default: 10).",
    )
    parser.add_argument(
        "--json",
        action = "store_true",
        help = "Output results as JSON instead of a formatted table.",
    )
    parser.add_argument(
        "--verbose",
        action = "store_true",
        help = "Print raw response headers above the report.",
    )
    parser.add_argument(    # CHALLENGE 5
        "--min-grade",
        choices = ["A", "B", "C", "D", "F"],
        default = "C",
        help = "Lowest grade that should still exit successfully (default: C).",
    )
    parser.add_argument(    # CHALLENGE 6
        "--no-cache",
        action="store_true",
        help="Bypass the on-disk cache and force a fresh scan.",
    )

    return parser


# =============================================================================
# main() — exit codes mean something
# =============================================================================
# 0 → grade A or B (green light for CI)
# 1 → grade C or D (warn but do not fail by default)
# 2 → grade F or network error (fail loudly)


def main() -> int:
    """
    CLI entry point — return an exit code reflecting the scan result
    """
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    async def run_cli() -> int:    # CHALLENGE 8
        try:
            reports = await run_many(
                args.urls,
                timeout = args.timeout,
                no_cache = args.no_cache,
            )
        except httpx.RequestError as exc:
            console.print(f"[red]Request failed[/red]: {exc}")
            return 2

        for report in reports:    # CHALLENGE 4
            if args.json:
                report_dict = asdict(report)
                report_dict["score"] = report.score
                report_dict["grade"] = report.grade
                json.dump(report_dict, sys.stdout)
            else:
                _render_report(report, console, args.verbose)
                console.print()

        # CHALLENGE 5: compare each report's grade against the user-supplied
        # `--min-grade` threshold. If any report is below the threshold,
        # return 1. Network errors already return 2 earlier.
        threshold_rank = _grade_rank(args.min_grade)

        for report in reports:  # CHALLENGE 5
            if _grade_rank(report.grade) < threshold_rank:
                return 1

        return 0  # all reports met or exceeded the threshold
    
    return asyncio.run(run_cli())    # CHALLENGE 8


# Standard "if invoked directly as a script" guard — lets the file be
# imported by tests without firing main()
if __name__ == "__main__":
    sys.exit(main())
