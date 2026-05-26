import base64
import io
import logging
import os
import re
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from colorama import Fore, init

init(autoreset=True)


class CustomFormatter(logging.Formatter):
    """Colored log formatter."""

    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        base = "%(asctime)s - %(levelname)s - %(message)s"
        return logging.Formatter(color + base + Fore.RESET).format(record)


logger = logging.getLogger("insecureactions")
logger.setLevel(logging.INFO)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(CustomFormatter())
    logger.addHandler(_handler)
logger.propagate = False


GITHUB_API = "https://api.github.com"
GITHUB_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN") or os.getenv("GITHUB_TOKEN")

# Inputs an attacker can fully control. Used inside ${{ … }} expressions in a
# `run:` block, these enable arbitrary command execution on the runner.
# Reference: https://securitylab.github.com/research/github-actions-untrusted-input/
UNTRUSTED_EXPRESSIONS = [
    r"github\.event\.issue\.title",
    r"github\.event\.issue\.body",
    r"github\.event\.pull_request\.title",
    r"github\.event\.pull_request\.body",
    r"github\.event\.pull_request\.head\.ref",
    r"github\.event\.pull_request\.head\.label",
    r"github\.event\.pull_request\.head\.repo\.default_branch",
    r"github\.event\.comment\.body",
    r"github\.event\.review\.body",
    r"github\.event\.review_comment\.body",
    r"github\.event\.pages\.[^}\s]*\.page_name",
    r"github\.event\.commits\.[^}\s]*\.message",
    r"github\.event\.commits\.[^}\s]*\.author\.email",
    r"github\.event\.commits\.[^}\s]*\.author\.name",
    r"github\.event\.head_commit\.message",
    r"github\.event\.head_commit\.author\.email",
    r"github\.event\.head_commit\.author\.name",
    r"github\.event\.workflow_run\.head_branch",
    r"github\.event\.workflow_run\.head_commit\.message",
    r"github\.event\.workflow_run\.head_commit\.author\.email",
    r"github\.event\.workflow_run\.head_commit\.author\.name",
    r"github\.event\.discussion\.title",
    r"github\.event\.discussion\.body",
    r"github\.head_ref",
]
UNTRUSTED_RE = re.compile(
    r"\$\{\{\s*[^}]*(?:" + "|".join(UNTRUSTED_EXPRESSIONS) + r")[^}]*\}\}",
    re.IGNORECASE,
)
RUN_BLOCK_RE = re.compile(
    r"^([ \t]*)(?:-\s*)?run\s*:\s*(?:\|[+-]?|>[+-]?)?\s*\n"
    r"((?:\1[ \t]+.*\n?)+)",
    re.MULTILINE,
)
INLINE_RUN_RE = re.compile(r"^\s*(?:-\s*)?run\s*:\s*([^\n]+)", re.MULTILINE)
PR_TARGET_RE = re.compile(
    r"^\s*on\s*:.*?pull_request_target", re.MULTILINE | re.DOTALL
)
CHECKOUT_BLOCK_RE = re.compile(
    r"uses\s*:\s*actions/checkout@[^\s]+[\s\S]{0,600}", re.IGNORECASE
)
PR_REF_TOKENS_RE = re.compile(
    r"(?:ref\s*:\s*[^\n]*?(?:github\.event\.pull_request\.head|github\.head_ref|refs/pull/)"
    r"|repository\s*:\s*[^\n]*?github\.event\.pull_request\.head\.repo)",
    re.IGNORECASE,
)
USES_RE = re.compile(r"^\s*-?\s*uses\s*:\s*([^\s#]+)", re.MULTILINE)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")

# Commands that execute code from the checked-out tree. After a privileged
# checkout of an attacker-controlled ref these are arbitrary RCE sinks.
DANGEROUS_INSTALL_RE = re.compile(
    r"(?:^|[\s;&|`])("
    r"pip(?:3)?\s+install\b"
    r"|python(?:3)?\s+setup\.py\b"
    r"|npm\s+(?:install|ci|i)\b"
    r"|yarn(?:\s+install)?\b"
    r"|pnpm\s+(?:install|i)\b"
    r"|bundle\s+install\b"
    r"|gem\s+install\b"
    r"|composer\s+install\b"
    r"|go\s+(?:install|get|generate|run|build|test)\b"
    r"|cargo\s+(?:install|build|run|test)\b"
    r"|mvn\s+\S+"
    r"|gradle\s+\S+|\./gradlew\b"
    r"|make\b"
    r"|sbt\s+\S+"
    r"|terraform\s+(?:init|apply|plan)\b"
    r")",
    re.MULTILINE,
)
PERMISSIONS_RE = re.compile(r"^\s*permissions\s*:\s*(.*)$", re.MULTILINE)
WRITE_ALL_RE = re.compile(r"\bwrite-all\b", re.IGNORECASE)
# Triggers that hand workflow execution to untrusted actors.
UNTRUSTED_TRIGGERS_RE = re.compile(
    r"^\s*on\s*:.*?(?:pull_request_target|workflow_run|issue_comment)",
    re.MULTILINE | re.DOTALL,
)
# Triggers attackers can drive from a fork (broader set — covers public-repo
# self-hosted abuse via plain `pull_request` too).
FORK_REACHABLE_TRIGGERS_RE = re.compile(
    r"^\s*on\s*:.*?(?:pull_request_target|pull_request|workflow_run|issue_comment|fork)",
    re.MULTILINE | re.DOTALL,
)
SELF_HOSTED_RE = re.compile(
    r"runs-on\s*:\s*(?:\[[^\]]*[\"']?self-hosted|[\"']?self-hosted)",
    re.IGNORECASE,
)
PIPE_TO_SHELL_RE = re.compile(
    r"(?:curl|wget|fetch)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash|ksh)\b",
    re.IGNORECASE,
)
OUTDATED_CHECKOUT_RE = re.compile(
    r"uses\s*:\s*actions/checkout@(v[123])(?![0-9])", re.IGNORECASE
)
SECRETS_INHERIT_RE = re.compile(r"^\s*secrets\s*:\s*inherit\s*$", re.MULTILINE)
GITHUB_SCRIPT_RE = re.compile(
    r"uses\s*:\s*actions/github-script@[^\s]+", re.IGNORECASE
)
NEXT_STEP_RE = re.compile(
    r"^\s*-\s+(?:uses|name|run|id)\s*:", re.MULTILINE
)
# CVE-2025-30066: tj-actions/changed-files was compromised; all version tags
# were retroactively pointed at a malicious commit that dumped runner memory
# (containing secrets) into the workflow log. Exposure window roughly
# 2025-03-14 to 2025-03-15 UTC.
MALICIOUS_TJ_SHA = "0e58ed8671d6b60d0890c21b07f8835ace038e67"
CVE_2025_30066_DATE_RANGE = "2025-03-14..2025-03-15"
# Cap log downloads to keep network/memory bounded — a single repo with 100s
# of CVE-window runs would otherwise produce GBs of traffic.
CVE_LOG_SCAN_RUN_CAP = 20

# IoC patterns for CVE-2025-30066 log forensics.
# A line of pure base64 longer than this is unusual in CI output but matches
# the memory-dump signature dropped by the malicious tj-actions payload.
LONG_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{500,}={0,2}")
# Common secret prefixes that, when found inside a *decoded* base64 blob from
# a workflow log, indicate the memory dump captured live credentials.
SECRET_PREFIX_RE = re.compile(
    rb"("
    rb"ghp_[A-Za-z0-9]{36}"
    rb"|ghs_[A-Za-z0-9]{36}"
    rb"|gho_[A-Za-z0-9]{36}"
    rb"|github_pat_[A-Za-z0-9_]{82}"
    rb"|AKIA[0-9A-Z]{16}"
    rb"|ASIA[0-9A-Z]{16}"
    rb"|AIza[0-9A-Za-z_\-]{35}"
    rb"|xox[pbaor]-[A-Za-z0-9\-]{10,}"
    rb"|npm_[A-Za-z0-9]{36}"
    rb"|sk-[A-Za-z0-9]{20,}"
    rb"|glpat-[A-Za-z0-9_\-]{20,}"
    rb")"
)

# Actions known to have been compromised in supply-chain attacks. Pinning to a
# SHA does not save you if the SHA itself was tampered — these refs warrant a
# louder warning regardless of how they are pinned.
COMPROMISED_ACTIONS = {
    "tj-actions/changed-files":
        "Compromised Mar-2025 (CVE-2025-30066) — secrets leaked via crafted commits",
    "reviewdog/action-setup":
        "Compromised Mar-2025 alongside tj-actions",
    "reviewdog/action-shellcheck":
        "Compromised Mar-2025 alongside tj-actions",
    "reviewdog/action-composite-template":
        "Compromised Mar-2025 alongside tj-actions",
    "reviewdog/action-staticcheck":
        "Compromised Mar-2025 alongside tj-actions",
    "reviewdog/action-actionlint":
        "Compromised Mar-2025 alongside tj-actions",
    "reviewdog/action-typos":
        "Compromised Mar-2025 alongside tj-actions",
}


def _headers():
    if not GITHUB_TOKEN:
        return {"Accept": "application/vnd.github+json"}
    return {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _handle_rate_limit(response):
    """Sleep until the rate-limit window resets if we're about to exhaust it."""
    remaining = response.headers.get("X-RateLimit-Remaining")
    reset = response.headers.get("X-RateLimit-Reset")
    if remaining is not None and reset is not None:
        try:
            if int(remaining) == 0:
                wait = max(int(reset) - int(time.time()), 0) + 1
                logger.warning(f"Rate limit hit, sleeping {wait}s")
                time.sleep(wait)
        except ValueError:
            pass


def make_request(url, params=None, method="get"):
    try:
        response = requests.request(
            method, url, params=params, headers=_headers(), timeout=15
        )
    except requests.RequestException as e:
        logger.debug(f"Request failed for {url}: {e}")
        return None

    if response.status_code in (403, 429):
        _handle_rate_limit(response)
    if response.status_code == 401:
        logger.error("GitHub token rejected (401). Check GITHUB_ACCESS_TOKEN.")
        return None
    if response.status_code == 404:
        return None
    if not response.ok:
        logger.debug(f"{response.status_code} for {url}")
        return None
    return response


def _paginate(url, params, key=None):
    """Paginate any GitHub list endpoint via the Link header.

    Some endpoints (e.g. Actions runs) wrap results in a top-level key; pass
    `key=` to extract the embedded array.
    """
    results = []
    while url:
        response = make_request(url, params=params)
        if not response:
            break
        payload = response.json()
        if key is not None and isinstance(payload, dict):
            items = payload.get(key, [])
        elif isinstance(payload, list):
            items = payload
        else:
            items = []
        results.extend(items)
        params = None  # next link already encodes pagination
        url = response.links.get("next", {}).get("url")
    return results


def get_single_repository(owner, repo):
    """Fetch one repository's metadata."""
    response = make_request(f"{GITHUB_API}/repos/{owner}/{repo}")
    if not response:
        return None
    return response.json()


def get_all_repositories(owner):
    """List every repo owned by an org *or* user account.

    Tries the org endpoint first; falls back to the user endpoint on 404 so
    callers don't have to know the account type in advance.
    """
    repos = _paginate(
        f"{GITHUB_API}/orgs/{owner}/repos",
        {"per_page": 100, "type": "public"},
    )
    if repos:
        return repos
    # Fallback: user account.
    return _paginate(
        f"{GITHUB_API}/users/{owner}/repos",
        {"per_page": 100, "type": "owner"},
    )


def list_workflow_files(org_name, repo_name, default_branch):
    """Use the Git Trees API to list workflow files in one request."""
    url = f"{GITHUB_API}/repos/{org_name}/{repo_name}/git/trees/{default_branch}"
    response = make_request(url, params={"recursive": "1"})
    if not response:
        return []
    tree = response.json().get("tree", [])
    return [
        item["path"]
        for item in tree
        if item.get("type") == "blob"
        and item["path"].startswith(".github/workflows/")
        and item["path"].endswith((".yml", ".yaml"))
    ]


def fetch_file(org_name, repo_name, path):
    url = f"{GITHUB_API}/repos/{org_name}/{repo_name}/contents/{path}"
    response = make_request(url)
    if not response:
        return None
    payload = response.json()
    if payload.get("encoding") != "base64":
        return None
    try:
        return base64.b64decode(payload["content"]).decode("utf-8", errors="replace")
    except (KeyError, ValueError) as e:
        logger.debug(f"Decode failed for {path}: {e}")
        return None


def find_script_injections(content):
    """Return untrusted ${{ … }} expressions used inside a `run:` block."""
    findings = []
    for match in RUN_BLOCK_RE.finditer(content):
        block = match.group(2)
        for expr in UNTRUSTED_RE.finditer(block):
            findings.append(expr.group(0).strip())
    for match in INLINE_RUN_RE.finditer(content):
        line = match.group(1)
        for expr in UNTRUSTED_RE.finditer(line):
            findings.append(expr.group(0).strip())
    return findings


def find_pull_request_target_risks(content):
    """`pull_request_target` + checkout of attacker-controlled ref = RCE on
    the base repo with write tokens. Catches both `ref: <PR head>` and
    `repository: <PR head repo>` shapes. See GitHub's own advisory."""
    if not PR_TARGET_RE.search(content):
        return False
    for checkout in CHECKOUT_BLOCK_RE.finditer(content):
        if PR_REF_TOKENS_RE.search(checkout.group(0)):
            return True
    return False


def find_dangerous_builds_after_checkout(content):
    """Privileged trigger + checkout of attacker-controlled code + build/install
    command in a `run:` block = arbitrary code execution (e.g. malicious
    setup.py during `pip install`). Reported by Sysdig against MITRE, Splunk,
    spotipy, et al."""
    if not UNTRUSTED_TRIGGERS_RE.search(content):
        return []
    has_untrusted_checkout = any(
        PR_REF_TOKENS_RE.search(m.group(0))
        for m in CHECKOUT_BLOCK_RE.finditer(content)
    )
    # `pull_request_target` defaults to checking out the *base* branch, but the
    # workflow files are still read from base — so a build step on its own is
    # not enough. We only fire when an untrusted ref is actually checked out.
    if not has_untrusted_checkout:
        return []
    findings = []
    for match in RUN_BLOCK_RE.finditer(content):
        for cmd in DANGEROUS_INSTALL_RE.finditer(match.group(2)):
            findings.append(cmd.group(1).strip())
    for match in INLINE_RUN_RE.finditer(content):
        for cmd in DANGEROUS_INSTALL_RE.finditer(match.group(1)):
            findings.append(cmd.group(1).strip())
    return findings


def find_token_permission_issues(content):
    """Workflows without a `permissions:` block inherit the repo/org default,
    which is often the legacy `contents: write` (or full write-all). An
    untrusted-input vuln becomes a repo takeover when paired with a write token.

    Returns one of: 'missing', 'write-all', or None.
    """
    matches = PERMISSIONS_RE.findall(content)
    if not matches:
        return "missing"
    # `permissions: write-all` (or `permissions: read-all` — the latter is fine).
    for value in matches:
        if WRITE_ALL_RE.search(value):
            return "write-all"
    return None


def find_unpinned_actions(content):
    """Third-party actions referenced by tag/branch instead of a full SHA can
    be silently swapped by the action owner."""
    unpinned = []
    for match in USES_RE.finditer(content):
        ref = match.group(1)
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        if "@" not in ref:
            continue
        action, version = ref.rsplit("@", 1)
        owner = action.split("/", 1)[0]
        # Skip first-party (actions/, github/) — still ideally pinned but lower risk.
        if owner in ("actions", "github"):
            continue
        if not SHA_RE.match(version):
            unpinned.append(ref)
    return unpinned


def find_self_hosted_with_untrusted_trigger(content):
    """Self-hosted runners exposed to fork-driven triggers let any contributor
    execute code on your infrastructure. On public repos this is one of the
    most-abused GitHub Actions footguns."""
    if not FORK_REACHABLE_TRIGGERS_RE.search(content):
        return False
    return bool(SELF_HOSTED_RE.search(content))


def find_pipe_to_shell(content):
    """`curl ... | bash` in CI — if the source domain or TLS is compromised,
    your build environment is compromised."""
    findings = []
    for match in RUN_BLOCK_RE.finditer(content):
        for m in PIPE_TO_SHELL_RE.finditer(match.group(2)):
            findings.append(m.group(0).strip())
    for match in INLINE_RUN_RE.finditer(content):
        for m in PIPE_TO_SHELL_RE.finditer(match.group(1)):
            findings.append(m.group(0).strip())
    return findings


def find_outdated_first_party(content):
    """`actions/checkout@v1` (leaks token by default) and v2/v3 (deprecated
    Node 12/16 runtimes) — first-party but still worth flagging."""
    return [f"actions/checkout@{m.group(1)}" for m in OUTDATED_CHECKOUT_RE.finditer(content)]


def find_malicious_tj_pin(content):
    """A direct pin to the CVE-2025-30066 malicious commit SHA — definitive
    evidence the workflow currently invokes the compromised payload."""
    findings = []
    for m in USES_RE.finditer(content):
        ref = m.group(1)
        if "@" not in ref:
            continue
        action, version = ref.rsplit("@", 1)
        if action == "tj-actions/changed-files" and version.lower() == MALICIOUS_TJ_SHA:
            findings.append(ref)
    return findings


def download_run_logs(owner, repo, run_id):
    """Fetch the log archive (ZIP) for a workflow run.

    Returns the raw bytes, or None if the logs are unavailable: the most
    common reason is GitHub's 90-day retention window having lapsed (HTTP
    410 / 404). We never write the bytes to disk — they likely contain
    secrets and live only in memory while we scan.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/runs/{run_id}/logs"
    response = make_request(url)
    if not response:
        return None
    return response.content


def scan_log_archive_for_cve_iocs(zip_bytes):
    """Inspect a workflow-run log archive for indicators of CVE-2025-30066
    memory-dump exposure.

    The malicious tj-actions/changed-files payload dumped runner process
    memory (which contains every secret in the env) as a base64 blob into
    the workflow log. We surface two confidence tiers:

      - 'confirmed' — a decoded base64 blob in the log matches a known
        secret prefix (ghp_, AKIA…, AIza…, xoxb-…, npm_…, etc.).
      - 'suspicious' — a very long base64 blob whose decoded bytes don't
        match a known prefix but is consistent with a memory dump.

    Returns a list of (log_filename, severity, hint) tuples.
    """
    findings = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return findings
    try:
        for name in zf.namelist():
            try:
                raw = zf.read(name)
            except (KeyError, RuntimeError):
                continue
            text = raw.decode("utf-8", errors="replace")
            for match in LONG_BASE64_RE.finditer(text):
                blob = match.group(0)
                try:
                    decoded = base64.b64decode(blob, validate=False)
                except (ValueError, base64.binascii.Error):
                    continue
                secret_hit = SECRET_PREFIX_RE.search(decoded)
                if secret_hit:
                    token = secret_hit.group(1).decode("ascii", errors="replace")
                    # Don't echo the whole token — just the prefix family.
                    prefix = re.split(r"[A-Za-z0-9]{6,}", token, maxsplit=1)[0] or token[:6]
                    findings.append((name, "confirmed", f"decoded blob contains {prefix}… credential"))
                    break  # one hit per file is enough
                elif len(decoded) > 4096:
                    findings.append(
                        (name, "suspicious", f"{len(blob)}-char base64 blob ({len(decoded)} bytes decoded)")
                    )
                    break
    finally:
        zf.close()
    return findings


def list_workflow_runs_in_window(owner, repo, workflow_path, date_range):
    """List runs of a specific workflow file during a date window.

    GitHub's API accepts `created=YYYY-MM-DD..YYYY-MM-DD` for inclusive ranges.
    """
    filename = workflow_path.rsplit("/", 1)[-1]
    url = (
        f"{GITHUB_API}/repos/{owner}/{repo}/actions/workflows/"
        f"{filename}/runs"
    )
    params = {"created": date_range, "per_page": 100}
    return _paginate(url, params, key="workflow_runs")


def find_compromised_actions(content):
    """Match references against a curated blocklist of actions involved in
    public supply-chain incidents."""
    findings = []
    seen = set()
    for m in USES_RE.finditer(content):
        ref = m.group(1)
        action = ref.split("@", 1)[0] if "@" in ref else ref
        if action in COMPROMISED_ACTIONS and ref not in seen:
            seen.add(ref)
            findings.append((ref, COMPROMISED_ACTIONS[action]))
    return findings


def find_secrets_inherit(content):
    """`secrets: inherit` on a `uses:`-style reusable workflow call passes
    every caller secret to the called workflow — fine for internal reusables,
    catastrophic if the called workflow is third-party."""
    return SECRETS_INHERIT_RE.search(content) is not None


def find_github_script_injections(content):
    """`actions/github-script` interpolates `${{ … }}` into a JS body — same
    injection class as `run:`, but our run-block scanner misses it because the
    sink key is `script:` under `with:`, not `run:`."""
    findings = []
    for match in GITHUB_SCRIPT_RE.finditer(content):
        # Look ahead until the next step boundary (best-effort, no YAML parse).
        chunk = content[match.end(): match.end() + 2000]
        boundary = NEXT_STEP_RE.search(chunk)
        if boundary:
            chunk = chunk[: boundary.start()]
        for expr in UNTRUSTED_RE.finditer(chunk):
            findings.append(expr.group(0).strip())
    return findings


def check_broken_links(content):
    """A link that 404s in a workflow can be a hijack vector if the target
    domain or repo can later be claimed by an attacker."""
    broken = []
    for link in URL_RE.findall(content):
        link = link.rstrip(".,);:'\"")
        try:
            r = requests.head(link, timeout=10, allow_redirects=True)
            if r.status_code >= 400:
                broken.append((link, r.status_code))
        except requests.RequestException:
            broken.append((link, "unreachable"))
    return broken


def scan_workflow(org_name, repo_name, path, check_links=False, check_cve_tj=False):
    content = fetch_file(org_name, repo_name, path)
    if content is None:
        return

    location = f"{org_name}/{repo_name}:{path}"

    for ref in find_malicious_tj_pin(content):
        logger.error(
            f"[cve-2025-30066-malicious-pin] {location} -> {ref} "
            f"(direct pin to the malicious commit; secrets in any run that "
            f"executed this step are compromised)"
        )

    for expr in find_script_injections(content):
        logger.warning(f"[script-injection] {location} -> {expr}")

    if find_pull_request_target_risks(content):
        logger.error(
            f"[pull_request_target+checkout-pr-ref] {location} "
            f"-> attacker-controlled code may run with write token"
        )

    for cmd in find_dangerous_builds_after_checkout(content):
        logger.error(
            f"[build-on-untrusted-checkout] {location} -> `{cmd}` runs "
            f"attacker code after privileged checkout"
        )

    perm_issue = find_token_permission_issues(content)
    if perm_issue == "missing":
        logger.warning(
            f"[no-permissions-block] {location} -> GITHUB_TOKEN inherits repo "
            f"defaults (often contents: write)"
        )
    elif perm_issue == "write-all":
        logger.error(
            f"[permissions-write-all] {location} -> GITHUB_TOKEN granted full "
            f"write scope"
        )

    if find_self_hosted_with_untrusted_trigger(content):
        logger.error(
            f"[self-hosted+fork-trigger] {location} -> self-hosted runner "
            f"exposed to fork-driven workflow execution"
        )

    for cmd in find_pipe_to_shell(content):
        logger.warning(f"[pipe-to-shell] {location} -> {cmd}")

    for ref in find_outdated_first_party(content):
        logger.warning(f"[outdated-action] {location} -> {ref}")

    compromised_refs = find_compromised_actions(content)
    for ref, reason in compromised_refs:
        logger.error(f"[compromised-action] {location} -> {ref} ({reason})")

    # CVE-2025-30066 dynamic audit: list runs of this workflow during the
    # exposure window. Any run that executed during that window with this
    # action present likely leaked secrets to the workflow log.
    if check_cve_tj and any(
        ref.startswith("tj-actions/changed-files") for ref, _ in compromised_refs
    ):
        logger.info(
            f"[cve-2025-30066] {location} -> querying runs in "
            f"{CVE_2025_30066_DATE_RANGE}…"
        )
        runs = list_workflow_runs_in_window(
            org_name, repo_name, path, CVE_2025_30066_DATE_RANGE
        )
        if not runs:
            logger.info(
                f"[cve-2025-30066-clean] {location} -> no runs executed in "
                f"the exposure window (the workflow may not have existed yet "
                f"or simply did not trigger during 2025-03-14..2025-03-15)"
            )
        else:
            logger.error(
                f"[cve-2025-30066-exposed-runs] {location} -> "
                f"{len(runs)} run(s) executed during the exposure window "
                f"(2025-03-14..2025-03-15); scanning logs for leaked secrets"
            )

            scanned = 0
            confirmed = 0
            suspicious = 0
            expired = 0
            for run in runs[:CVE_LOG_SCAN_RUN_CAP]:
                run_id = run.get("id")
                run_url = run.get("html_url")
                run_number = run.get("run_number")
                if run_id is None:
                    continue
                zip_bytes = download_run_logs(org_name, repo_name, run_id)
                if zip_bytes is None:
                    expired += 1
                    continue
                scanned += 1
                iocs = scan_log_archive_for_cve_iocs(zip_bytes)
                if not iocs:
                    logger.info(
                        f"    run #{run_number} {run_url} -> no IoCs in logs"
                    )
                    continue
                run_confirmed = any(sev == "confirmed" for _, sev, _ in iocs)
                if run_confirmed:
                    confirmed += 1
                else:
                    suspicious += 1
                for log_name, severity, hint in iocs:
                    level = logger.error if severity == "confirmed" else logger.warning
                    level(
                        f"    [{severity}] run #{run_number} {run_url} "
                        f"-> {log_name}: {hint}"
                    )

            remaining = len(runs) - CVE_LOG_SCAN_RUN_CAP
            if remaining > 0:
                logger.warning(
                    f"    {remaining} additional run(s) NOT scanned (cap = "
                    f"{CVE_LOG_SCAN_RUN_CAP}); review manually at the workflow URL"
                )
            logger.info(
                f"    summary: scanned={scanned} confirmed={confirmed} "
                f"suspicious={suspicious} expired-or-unreadable={expired}"
            )

    if find_secrets_inherit(content):
        logger.warning(
            f"[secrets-inherit] {location} -> reusable workflow call receives "
            f"all caller secrets"
        )

    for expr in find_github_script_injections(content):
        logger.error(f"[github-script-injection] {location} -> {expr}")

    for ref in find_unpinned_actions(content):
        logger.warning(f"[unpinned-action] {location} -> {ref}")

    if check_links:
        for link, status in check_broken_links(content):
            logger.warning(f"[broken-link] {location} -> {link} ({status})")


def scan_repository(repo, check_links=False, check_cve_tj=False):
    owner = repo.get("owner", {}).get("login")
    repo_name = repo.get("name")
    default_branch = repo.get("default_branch") or "main"
    if not owner or not repo_name:
        return
    if repo.get("archived"):
        return
    paths = list_workflow_files(owner, repo_name, default_branch)
    if not paths:
        return
    logger.info(f"Scanning {owner}/{repo_name} ({len(paths)} workflow file(s))")
    for path in paths:
        scan_workflow(
            owner,
            repo_name,
            path,
            check_links=check_links,
            check_cve_tj=check_cve_tj,
        )


def _resolve_targets(targets):
    """Expand each CLI target into a list of repo objects.

    A target is one of:
      - "owner/repo" → that single repository
      - "name"       → every repo in that org (falls back to user account)
    """
    repos = []
    for target in targets:
        target = target.strip().lstrip("@")
        if "/" in target:
            owner, _, name = target.partition("/")
            repo = get_single_repository(owner, name)
            if repo:
                repos.append(repo)
            else:
                logger.warning(f"Repository {target} not found or inaccessible")
            continue
        found = get_all_repositories(target)
        if found:
            logger.info(f"Found {len(found)} repositories under {target}")
            repos.extend(found)
        else:
            logger.warning(f"No repositories found for {target}")
    return repos


def check(targets, check_links=False, check_cve_tj=False, workers=8):
    if not GITHUB_TOKEN:
        logger.error("GITHUB_ACCESS_TOKEN is not set. Aborting.")
        return

    if isinstance(targets, str):
        targets = [targets]

    repositories = _resolve_targets(targets)
    if not repositories:
        logger.info("No repositories to scan. Exiting.")
        return

    logger.info(f"Total repositories to scan: {len(repositories)}")
    if check_cve_tj:
        logger.info(
            "CVE-2025-30066 audit enabled: workflows using tj-actions/changed-files "
            "will be checked against runs in 2025-03-14..2025-03-15"
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(scan_repository, repo, check_links, check_cve_tj)
            for repo in repositories
        ]
        for future in as_completed(futures):
            exc = future.exception()
            if exc:
                logger.debug(f"Worker error: {exc}")
