# RELEASE-CHECKLIST

The canonical, mandatory 27-gate release checklist for every artifact published under this
account. This file is the checklist itself, plus the
machine-readable gate registry a validator reads.

A per-release copy of the *results* (not this file) is pasted into the release PR and committed
as `docs/releases/v<MAJOR>.<MINOR>.<PATCH>/release-evidence.json` in the tool's own repo.

## Applicability tags

`[all]` every artifact - `[bin]` packaged Windows `.exe`/MSI - `[mod]` PowerShell module -
`[plg]` Stream Deck plugin - `[skl]` Claude skill - `[web]` browser tool on hans.study -
`[prod]` anything that executes against production directory services, domain controllers, or
access-control panels.

## The N/A rule

A gate whose tag does not apply to the artifact being released is marked **N/A, with the reason
written in** (for example: "N/A - no binary artifact; skill is distributed as a git-tracked
package"). A gate that applies and was skipped is a **failed release**, not a marked one.
Silently omitting a gate is never acceptable - that distinction is the whole point of giving
each gate a tag and an explicit `N/A allowed` flag below. Where `N/A allowed: no` is stated for
a gate, the only valid outcomes for an artifact the gate's tags apply to are `pass` or `fail`.

Each gate below carries: its applicability tag(s), an **Id** (stable forever - never renumbered,
only added or marked withdrawn, because per-release `release-evidence.json` files reference
gates by id), an **Evidence** artifact, a **Command** that produces or checks that evidence
(or "manual review" where no single command suffices), and whether **N/A is allowed** for a gate
whose tags do apply.

---

## Gate 1 - Security

1. `[all]` **Security review completed and recorded** - for higher-risk projects, an extended,
   independent review report is attached.
   - Id: `G01-security-review`
   - Evidence: a security review record (`docs/security-review.md`, or an extended independent
     security review report for higher-risk projects) linked from the release PR
   - Command: manual review; no single automated command
   - N/A allowed: no

2. `[all]` **Secret scan clean** - repo secret scanning + push protection on, plus a
   `gitleaks`-class scan over full history, output attached. No live credential in code, config,
   sample output, or screenshots.
   - Id: `G02-secret-scan`
   - Evidence: `gitleaks` scan output attached to the release PR, plus confirmation that repo
     secret scanning and push protection are enabled
   - Command: `gitleaks detect --source . --log-opts="--all" --no-banner --exit-code 1`
   - N/A allowed: no

3. `[all]` **Threat model / abuse notes present** for anything that touches credentials,
   networks, or privileged operations.
   - Id: `G03-threat-model`
   - Evidence: `docs/threat-model.md`, or a README "Threat model" section
   - Command: `test -f docs/threat-model.md || grep -qi 'threat model' README.md`
   - N/A allowed: yes - reason must state that the tool touches no credentials, network, or
     privileged operation

4. `[all]` **Dependencies**: Dependabot alerts at zero High/Critical, or each one waived with a
   written reason.
   - Id: `G04-dependency-alerts`
   - Evidence: the Dependabot alerts list (zero open High/Critical), or a written waiver per
     alert
   - Command: `gh api repos/{owner}/{repo}/dependabot/alerts -q '[.[] | select(.state=="open" and (.security_advisory.severity=="high" or .security_advisory.severity=="critical"))] | length'`
   - N/A allowed: no

5. `[all]` **Dependency pinning verified**: lockfile committed, exact module versions,
   every `uses:` in every workflow pinned to a full commit SHA. Zero floating ranges reach a
   release build. *(Gate 4 is a point-in-time CVE check; this is the gate that stops a clean
   release silently pulling a compromised transitive dependency for a downstream user
   tomorrow.)*
   - Id: `G05-dependency-pinning`
   - Evidence: committed lockfile (or `RequiredVersion` in the `.psd1`) plus every `uses:` line
     pinned to a 40-hex commit SHA
   - Command: `grep -rhoE 'uses:[[:space:]]*[^[:space:]]+' .github/workflows/ | grep -vE '@[0-9a-f]{40}$'` (expect empty)
   - N/A allowed: no

6. `[all]` **Third-party content provenance review complete**, with
   `docs/content-provenance.md` (or the equivalent README section) naming every third-party
   source class, its licence, and how it is used. For any project grounded in benchmark or
   standards content, this gate explicitly confirms that no CC BY-NC-SA prose (CIS Benchmark
   text) has been copied and that such sources appear as ID cross-references only. Any
   copyleft (GPL/AGPL) dependency is a blocking finding here, not a footnote.
   - Id: `G06-content-provenance`
   - Evidence: `docs/content-provenance.md` naming each third-party source class, its licence,
     and how it is used
   - Command: `test -f docs/content-provenance.md`
   - N/A allowed: no

7. `[all]` **Least privilege documented**: the exact rights the tool needs and why (for the AD
   audit tool, "read-only" is a claim that must be demonstrable).
   - Id: `G07-least-privilege`
   - Evidence: a README "Requirements" or "Least privilege" section naming the exact rights
     needed and why
   - Command: manual review; no single automated command
   - N/A allowed: no

8. `[all]` **Redaction**: any report/export the tool produces is checked for credentials,
   hostnames, and PII that the user did not consent to include.
   - Id: `G08-redaction`
   - Evidence: a redaction pass note covering any sample report/export shown in docs or README
   - Command: manual review; no single automated command
   - N/A allowed: yes - reason must state that the tool produces no report or export

## Gate 2 - Correctness and docs

9. `[all]` **README complete** against the house tier-1 README shape, including a working install
   one-liner that was actually run on a clean machine (or, for `[skl]`, a clean profile).
   - Id: `G09-readme-complete`
   - Evidence: README matching the house tier-1 README shape, plus a captured transcript of the install
     one-liner run on a clean machine or profile
   - Command: manual review + the install one-liner run on a clean machine/profile
   - N/A allowed: no

10. `[all]` **`CHANGELOG.md` has an entry for this version**, dated, in Keep a Changelog format.
    - Id: `G10-changelog-entry`
    - Evidence: the `CHANGELOG.md` section for this version
    - Command: `grep -qE '^## \[?v?[0-9]+\.[0-9]+\.[0-9]+\]?.*[0-9]{4}-[0-9]{2}-[0-9]{2}' CHANGELOG.md`
    - N/A allowed: no

11. `[all]` **Version is SemVer** and is consistent across: git tag, manifest (`plugin.json` /
    `.psd1` / Stream Deck `manifest.json`), README badge, landing page frontmatter.
    - Id: `G11-semver-consistent`
    - Evidence: the identical SemVer string quoted from all four locations
    - Command: manual/CI cross-check of the tag, manifest, README badge, and landing-page
      `version` field
    - N/A allowed: no
    - **Prerelease note:** for a prerelease tag (`vX.Y.Z-<suffix>`), `release.yml`
      publishes a GitHub Release with artifacts, SBOM, checksums and attestation, but publishes
      to **no channel**, and the landing page is not updated. This gate is therefore
      **N/A - reason: "Prerelease tag: no channel is published and the landing page is not
      updated for a prerelease, per the prerelease policy; there is no channel evidence to
      check version consistency against."** A final tag (no suffix) still requires pass/fail as
      above.

12. `[all]` **Screenshots and a demo GIF exist**, are current, and contain no customer data, no
    real hostnames, no licence keys - lab data only.
    - Id: `G12-screenshots-demo`
    - Evidence: the current screenshots/GIF, reviewed for lab-data-only content
    - Command: manual review; no single automated command
    - N/A allowed: no

13. `[all]` **Docs link resolves**; landing page and repo link to each other.
    - Id: `G13-docs-links`
    - Evidence: a resolving docs URL, and each of the repo README and the landing page linking
      to the other
    - Command: `curl -fsSL -o /dev/null -w '%{http_code}' <docsUrl>` (expect 200), plus a grep
      of each side for the other's URL
    - N/A allowed: no

## Gate 3 - Artifacts

14. `[all]` **Release built by CI from the tag**, not from a workstation.
    - Id: `G14-ci-built`
    - Evidence: the GitHub Actions run that produced the release, triggered by the tag push
    - Command: `gh run list --workflow=release.yml --json headBranch,event,conclusion -q '.[] | select(.event=="push")'`
    - N/A allowed: no

15. `[all]` **SBOM published** : a CycloneDX JSON document attached to the release,
    which parses and names at least the tool itself. A zero-dependency tool still ships one.
    - Id: `G15-sbom-published`
    - Evidence: `dist/<slug>-<version>.cdx.json` attached to the GitHub Release
    - Command: `node -e "const s=require('./<slug>-<version>.cdx.json');process.exit(s.components&&s.components.length?0:1)"`
    - N/A allowed: no

16. `[all]` **`SHA256SUMS` published** (covering the SBOM too) and the values shown on the
    landing page.
    - Id: `G16-sha256sums`
    - Evidence: `SHA256SUMS` attached to the release, values reproduced on the landing page
    - Command: `sha256sum -c SHA256SUMS`
    - N/A allowed: no
    - **Prerelease note:** for a prerelease tag (`vX.Y.Z-<suffix>`), `SHA256SUMS` is still
      published on the GitHub Release, but no channel is published and the landing page is not
      updated for a prerelease. This gate is therefore **N/A - reason: "Prerelease tag: no
      channel is published and the landing page is not updated for a prerelease, per the
      prerelease policy; SHA256SUMS is verified against the GitHub Release alone, with no
      landing-page value to check it against."** A final tag (no suffix) still requires pass/fail
      as above.

17. `[all]` **Build provenance attestation published** and `gh attestation verify` demonstrated
    in the release notes or docs.
    - Id: `G17-build-attestation`
    - Evidence: the Sigstore attestation bundle attached to the release, plus a documented
      `gh attestation verify` run
    - Command: `gh attestation verify <artifact> --owner hansstudy`
    - N/A allowed: no

18. `[bin]` `[mod]` **Authenticode signature applied** if a certificate exists; if not, the
    release notes and landing page carry the verify-by-hash instructions instead (explicitly,
    not silently). `N/A` for `[skl]` and `[web]`.
    - Id: `G18-authenticode`
    - Evidence: an `Authenticode` signature on the binary/module, or (until a certificate
      exists) `docs/verify-downloads.md`'s verify-by-hash block: compute
      `Get-FileHash -Algorithm SHA256 .\<file>`, compare it against the published
      `SHA256SUMS`, and verify build provenance with
      `gh attestation verify <file> --owner hansstudy`
    - Command: `Get-AuthenticodeSignature <file>` (expect `Status: Valid`)
    - N/A allowed: yes - reason (fixed, verbatim, so every repo states the absence identically):
      "No code-signing certificate held; deferred until a tool shows traction. Release ships
      Sigstore attestation, SHA256SUMS and verify instructions instead." Evidence for the N/A:
      `docs/verify-downloads.md`.

19. `[bin]` `[mod]` `[plg]` `[skl]` `[web]` **Artifacts install and run on a clean VM**;
    uninstall/removal is documented and works. For `[skl]`, the equivalent evidence is: the package validates
    (`claude plugin validate`), installs into a **clean profile** from the marketplace repo, and
    the skill triggers on its intended prompt. For `[web]`, the equivalent is a clean-profile
    browser load of the built page.
    - Id: `G19-clean-install`
    - Evidence: a clean-VM (or clean-profile) install/run transcript, plus documented
      uninstall/removal
    - Command: runtime-specific - e.g. `claude plugin validate <dir>` for `[skl]`; a clean-VM
      install script exit code for `[bin]`/`[mod]`/`[plg]`
    - N/A allowed: no

## Gate 4 - Policy

20. `[all]` **Telemetry policy: none by default.** A downloadable tool that runs on a customer's
    domain controller must not phone home. If a specific tool genuinely needs usage data, it is
    **opt-in only**, off by default, with a one-line prompt or flag, a documented exact payload,
    a documented endpoint, and a documented off switch. No opt-out-only, no silent collection,
    no third-party analytics SDK inside a downloadable tool. The existing site-side disclosure
    (`ToolFinePrint.astro`) stays as-is for browser tools and must be restated verbatim-in-spirit
    on the landing page.
    - Id: `G20-telemetry-policy`
    - Evidence: a telemetry statement in the README and landing page, stating one of: (a) no
      telemetry - the tool does not phone home or transmit anything about its use; (b) an
      opt-in-only collection, off by default, with the exact payload, endpoint, and off switch
      documented; or (c) for a browser tool, the site's own published fine-print disclosure
      restated in spirit
    - Command: manual review against the stated policy
    - N/A allowed: no

21. `[all]` **Support statement** present and honest, stating there is no SLA, plus the
    engagement link.
    - Id: `G21-support-statement`
    - Evidence: the support statement text, present in the README and on the landing page
    - Command: `grep -qi 'no SLA' README.md`
    - N/A allowed: no

22. `[all]` **Licence file present and correct**; trademark disclaimer present where a vendor
    is named; provenance note present where third-party content is used.
    - Id: `G22-licence-trademark`
    - Evidence: `LICENSE` (Apache-2.0); a trademark disclaimer where a vendor is named, stating
      the project is independent and not affiliated with, endorsed by, or supported by that
      vendor; a provenance note where third-party standards or benchmark content is used
    - Command: `test -f LICENSE && grep -qi 'Apache License' LICENSE`
    - N/A allowed: no

23. `[all]` **Privacy**: if the tool transmits anything anywhere (including the windows-audit
    upload endpoint), that is stated on the landing page and covered by `/privacy-policy/`.
    - Id: `G23-privacy-disclosure`
    - Evidence: the landing page and `/privacy-policy/` statement of what is transmitted, if
      anything
    - Command: manual review; no single automated command
    - N/A allowed: yes - reason must state that the tool transmits nothing anywhere

24. `[prod]` **Authorized-use notice** present in the README, in the landing page fine print,
    and in the tool's own startup/help output, using the fixed authorized-use template with a required,
    non-empty, tool-specific `{{AUTHORIZED_USE_CLAUSE}}`:

    > Run this only against systems you own or have written authorisation to assess.
    > **{{AUTHORIZED_USE_CLAUSE}}**
    > You are responsible for handling that output and for having permission to run it.

    The clause names, in one or two sentences, what the tool actually touches and what its
    output actually contains - it is never left as boilerplate. `ad-gpo-audit`'s clause ("It
    reads configuration from directory services and security systems and will produce a report
    containing sensitive infrastructure detail.") is the **worked example, not the mandate**: a
    certificate scanner, a port prober, and an exhibit packager each need their own clause. The
    Apache-2.0 warranty disclaimer is not this notice; it disclaims liability, it does not set
    scope of use. Applies to `ad-gpo-audit`, `streamdeck-genetec`, `streamdeck-ccure`, and any
    toolkit utility that touches production.
    - Id: `G24-authorized-use`
    - Evidence: the filled-in authorized-use template with its tool-specific
      `{{AUTHORIZED_USE_CLAUSE}}` resolved and non-empty, present in all three surfaces
    - Command: `grep -qi 'authoris' README.md && ! grep -q '{{AUTHORIZED_USE_CLAUSE}}' README.md`
      plus a manual check of the tool's own startup/help output
    - N/A allowed: no

25. `[all]` **Landing page live** on hans.study, in the `tools` collection, in the nav, and in
    the sitemap.
    - Id: `G25-landing-page-live`
    - Evidence: a 200 response for the landing page URL and a matching sitemap entry
    - Command: `curl -fsSL -o /dev/null -w '%{http_code}' https://hans.study/tools/<slug>/`
      (expect 200); `curl -fsSL https://hans.study/sitemap.xml | grep -q '/tools/<slug>/'`
    - N/A allowed: no
    - **Prerelease note:** for a prerelease tag (`vX.Y.Z-<suffix>`), no channel is
      published and the landing page is not updated. This gate is therefore
      **N/A - reason: "Prerelease tag: no channel is published and the landing page is not
      updated for a prerelease, per the prerelease policy; the tool's existing landing page
      (if any) is unchanged by this release."** A final tag (no suffix) still requires pass/fail
      as above.

26. `[all]` **Release blog post drafted**. A patch release's documented outcome
    is "no post" - that recorded decision is the passing evidence for a patch release, not an
    N/A.
    - Id: `G26-release-blog-post`
    - Evidence: the published post (launch article or minor-release news), or the recorded
      "patch release - no post" decision
    - Command: manual review; no single automated command
    - N/A allowed: no

27. `[all]` **Cross-post pre-flight signed off** before any release-linked post goes out: for
    each target community, the current sidebar/rules were read **on the day** and the reading is
    recorded (subreddit, date, verdict); authorship is disclosed in the first line of the post;
    the body is written fresh for that community and is not a copy of any other post; and the
    post links the repo rather than the marketing page where the community expects that. Where
    no cross-post is planned for this release, the recorded decision not to cross-post is the
    passing evidence, not an N/A.
    - Id: `G27-cross-post-preflight`
    - Evidence: the dated sidebar-reading record, for each target community, plus confirmation
      of authorship disclosure and the repo-link rule
    - Command: manual review; no single automated command
    - N/A allowed: no

---

## Machine-readable gate registry

The 27 gates above appear once more below, as a single fenced JSON block delimited by the HTML
comment markers, so a validator can extract and parse it without a markdown library. JSON
(rather than YAML) so the validator needs no dependency. `evidence.kind` is one of
`file | url | command-output | attestation | statement | review-record`. `checklist_version` is
bumped whenever either this registry or the prose gates above change.

<!-- machine-readable: begin -->
```json
{
  "checklist_version": 3,
  "gates": [
    { "id": "G01-security-review", "number": 1, "title": "Security review completed and recorded",
      "tags": ["all"], "na_allowed": false, "automatable": false,
      "evidence": { "kind": "review-record", "path": "docs/security-review.md" },
      "command": "manual review; no single automated command" },
    { "id": "G02-secret-scan", "number": 2, "title": "Secret scan clean",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "command-output", "path": "gitleaks output attached to release PR" },
      "command": "gitleaks detect --source . --log-opts=\"--all\" --no-banner --exit-code 1" },
    { "id": "G03-threat-model", "number": 3, "title": "Threat model / abuse notes present",
      "tags": ["all"], "na_allowed": true, "automatable": true,
      "evidence": { "kind": "file", "path": "docs/threat-model.md" },
      "command": "test -f docs/threat-model.md || grep -qi 'threat model' README.md" },
    { "id": "G04-dependency-alerts", "number": 4, "title": "Dependencies at zero High/Critical or waived",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "url", "path": "repos/{owner}/{repo}/dependabot/alerts" },
      "command": "gh api repos/{owner}/{repo}/dependabot/alerts -q '[.[] | select(.state==\"open\" and (.security_advisory.severity==\"high\" or .security_advisory.severity==\"critical\"))] | length'" },
    { "id": "G05-dependency-pinning", "number": 5, "title": "Dependency pinning verified",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "command-output", "path": ".github/workflows/*.yml" },
      "command": "grep -rhoE 'uses:[[:space:]]*[^[:space:]]+' .github/workflows/ | grep -vE '@[0-9a-f]{40}$'" },
    { "id": "G06-content-provenance", "number": 6, "title": "Third-party content provenance review complete",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "file", "path": "docs/content-provenance.md" },
      "command": "test -f docs/content-provenance.md" },
    { "id": "G07-least-privilege", "number": 7, "title": "Least privilege documented",
      "tags": ["all"], "na_allowed": false, "automatable": false,
      "evidence": { "kind": "file", "path": "README.md#requirements" },
      "command": "manual review; no single automated command" },
    { "id": "G08-redaction", "number": 8, "title": "Redaction of reports/exports",
      "tags": ["all"], "na_allowed": true, "automatable": false,
      "evidence": { "kind": "review-record", "path": "docs or README redaction note" },
      "command": "manual review; no single automated command" },
    { "id": "G09-readme-complete", "number": 9, "title": "README complete against house tier-1 README shape",
      "tags": ["all"], "na_allowed": false, "automatable": false,
      "evidence": { "kind": "file", "path": "README.md" },
      "command": "manual review + install one-liner run on a clean machine/profile" },
    { "id": "G10-changelog-entry", "number": 10, "title": "CHANGELOG.md has a dated entry for this version",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "file", "path": "CHANGELOG.md" },
      "command": "grep -qE '^## \\[?v?[0-9]+\\.[0-9]+\\.[0-9]+\\]?.*[0-9]{4}-[0-9]{2}-[0-9]{2}' CHANGELOG.md" },
    { "id": "G11-semver-consistent", "number": 11, "title": "Version is SemVer and consistent everywhere",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "command-output", "path": "tag, manifest, README badge, landing page frontmatter" },
      "command": "manual/CI cross-check of the four version strings",
      "prerelease_na_allowed": true,
      "prerelease_condition": "tag matches ^v[0-9]+\\.[0-9]+\\.[0-9]+-.+$",
      "prerelease_na_reason_fixed": "Prerelease tag: no channel is published and the landing page is not updated for a prerelease, per the prerelease policy; there is no channel evidence to check version consistency against." },
    { "id": "G12-screenshots-demo", "number": 12, "title": "Current screenshots and demo GIF, lab data only",
      "tags": ["all"], "na_allowed": false, "automatable": false,
      "evidence": { "kind": "review-record", "path": "README/docs screenshots and demo GIF" },
      "command": "manual review; no single automated command" },
    { "id": "G13-docs-links", "number": 13, "title": "Docs link resolves; landing page and repo link to each other",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "url", "path": "docsUrl" },
      "command": "curl -fsSL -o /dev/null -w '%{http_code}' <docsUrl>" },
    { "id": "G14-ci-built", "number": 14, "title": "Release built by CI from the tag",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "url", "path": "Actions run URL" },
      "command": "gh run list --workflow=release.yml --json headBranch,event,conclusion -q '.[] | select(.event==\"push\")'" },
    { "id": "G15-sbom-published", "number": 15, "title": "SBOM published",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "file", "path": "dist/{slug}-{version}.cdx.json" },
      "command": "node -e \"const s=require('./<slug>-<version>.cdx.json');process.exit(s.components&&s.components.length?0:1)\"" },
    { "id": "G16-sha256sums", "number": 16, "title": "SHA256SUMS published",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "file", "path": "dist/SHA256SUMS" },
      "command": "sha256sum -c SHA256SUMS",
      "prerelease_na_allowed": true,
      "prerelease_condition": "tag matches ^v[0-9]+\\.[0-9]+\\.[0-9]+-.+$",
      "prerelease_na_reason_fixed": "Prerelease tag: no channel is published and the landing page is not updated for a prerelease, per the prerelease policy; SHA256SUMS is verified against the GitHub Release alone, with no landing-page value to check it against." },
    { "id": "G17-build-attestation", "number": 17, "title": "Build provenance attestation published",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "attestation", "path": "attestation bundle on the GitHub Release" },
      "command": "gh attestation verify <artifact> --owner hansstudy" },
    { "id": "G18-authenticode", "number": 18, "title": "Authenticode signature applied if a certificate exists",
      "tags": ["bin", "mod"], "na_allowed": true, "automatable": true,
      "evidence": { "kind": "file", "path": "docs/verify-downloads.md" },
      "command": "Get-AuthenticodeSignature <file>",
      "na_reason_fixed": "No code-signing certificate held; deferred until a tool shows traction. Release ships Sigstore attestation, SHA256SUMS and verify instructions instead." },
    { "id": "G19-clean-install", "number": 19, "title": "Artifacts install and run on a clean VM/profile",
      "tags": ["bin", "mod", "plg", "skl", "web"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "command-output", "path": "clean-VM or clean-profile install transcript" },
      "command": "claude plugin validate <dir>  # [skl]; runtime-specific install script exit code otherwise" },
    { "id": "G20-telemetry-policy", "number": 20, "title": "Telemetry policy: none by default",
      "tags": ["all"], "na_allowed": false, "automatable": false,
      "evidence": { "kind": "statement", "path": "README and landing page telemetry statement" },
      "command": "manual review against the stated policy" },
    { "id": "G21-support-statement", "number": 21, "title": "Support statement present and honest",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "statement", "path": "README and landing page support statement" },
      "command": "grep -qi 'no SLA' README.md" },
    { "id": "G22-licence-trademark", "number": 22, "title": "Licence file correct; trademark/provenance notes present",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "file", "path": "LICENSE, plus a trademark disclaimer and/or provenance note where applicable" },
      "command": "test -f LICENSE && grep -qi 'Apache License' LICENSE" },
    { "id": "G23-privacy-disclosure", "number": 23, "title": "Privacy: transmissions stated on landing page and privacy policy",
      "tags": ["all"], "na_allowed": true, "automatable": false,
      "evidence": { "kind": "statement", "path": "landing page + /privacy-policy/" },
      "command": "manual review; no single automated command" },
    { "id": "G24-authorized-use", "number": 24, "title": "Authorized-use notice present (template with a required per-tool clause)",
      "tags": ["prod"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "statement", "path": "the filled-in authorized-use template in README, landing page, and startup/help output" },
      "command": "grep -qi 'authoris' README.md && ! grep -q '{{AUTHORIZED_USE_CLAUSE}}' README.md",
      "requires_clause": "AUTHORIZED_USE_CLAUSE (non-empty, tool-specific)" },
    { "id": "G25-landing-page-live", "number": 25, "title": "Landing page live, in collection, nav, and sitemap",
      "tags": ["all"], "na_allowed": false, "automatable": true,
      "evidence": { "kind": "url", "path": "https://hans.study/tools/{slug}/" },
      "command": "curl -fsSL -o /dev/null -w '%{http_code}' https://hans.study/tools/<slug>/",
      "prerelease_na_allowed": true,
      "prerelease_condition": "tag matches ^v[0-9]+\\.[0-9]+\\.[0-9]+-.+$",
      "prerelease_na_reason_fixed": "Prerelease tag: no channel is published and the landing page is not updated for a prerelease, per the prerelease policy; the tool's existing landing page (if any) is unchanged by this release." },
    { "id": "G26-release-blog-post", "number": 26, "title": "Release blog post drafted",
      "tags": ["all"], "na_allowed": false, "automatable": false,
      "evidence": { "kind": "url", "path": "published post, or recorded patch-release no-post decision" },
      "command": "manual review; no single automated command" },
    { "id": "G27-cross-post-preflight", "number": 27, "title": "Cross-post pre-flight signed off",
      "tags": ["all"], "na_allowed": false, "automatable": false,
      "evidence": { "kind": "review-record", "path": "dated sidebar-reading record per target community" },
      "command": "manual review; no single automated command" }
  ]
}
```
<!-- machine-readable: end -->
