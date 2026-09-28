# Release checklist mapping

Maps every gate in `docs/RELEASE-CHECKLIST.md` (checklist_version 3, 27 gates) to how PortProof
answers it. `artifact_kinds: ["mod", "prod"]` (`.github/release-config.yml`) is the authoritative
scope (`RELEASE-CHECKLIST.md` "Applicability tags"): every gate below is tagged `[all]`, `[mod]`
(or `[bin, mod]`), or `[prod]`, and all three sets are in scope for this repo, so **every gate
applies** - there is no tag combination that excludes a gate here.

"Planned status" is what `docs/releases/v1.0.0/release-evidence.json` is expected to record once
every release-time action below has happened; it is not itself the evidence file, and it is not a
claim that any given gate is satisfied today - see that file for the current, honest per-gate
status. `G24-authorized-use` no longer needs a separate call-out: the Maintainer approved the
clause wording on 2026-09-26 (see "Decisions recorded" below), so its remaining work is the same
kind of release-time/evidence-recording action as the other gates below.

| Gate id | Tags | Applies to `["mod","prod"]` | Planned status | Evidence path | Owner |
|---|---|---|---|---|---|
| G01-security-review | all | yes | pass | `docs/security-review.md` (independent pre-release security review, closed) | Maintainer |
| G02-secret-scan | all | yes | pass | `gitleaks` scan output attached to the release PR; repo secret scanning + push protection on | Maintainer |
| G03-threat-model | all | yes | pass | `docs/threat-model.md` | Maintainer |
| G04-dependency-alerts | all | yes | pass | Dependabot alerts list, zero open High/Critical | Maintainer |
| G05-dependency-pinning | all | yes | pass | `.github/workflows/*.yml` (every `uses:` pinned to a 40-hex commit SHA); `PortProof.psd1` has no floating `RequiredModules` | Maintainer |
| G06-content-provenance | all | yes | pass | `docs/content-provenance.md` | Maintainer |
| G07-least-privilege | all | yes | pass | `README.md` Requirements / least-privilege section | Maintainer |
| G08-redaction | all | yes | pass | `README.md` "Output sensitivity" section (`-NoOperator`, no general redaction) | Maintainer |
| G09-readme-complete | all | yes | pass | `README.md`, install one-liner transcript | Maintainer |
| G10-changelog-entry | all | yes | pass | `CHANGELOG.md` `## [1.0.0] - <date>` entry | Maintainer |
| G11-semver-consistent | all | yes | pass | git tag, `PortProof.psd1` `ModuleVersion`, README badge, landing page frontmatter (all `1.0.0`) | Maintainer |
| G12-screenshots-demo | all | yes | pass | `docs/samples/matrix.png`, `run.gif`, `console.txt` (lab data only) | Maintainer |
| G13-docs-links | all | yes | pass | README doc links resolve; `https://hans.study/tools/portproof/` linked both ways (landing page) | Maintainer |
| G14-ci-built | all | yes | pass | `release.yml` Actions run for the `v1.0.0` tag push | Maintainer |
| G15-sbom-published | all | yes | pass | `dist/portproof-1.0.0.cdx.json` on the GitHub Release | Maintainer |
| G16-sha256sums | all | yes | pass | `dist/SHA256SUMS` on the GitHub Release | Maintainer |
| G17-build-attestation | all | yes | pass | Sigstore attestation bundle; `gh attestation verify dist/PortProof.ps1 --owner hansstudy` | Maintainer |
| G18-authenticode | bin, mod | yes (mod) | **N/A** - reason (fixed, verbatim per `RELEASE-CHECKLIST.md`): "No code-signing certificate held; deferred until a tool shows traction. Release ships Sigstore attestation, SHA256SUMS and verify instructions instead." | `docs/verify-downloads.md` | Maintainer |
| G19-clean-install | bin, mod, plg, skl, web | yes (mod) | pass | a clean-VM (or clean-profile) install/run transcript of `dist/PortProof.ps1 -Version` and a `-DryRun`, plus documented uninstall/removal | Maintainer |
| G20-telemetry-policy | all | yes | pass | `README.md` "Telemetry" section states the tool collects no telemetry and does not phone home or transmit anything about its use - satisfies the gate's "no telemetry" evidence option | Maintainer |
| G21-support-statement | all | yes | pass | README support section states there is no SLA, plus the engagement link | Maintainer |
| G22-licence-trademark | all | yes | pass | `LICENSE` (Apache-2.0, copyright holder Hans Study); `NOTICE` (Microsoft trademark disclaimer) | Maintainer |
| G23-privacy-disclosure | all | yes | pass | landing page + `/privacy-policy/` statement (tool transmits nothing beyond declared probes) | Maintainer |
| G24-authorized-use | prod | yes | pass | clause approved by the Maintainer 2026-09-26; present in `src/05-Contract.ps1`, `src/00-Header.ps1` (help/startup output) and `README.md` (report header echoes the same clause via `AuthorizedUseNotice`) | Maintainer |
| G25-landing-page-live | all | yes | pass | `https://hans.study/tools/portproof/` (200, in `tools` collection, nav, sitemap) | Maintainer |
| G26-release-blog-post | all | yes | pass | published launch article, or recorded "no post" decision | Maintainer |
| G27-cross-post-preflight | all | yes | pass | a dated sidebar-reading record for each target community, plus authorship disclosure and the repo-link rule (the gate's own evidence requirement) | Maintainer |

All 27 gates now have a planned "pass" (`G18` and `G23` are `N/A`/na, not pass, as their rows
record); see `docs/releases/v1.0.0/release-evidence.json` for which of the "pass"-planned gates
already hold today versus which still need a release-time action (tag push, live repo, clean
machine, live site) to become true. Verified with a synthetic evidence file against
`check-release-evidence.mjs` in a scratch directory (not committed) -
`ok: 27 applicable gate(s) accounted for`.

## Open items

None outstanding for this mapping. The former `AUTHORIZED_USE_CLAUSE` wording decision is closed;
see "Decisions recorded" below.

## Records

- **No CI deviation.** `.github/workflows/ci.yml` and `release.yml` carry no repo-local job beyond
  the shared release pipeline.
- **`mod`-with-minimal-manifest choice.** PortProof ships as a single script
  (`dist/PortProof.ps1`), not a real PowerShell module, but the release pipeline's artifact-kind
  vocabulary has no `script` kind and hard-fails a `runtime: powershell` release with no `.psd1`.
  `artifact_kind: "mod"` is declared and `PortProof.psd1` is a minimal manifest with
  no `RootModule`, no exports, and no `RequiredModules` key at all. `PortProof.psd1` is the only
  `.psd1` within three directory levels (AC35).
- **`test_command` form, and why it starts with `powershell`.** The CI pipeline's Windows test and
  lint lanes refuse any `test_command`/`lint_command` whose first word is not
  `powershell`/`powershell.exe`, and the release job installs a `powershell` -> `pwsh` shim on
  ubuntu so the same string runs Windows PowerShell 5.1 on the Windows lane and PowerShell 7 in the
  release job. `test_command` is therefore `powershell -NoProfile -NonInteractive -File
  tests/Invoke-Tests.ps1`, not a plain `pwsh ...` string, which would have failed the Windows lane
  at its first step.
- **No CI run exercises the TEST-NET case.** The CI pipeline sets no `PORTPROOF_TEST_OFFHOST`
  variable, so the off-host listener case is local opt-in only; no GitHub Actions run in this repo
  exercises it. This is a recorded, accepted gap, not an oversight.
- **The 5.1 floor is proven by the Windows test lane**, under `powershell.exe` (Windows
  PowerShell 5.1); the release job re-runs the portable subset of `Invoke-Tests.ps1` under `pwsh` 7
  on `ubuntu-latest` as a release precondition, not as the 5.1 proof.
- **Unresolved-token scan.** The whole-tree scan for unresolved double-brace-bracketed markers excludes
  exactly two verbatim upstream copies: `docs/RELEASE-CHECKLIST.md` and
  `.github/workflows/scripts/check-release-evidence.mjs` (both carry the double-brace
  `ARTIFACT_KIND`/`AUTHORIZED_USE_CLAUSE` markers literally, documenting the checklist's own G24
  command - not unresolved tokens in this repo's own text). No other path is excluded, which is why
  this document names every token below by its bare identifier and never wraps one in double
  braces.

## Decisions recorded (formerly release-blocking, now closed)

- **Copyright holder - decided.** Confirmed as **Hans Study** - the value used throughout the repo
  is final, not a placeholder. No pending-holder marker remains anywhere in `NOTICE`,
  `PortProof.psd1`, `README.md` or `SECURITY.md`; `LICENSE` line 189 carries the name directly. All
  five files agree: `LICENSE`, `NOTICE`, `PortProof.psd1` (`Author`, `CompanyName`, `Copyright`
  fields), `README.md` (byline and Third-party content section), and `SECURITY.md` (footer line).
  `G22-licence-trademark` closes as `pass`.
- **Security contact - decided.** Confirmed as **bugs@hans.study**, for everything. No
  pending-contact marker remains in `README.md`'s Security section or `SECURITY.md`'s "Reporting a
  vulnerability" section. Both name **bugs@hans.study** as an alternative alongside GitHub private
  vulnerability reporting, which remains the preferred channel.
- Verification: a whole-tree search for pending-marker text turns up no live marker in any source
  file.
- **`AUTHORIZED_USE_CLAUSE` wording - decided.** The Maintainer approved the clause text on
  2026-09-26. All three byte-identical copies (`src/05-Contract.ps1`'s `AuthorizedUseClause`,
  `src/00-Header.ps1`'s help text, and `README.md`'s "Authorized use" section) were edited
  together to the approved wording; the `AUTHORIZED-USE-NOTICE` marker comment next to each copy
  is unchanged and still records that they must stay byte-identical. `dist/PortProof.ps1` was
  rebuilt from `src/` (drift-gated), and `tests/Golden/*` and `docs/samples/*` were regenerated to
  carry the new wording. `G24-authorized-use` closes as `pass`.
