# Security review - v1.0.0

Gate `G01-security-review`'s evidence record (`docs/RELEASE-CHECKLIST.md`). This is a summary of
the pre-release security review and its closure verification; it does not reproduce their full
text.

- **Date:** review 2026-09-26; closure verification 2026-09-26.
- **Review:** an independent pre-release security review, followed by an independent closure
  verification of every finding.
- **Verdict:** initial review REVISE (1 MAJOR, 3 MINOR, 8 NOTE); every finding closed on
  re-verification against the current tree. Closure verdict: **PASS**.
- **Record location:** the full review notes and its closure verification are not published in
  this repository; this file is the public-facing summary the checklist gate points to.

## Scope

The whole of this repository (`src/`, `tests/`, `build/`, `docs/`, `profiles/`, `.github/`)
against: the tool's own security requirements; its security-surface design and known residuals;
the static-analysis rules that gate the source; and every finding from the prior review pass.

**Method:** a full read of every source file end to end, tracing each untrusted input (profile
file bytes, `-Set` values, CLI arguments, DNS answers, socket results, environment values, `-Out`)
to its sink, followed by hostile-input testing both in-process and against the built
`dist/PortProof.ps1`. All probing was constrained to loopback addresses (`127.0.0.0/8`, `::1`)
throughout both the review and its closure verification - no host outside loopback was touched at
any point. The PowerShell 7 `-Parallel` scheduler path and real-subnet directed-broadcast/6to4/
NAT64 behaviour were not exercised (no `pwsh` runtime available to the reviewer; those are
loopback-observable-only by design in this environment).

## Findings and dispositions

| # | Severity | Finding | Fix applied | Closure evidence |
|---|---|---|---|---|
| 1 | MAJOR | The JSON profile reader had no whole-document node/value budget: containers nested inside the row list were parsed in full before shape validation, so a crafted (but under the byte-size cap) profile could cost roughly 400 CPU-seconds before being refused. | Added a hard container-depth cutoff (refuses at depth 3, which the schema never needs) plus a total parsed-value counter across the whole document. | The flagship repro now refuses in ~2.7 s (`Profile.TooLarge`); a mixed-nesting variant refuses via a new `Profile.JsonDepth` id in well under 25 ms; boundary values at exactly the new budget and one over it both refuse correctly (no off-by-one gap). A same-shaped object (rather than array) variant is a documented residual - see below. |
| 2 | MINOR | IPv4 addresses embedded in NAT64/6to4/Teredo/IPv4-compatible/IPv4-mapped IPv6 forms were admitted without the ordinary refused-class check applying to the embedded address, and this was undocumented. | Ruled acceptable to admit for v1.0.0 (exploiting it needs a tunnel/translator most hosts do not run by default), but it must be documented. Added a README limitations bullet and a threat-model entry. | All originally-cited forms plus eight additional reviewer-constructed variants (case folding, leading zeros, a zone id on an embedded form, dotted-decimal NAT64 tails) are each classified correctly and documented; nothing changed the admission behaviour, only its disclosure. |
| 3 | MINOR | Control characters (C0 and C1) inside the profile's `Service`/`Notes` (and JSON `name`/`version`) fields reached the CSV and HTML output files unescaped - a terminal-injection risk if the CSV is later viewed with `type`/`cat`. | Extended the existing control-character refusal rule (previously only applied to `Source`/`Target`) to these fields at parse time. | Both raw control bytes and `\u00XX`-escaped forms are refused at parse time for every affected field, verified across both the CSV and JSON paths. |
| 4 | MINOR | No automated check compared the committed `dist/PortProof.ps1` to a fresh build of `src/`; freshness depended on process discipline (the rebuild-and-record step), not a gate. | Added a Full-suite test that rebuilds from `src/` and byte-compares the result to the committed `dist/`. | The new dist-drift test passes as part of the Full suite; a fresh rebuild's SHA-256 matches the committed file's SHA-256 exactly. |
| 5 | NOTE | The authorized-use clause's working wording has four small gaps (it does not mention `-Icmp` echo requests, name-resolution traffic, that `-Set` can also choose targets, or that the UDP adapter reads one discarded reply datagram). | No code change - the exact wording is a decision reserved for the tool's owner and is already tracked as its own open item, independent of this review. | Not applicable; this is a documentation-wording item, not a code defect, and remains open pending that decision. |
| 6 | NOTE | Writing an output file followed filesystem reparse points, so a symlink or junction planted at the exact `-Out` path by another local account with write access to that directory could redirect the write. | Output paths that are, or already are, a reparse point are now refused before any write. | A junction and a dangling junction placed at the `-Out` path each refuse cleanly with nothing written. A reparse point placed above (an ancestor of) `-Out`, rather than at `-Out` itself, is an explicit, documented design boundary - not a gap - since checking every ancestor directory the operator chooses is out of this tool's scope. |
| 7 | NOTE | The static-scanner command allowlist carried several unused entries and one comment that no longer matched the scanner's actual behaviour. | Pruned the allowlist to exactly the commands the source actually calls and corrected the comment. | The allowlist now has a small, fully-used entry set, confirmed by cross-checking every entry against the source. |
| 8 | NOTE | With operator identity redacted, one timestamp field still carried a local UTC offset, a weak residual location hint. | That timestamp is now emitted in UTC when operator identity is redacted. | Verified on a real redacted run. |
| 9 | NOTE | The tool's core function (probing hosts a supplied profile names) is inherently usable to have an operator scan on a third party's behalf, and each resolved hostname is also a signal to whoever runs that DNS zone; this is inherent to the feature, not a defect. | Documentation only: a README line recommending review of the `-DryRun` target list before running a profile received from someone else. | Text present in the README; a stronger per-run allow-list is noted as a future-version idea, not a v1.0.0 requirement. |
| 10 | NOTE | The README's install instructions named a broader execution-policy bypass than necessary for the documented steps. | Narrowed the documented command to the minimum sufficient policy setting. | Verified in the README. |
| 11 | NOTE | A subnet directed-broadcast address supplied as a literal target is not refused as its own class. | Ruled a documented residual for v1.0.0 (see below), grouped with finding 2. | Documented alongside finding 2. |
| 12 | NOTE | Supply-chain review of the CI/release workflows, helper scripts and schemas. | No fix needed. | Confirmed byte-identical to the shared templates, every third-party action pinned to a full commit SHA, minimal default permissions, and no workflow triggered by untrusted input. |

## Accepted residuals

- **The object-shaped variant of finding 1** refuses correctly but takes about 32 seconds
  (measured 31.7 s) rather than the array variant's ~2.7 seconds, because reading object members
  costs more per element than the array fast path. It is still bounded and still refuses
  (`Profile.TooLarge`) well under any operational timeout - accepted as a performance
  characteristic of a rejected input, not a safety bypass.
- **Embedded-IPv4-in-IPv6 forms** (finding 2) and **directed-broadcast literals** (finding 11)
  remain admitted in v1.0.0; both are now documented in the README and the threat model, and a
  tighter address-table extraction is deferred to a later release.
- **A reparse point placed above `-Out`**, rather than at the `-Out` path itself, is intentionally
  out of scope: the operator's own ancestor directories are the operator's choice, not a boundary
  this tool checks.
- **The authorized-use clause wording** (finding 5) is not a code change for this review; it is
  tracked as its own open decision, reserved for the tool's owner.
- **The PowerShell 7 `-Parallel` scheduler path and real-subnet directed-broadcast/6to4/NAT64
  behaviour** were not exercised by either the review or its closure verification (no PowerShell 7
  runtime was available, and all probing was constrained to loopback addresses throughout).

## Closure

A follow-up verification pass re-ran every finding above against the current tree (after the
fixes were applied) and additionally ran the full test suite, the lint check and all nine static
scanners. Every finding closed with a working reproduction; no refused address class was admitted
on any tested path (literal, `-Set`-bound group, or resolved hostname); no probe cap was
exceeded; no dynamic code execution occurred; and no write landed outside the operator-chosen
output location. The rebuilt `dist/PortProof.ps1` was byte-identical to both a fresh build from
`src/` and to the hash recorded for this closure. Closure verdict: **PASS**.
