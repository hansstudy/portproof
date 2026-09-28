# Security Policy

## Supported versions

Only the latest published release of PortProof receives security fixes. There is no
long-term-support branch; upgrade to the latest release to pick up a fix.

| Version | Supported |
|---|---|
| Latest release | yes |
| Anything older | no - upgrade first |

## Reporting a vulnerability

Please report suspected vulnerabilities privately, not in a public issue.

Preferred: use **GitHub private vulnerability reporting** on this repo (Security tab ->
"Report a vulnerability"). It is enabled on this repo. Alternative: email **bugs@hans.study**.

Please include: the affected version/tag, a description of the issue, reproduction steps or a
proof of concept, and the potential impact. Do not include live credentials or customer data in
a report.

## Response window

Acknowledgement within **5 business days**. A fix or a mitigation plan within **30 days** for a
confirmed high/critical issue, longer for lower-severity findings, communicated back to the
reporter. This is a best-effort window from a solo maintainer, not a contractual SLA - see the
README's own support statement.

## Scope

PortProof scans ports; that it does so is not a vulnerability. Opening a TCP connection or
sending a UDP datagram to a host and port named in the operator's own profile, on the
operator's own authorisation, is the tool's documented function, not a finding.

In scope:

- **Escaping the declared scope** - any code path that reaches a target, port, or protocol not
  named (directly or via group/CIDR expansion) in the loaded profile.
- **Containment failures** - the Gate's cap (`AbsoluteProbeCeiling`), rate limiting, or refused
  address classes (section 5) being bypassable by profile content, `-Set` values, or CIDR input.
- **Cap bypass** - any path that reaches the scheduler with more probes admitted than the
  effective cap, or that resolves/probes before the early-exit check has run.
- **`-DryRun` leaks** - any socket, DNS query, or other network I/O performed while `-DryRun` is
  set; the refusing resolver stub must be the only resolver installed on that path.
- **Probing beyond the profile** - any probe emitted for a target, port, or protocol that is not
  a member of the expanded, deduplicated probe list the parser and expander produced from the
  profile actually loaded.

Out of scope: that the tool can be pointed at a network the operator does not own (the
authorized-use notice addresses that, not this policy); a vendor SDK, product, or platform this
project's profiles describe but do not vendor; social engineering; denial of service against
GitHub's own infrastructure; issues that require an already-compromised host to exploit.

## Disclosure

Coordinated disclosure preferred. Please allow the response window above to elapse (or a fix to
ship) before public disclosure. Credit is given in the release notes unless the reporter asks to
stay anonymous.

---

Copyright 2026 Hans Study. See `NOTICE` and `LICENSE`.
