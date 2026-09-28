# PortProof threat model

This document
maps what PortProof is designed to do, refuse, and leave unmitigated; it is a design-level map, not
a test report, and nothing in it should be read as a verification claim. Behaviour attributed to the
parser, expander, resolver, or probe engine is described as the design specifies it, because those
components are implemented and verified separately from this document. The independent pre-release
security review's findings are recorded separately, at `docs/security-review.md`.

## Assets

- **The output artifact** (HTML, CSV, and/or JSON report): a map of which declared network paths are
  open, closed, or inconclusive, including hostnames, resolved IP addresses, ports, protocols, and
  — unless `-NoOperator` is given — the operator's user name and host name.
- **The operator host**: the single machine that runs PortProof. It is the sole origin of every
  probe, so it is also the machine whose own resources (handles, runspaces, network egress) a
  hostile or oversized profile could try to exhaust, and the machine whose console/output a hostile
  profile's text could try to abuse.

## Actors

- **Operator.** Runs PortProof against systems they own or have written authorisation to assess, and
  is responsible for what they do with the output.
- **Malicious or careless profile author.** Anyone who can hand the operator a `.csv`/`.json`
  profile, or supply a `-Set`/JSON `groups` value — a vendor, a colleague, or a compromised
  intermediate source. The profile is untrusted input by design (it "arrives by email from a
  vendor").
- **Report recipient.** Whoever the operator sends the HTML/CSV/JSON artifact to — a change board, a
  ticket system, an email thread. May open the HTML in a browser, the CSV in Excel, or feed the JSON
  into a pipeline.
- **IDS/SOC on the probed network.** Observes the probe traffic and the run header's authorship
  fields, and may correlate them. PortProof does not defend against this actor, but its behaviour
  (rate limit, no evasion, no retries beyond the OS's own SYN retransmission) is designed not to
  look like an attack, and the authorized-use notice and run header exist partly for this actor's
  benefit — a defensible paper trail for the operator, and a readable signal for whoever reviews the
  traffic.

## Trust boundaries

| Boundary | Crossed at | Untrusted input |
|---|---|---|
| Profile file | the parser (`Import-PPProfile`) | the CSV/JSON bytes as delivered — arrives by email from a vendor |
| `-Set` values and JSON `groups` | the expander (`Expand-PPProfile`) | command-line and in-profile group bindings, one grammar for both |
| Name resolution | the resolver (`30-Resolver.ps1`) | whatever DNS — or LLMNR/NetBIOS/mDNS, for a single-label/`.local` name — returns |
| The network | the Gate, Scheduler, and adapters | every reply, refusal, or non-reply from a probed host |
| Output directory | output writing (`Write-PPOutputFile`) | wherever `-Out` points, and who else can read what lands there |

## Abuse cases

- A hostile profile supplies a refused address class (this-network, limited broadcast, multicast,
  link-local, or the unspecified address) as a literal target, inside a CIDR group, or as a name
  that resolves there, trying to make PortProof probe it anyway.
- A hostile profile tries to make PortProof write outside its resolved output directory, or
  overwrite a file it should not, via a crafted `Service`, `Notes`, or group value reaching a path.
- A hostile profile tries to make a rendered report execute something when it is opened: a formula
  injected into Excel via the CSV, a script tag or `javascript:` URL smuggled into the HTML, or a
  broken JSON escape that corrupts the document structure for a downstream parser.
- A hostile profile tries to exhaust the operator's own host — excessive rows, excessive expansion
  via groups/CIDR/lists, or a shape designed to leak runspaces or socket handles — turning PortProof
  into a denial-of-service against the machine running it, rather than against the target network.
- A hostile profile tries to make PortProof exceed its declared probe cap, or resolve and probe more
  than the profile as written actually expands to (the pre-resolution-vs-post-expansion distinction
  the cap arithmetic exists to close).
- A profile author (or a name reachable only via LLMNR/NetBIOS/mDNS) causes PortProof's DNS
  resolution step to emit multicast traffic to network classes PortProof would otherwise refuse to
  probe directly — not a probe, but traffic the operator did not explicitly declare.
- **Port-scan-by-proxy.** Anyone who can hand the operator a profile — a vendor, a colleague, a
  compromised intermediate source — chooses every target and port it declares. PortProof probes
  exactly what the profile (and any `-Set` override) names, so a profile is effectively a request
  to scan on the profile author's behalf, aimed at anything on the operator's network the operator
  host can reach that is not a refused address class. This is inherent to the tool's purpose (it
  has to probe what it is told to), not a bug; it is mitigated only by the cap, the `-DryRun`
  listing, and the authorized-use notice — never by PortProof judging the profile's intent.
- **DNS-as-signal, independent of any probe.** Resolving a name in a profile is a DNS (or
  LLMNR/mDNS) query sent before any TCP/UDP/ICMP probe. Whoever controls the authoritative zone for
  a name the profile author supplied learns that the profile was run, and roughly when, regardless
  of the probe outcome — an outbound signal distinct from, and not covered by, PortProof's own "no
  telemetry" claim.
- Someone relies on the README's SmartScreen/execution-policy guidance being read out of context as
  "disable your protections," rather than as a scoped, ordered, last-resort step (verify, then
  `Unblock-File`, then `RemoteSigned` at process scope only if still needed).

## Mitigations — the twelve safe-default invariants

Each row is enforced in code and proved by a criterion that observes behaviour, not configuration.

| # | Invariant | Enforced by | Proved by |
|---|---|---|---|
| 1 | Targets are an explicit list. A CIDR group is refused without `-AllowCidr`, and refused beyond `/24` with it. No discovery mode exists. Refused target classes are refused as literals **and** as resolved addresses, after IPv4-mapped canonicalisation. | Parser refusal on literals; the Gate's class check on every resolved address before any socket; one predicate in `05-Contract.ps1` | AC15, AC30 |
| 2 | No port ranges, ever. One port per row. | `Port` domain check, row-numbered | AC9, AC31 |
| 3 | The admitted probe list cannot exceed 1024 by default or 8192 ever. Every argument range is enforced in the body with exit 2; `-AllowLarge` raises only the ceiling; the Expander's pre-resolution count is an early exit that never resolves an over-cap list. | `Assert-Arguments`, fixed `AbsoluteProbeCeiling = 8192`, `35-Gate.ps1` | AC8, AC30 |
| 4 | Rate limit, concurrency cap, per-target serialisation (target = canonical resolved IP), and exactly one connection attempt per probe. | Scheduler token bucket, pool size, per-target lock held on both execution paths | AC29 |
| 5 | No SYN scanning, no raw sockets, no evasion. Full connect via `TcpClient.BeginConnect` with an explicit wait handle. | Implementation; static prohibition scan | AC16 |
| 6 | No payloads. TCP closed immediately after connect, nothing read or written. UDP sends a zero-length datagram; the UDP adapter is the only file permitted to receive. | Implementation; per-file static scan | AC16 |
| 7 | The authorized-use notice is printed on every run that reaches probing or `-DryRun`, on the information stream, and cannot be suppressed by any flag. A run refused at the argument-check stage (`Assert-Arguments`, before the notice prints) exits before the notice ever appears — that refusal sends nothing, so the notice's absence carries no risk, but it is not printed on every invocation, only on every one that gets past argument validation. | Entry-point ordering; stream choice | AC20 |
| 8 | `-DryRun` sends no probe and performs no name resolution; it reads only the named profile and creates nothing. | One Resolver seam (`30-Resolver.ps1` is the only file that may reference `System.Net.Dns` or any resolving API); adapters accept `[IPAddress]` only; `-DryRun` installs a refusing resolver stub whose `Resolve` throws | AC11 |
| 9 | No credential logic anywhere. | Absence; static scan over comment-stripped source | AC17 |
| 10 | The profile schema is fail-closed: every closed domain refuses, and no malformed profile can produce a run. | Parser domains; unknown-column policy | AC31 |
| 11 | Output containment: every file inside the resolved `-Out`, no profile field reaches a path, no overwrite without `-Force`. | Path construction from fixed names only | AC21 |
| 12 | No outbound call other than the declared probes. No telemetry, no update check, no remote reference in the HTML. | Absence; static scan; attribute-scoped HTML scan | AC14, AC18 |

## Additional controls

- **Output content is untrusted in every channel.** Console and error text pass through
  `Get-PPSafeText`, which strips control characters (including ESC) from every profile-derived
  string. HTML passes through an own escaper plus a `default-src 'none'` CSP meta tag (defence in
  depth: even an escaping defect could not run script or fetch anything). CSV passes through one
  field encoder applied to every field, header records included, with formula-trigger neutralisation.
  JSON passes through an own escaper. File names come only from a fixed table, never from a profile
  value.
- **CI supply chain.** GitHub Actions are SHA-pinned; PSScriptAnalyzer and Pester are installed from
  PSGallery at exact pinned versions, only in CI, and only when the pinned version is absent.
- **Code transported into runspaces** is limited to the tool's own already-loaded functions, read via
  `Get-Command`, never text originating from a profile.

## Residual risks

- **No general redaction.** The output is, by design, a map of a network's open paths: it
  names hosts, IPs, the operator (unless `-NoOperator`), and which controls are absent. The
  mitigation is containment (AC21), `-NoOperator`, and the README's "Output sensitivity" section —
  not redaction. There is no general redaction feature in v1, and the README must not imply
  otherwise.
- **UDP rows prove less than TCP rows.** `Open|Filtered` is an honest "could not tell the
  difference," never a claim of an open port; a report reader who treats it as a pass is
  misreading it, not PortProof misreporting it.
- **A name whose resolved address set contains a refused-class address refuses the whole run**, even
  when the first address DNS returned is ordinary. The workaround is to use the literal address
  instead of the name.
- **`-Out` placement, and who can subsequently read the output files, is entirely the operator's
  choice.** PortProof has no access-control mechanism over its own output; this is documented, not
  mitigated.
- **A caller can discard the information stream** with `6>$null`. The authorized-use notice is
  emitted on every run, but emission is not the same guarantee as being read.
- **Resolving a single-label or `.local` name causes the OS resolver to send LLMNR/NetBIOS/mDNS
  multicast queries**, not a PortProof probe, but traffic reaching network classes PortProof
  otherwise refuses to target directly. The README's Limitations section names this and recommends
  fully-qualified names or literals.
- **A name ending `.ipv6-literal.net` is refused at parse time rather than resolved**, specifically
  because Windows would otherwise map it to an IPv6 literal without a DNS query — bypassing the
  resolved-address class check that depends on a name actually going through resolution.
- **IPv6 forms that embed an IPv4 address are checked against the IPv4 refused classes.** `::/96`,
  `::ffff:0:0/96`, `64:ff9b::/96`, and 6to4/Teredo forms are checked the same way a plain IPv4
  literal is, so an embedded this-network, broadcast, multicast, or link-local address is refused
  rather than admitted just because the wrapper looks like an ordinary IPv6 literal.
- **A subnet's directed-broadcast address cannot be recognised as such without the subnet's
  netmask.** PortProof refuses the global broadcast address and every expanded CIDR's own
  network/broadcast pair, but a directed-broadcast literal for a subnet PortProof was never told
  about is an ordinary-looking host address to the parser, and is admitted. This is a residual, not
  a control gap PortProof can close on its own: the property "this address is a subnet's broadcast
  address" does not exist without the netmask that defines it.
- **Port-scan-by-proxy is inherent to the tool's purpose.** A profile chooses its own targets;
  PortProof has no way to judge whether the operator should trust the profile's author, only
  whether an individual target address falls in a refused class. See "Port-scan-by-proxy" under
  Abuse cases; the mitigation is operator practice (read the profile, review `-DryRun`), not a
  technical control.
- **Resolving a profile's names is an outbound signal of its own**, independent of any probe — see
  "DNS-as-signal" under Abuse cases. This is not telemetry PortProof sends, but it is traffic the
  operator did not necessarily intend to disclose to the name's authoritative zone.

## Out of scope for this document

Findings that require reading the implementation directly — control-flow tracing, mutation
evidence, dependency-pinning verification, and a judgement call on the SmartScreen/execution-policy
wording — are the independent pre-release security review's job, not this document's. Its record is
`docs/security-review.md`.
