# PortProof test harness

Loopback only, unless you explicitly opt in. `Listeners.ps1` never binds, connects, or sends
anywhere off `127.0.0.0/8` - `Assert-PPLoopbackAddress` throws before it would. `FixtureResolver.ps1`
never touches DNS (it is a hashtable lookup), and its `Get-PPFixtureResolver` guard checks every
address a `Resolve` call is about to return: an address outside `127.0.0.0/8` or `::1` throws a
named `PortProofTest.NonLoopbackAddress` error instead of resolving, unless
**either** the table entry is explicitly marked `RefusedClass` (the AC15 resolved-class fixtures
below - they must resolve to a refused address so the Gate's own class-check can be proven against
them, though nothing is ever probed there: the Gate refuses the address before scheduling
any socket) **or** `Test-PPOffHostOptIn`'s condition is true (the single opt-in gate, next section -
`FixtureResolver.ps1` checks the same two environment variables inline rather than calling that
function, since a `GetNewClosure()` scriptblock cannot reliably resolve a cross-file function once
invoked from inside a test framework's own scope). `tests/Harness/Harness.Tests.ps1` proves both
halves: a plain non-loopback entry throws, and every entry actually committed in
`resolver-table.json` is either loopback or `refused_class: true`.

## Opt-in variables (AC6, off-host, local only)

By default no test contacts anything off this host. Two environment variables opt individual
timeout-behaviour cases in, and both are unset in every CI lane (the template `ci.yml` defines
neither, so this is exercised only by a verifier who opts in locally):

- `PORTPROOF_TEST_OFFHOST=1` - runs the TEST-NET-1 (`192.0.2.1`) timeout fixture, and also lifts
  the FixtureResolver's loopback-only guard for any table entry (see above).
- `PORTPROOF_TEST_TIMEOUT_TARGET=<address>` - names a locally blackholed address to use instead.

`Test-PPOffHostOptIn` (in `Harness.ps1`) is the single place that checks these; a test that needs
the opt-in calls it and marks itself `SKIPPED` when it returns `$false`, and it is off by default
(a dedicated test asserts this). Neither variable turns on anything for the ordinary
listener/scheduler tests - those already run entirely against `127.0.0.0/8` regardless.

## What is in here

- `Harness.ps1` - repo/part-path lookup, the built-artifact cache, in-process and child-process
  invocation helpers, ephemeral fixture-profile writing, the loopback-address allocator
  (`Get-PPLoopbackAddress`, distinct `127.0.0.2`-`127.0.0.250` per run), and the off-host opt-in
  gate.
- `Listeners.ps1` - `Open-PPTcpListener` (`Accept` or `RefuseAfterOne`), `Open-PPUdpListener`
  (optionally replying once), `Get-PPUnboundPort`, `Close-PPListener`. Each listener exposes
  `Address`, `Port`, and a `ConcurrentQueue` of `Stopwatch` timestamps for every accepted
  connection or received datagram.
- `Recorder.ps1` - `Initialize-PPRecorder`, `Invoke-RecordingAdapter` (the AC29 adapter injected in
  place of the real TCP/UDP/ICMP adapters so concurrency peak and per-target overlap become
  observable), `Measure-PPPeakOccupancy`, `Measure-PPOverlap`.
- `FixtureResolver.ps1` - `Get-PPFixtureResolver`, a table-driven Resolver seam implementation that
  never touches DNS and enforces the loopback-only guard above; `Get-PPResolverTableFixture`, which
  loads `resolver-table.json` into the hashtable shape `Get-PPFixtureResolver` expects.

## Adding a fixture

- A **listener-backed** fixture (a profile that must hit a live loopback port) is generated at run
  time with `Write-PPFixtureProfile`, because the port is ephemeral and cannot live in a committed
  file. Call `Get-PPLoopbackAddress` for the address, open the listener you need, then write the
  profile into `$TestDrive`.
- A **static** fixture (malformed profile, refused literal, hostile string) is a committed file
  under `tests/Fixtures/`. Put it in `valid-*`, `invalid-*`, `hostile-*`, `refused-*`, or
  `corpus/` (add a row to `corpus/cases.csv` naming the file, the expected `PortProof.*` error id,
  and a short note) as appropriate. CSV or JSON only - never a `.psd1`, and never a planted static-
  analysis violation (generate that into `$TestDrive` at run time instead, so the static scanners
  never see it in a committed file).
- A **name-resolution** fixture adds an entry to `resolver-table.json` (or a table literal passed
  straight to `Get-PPFixtureResolver`) rather than a real hostname. Each entry is either
  `{ "addresses": ["127.x.x.x", ...] }` (must be loopback, or the guard above throws) or, only for
  an intentional AC15 resolved-class case, `{ "addresses": [...], "refused_class": true }`. An AC30
  fixture (multiple addresses for one name, two names sharing one address) uses several *distinct*
  `127.x` addresses so the assertions about which address won and which names coalesced are real.
