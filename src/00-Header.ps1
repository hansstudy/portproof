<#
.SYNOPSIS
PortProof - prove the firewall paths a profile declares are open; probe nothing else.

.DESCRIPTION
PortProof reads a profile (CSV or JSON) that lists the network paths a system needs - source,
target, port, protocol, and whether the path is required - and makes exactly one connection
attempt per declared path. It reports a pass/fail matrix and exits 0 when every required path
passed, so it can gate a change window. It never scans ranges, never discovers hosts, and never
probes anything the profile does not name.

AUTHORIZED USE
Run this only against systems you own or have written authorisation to assess.
It sends TCP connects, UDP datagrams and (with -Icmp) ICMP echoes to the hosts and ports the profile and -Set declare, plus DNS lookups for host names. It does not exploit or log in to anything and reads only what classifies each port.
You are responsible for handling that output and for having permission to run it.

.PARAMETER ProfilePath
-Profile <path>. Required. Path to a .csv or .json profile. The parameter is -Profile on the
command line (ProfilePath is its internal name). Checked in the script body: a missing value or
another extension exits 2.

.PARAMETER Set
NAME=VALUE group bindings for %NAME% references in the profile. Several bindings go in one
string separated by ';' (for example -Set 'CLIENT=10.0.0.5;DC=dc01.corp.example'), because
PowerShell refuses a parameter given twice. VALUE is a host name, an IP literal, a comma list of
those, or (only with -AllowCidr) one IPv4 CIDR prefix of /24 to /30.

.PARAMETER Out
Output directory. Every report file is written here and nowhere else; it is created if absent
(never under -DryRun). Without -Out, a single -Format Csv or Json document goes to the success
stream and nothing is written to disk.

.PARAMETER Format
Html, Csv, Json, as a comma list in one string (for example -Format Html,Json). Default with -Out:
all three. Html, or more than one format, needs -Out.

.PARAMETER Timeout
Milliseconds to wait for each probe. Range 100..30000. Default 2000.

.PARAMETER Concurrency
Number of targets probed at the same time; probes to one address never overlap. Range 1..64.
Default 16.

.PARAMETER MaxProbesPerSecond
Global rate limit on probe starts, in probes per second. Range 1..500. Default 50.

.PARAMETER Jitter
Maximum random delay before each probe, in milliseconds. Range 0..5000. Default 250.

.PARAMETER MaxProbes
Your cap on the number of admitted probes. Range 1..1024, or 1..8192 with -AllowLarge. Default:
the ceiling in force (1024, or 8192 with -AllowLarge). No parameter raises the 8192 ceiling.

.PARAMETER AllowLarge
Switch. Raises the probe ceiling from 1024 to 8192 and no further. -MaxProbes still binds.
Recorded in the run header Flags.

.PARAMETER AllowCidr
Switch. Permits a group bound to one IPv4 CIDR prefix of /24 to /30 (network and broadcast
addresses excluded). Recorded in the run header Flags.

.PARAMETER Icmp
Switch. Adds one ICMP echo per distinct resolved target. These count against the cap, are
rate-limited and serialised like every other probe, and never decide the exit code.

.PARAMETER DryRun
Switch. Prints the probe list, the probe count and a worst-case duration, then exits. Sends no
probe, resolves no name, and creates nothing (not even -Out).

.PARAMETER NoOperator
Switch. Records OperatorUser and OperatorHost as "redacted" in the run header.

.PARAMETER Force
Switch. Permits overwriting existing report files in -Out.

.PARAMETER Quiet
Switch. Suppresses progress output only. The authorized-use notice and the summary still print.

.PARAMETER Version
Switch. Prints the version and exits 0.

.EXAMPLE
.\PortProof.ps1 -Profile .\ad-dc.csv -Set 'CLIENT=10.0.0.5;DC=dc01.corp.example' -DryRun

Lists every probe the run would make, with the count and a worst-case duration. Sends nothing.

.EXAMPLE
powershell -NoProfile -File .\PortProof.ps1 -Profile .\ad-dc.csv -Set 'CLIENT=10.0.0.5;DC=dc01.corp.example'
if ($LASTEXITCODE -ne 0) { throw 'Required paths are not open; the change window stays closed.' }

The change-window gate: no report files, only the console summary and the exit code.

.EXAMPLE
.\PortProof.ps1 -Profile .\sql-server.json -Set 'CLIENT=10.0.0.5;SQL=sql01.corp.example' -Out .\portproof-out -Format Html,Csv,Json

Writes portproof-report.html, portproof-results.csv and portproof-results.json into .\portproof-out.

.NOTES
Exit codes: 0 every required path passed (also -Version and an admissible -DryRun); 1 at least
one required path failed or was inconclusive; 2 bad input, a profile error, or a refusal (cap,
argument range, refused address class, output collision), or an internal error.
Exit 1 from a mistyped parameter name or an unconvertible value is PowerShell's own binding error, not a failed path.

.LINK
https://hans.study/tools/portproof/
#>

# AUTHORIZED-USE-NOTICE: keep this text byte-identical to the copy in src/05-Contract.ps1 and the clause in .DESCRIPTION above; edit all copies together.
#requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Fragment: every parameter is consumed by the entry block in 90-Main.ps1; Contract.Tests asserts it by AST.')]
[CmdletBinding(PositionalBinding = $false)]
param(
    [Alias('Profile')] [string] $ProfilePath,
    [string[]] $Set,
    [string] $Out,
    [string[]] $Format,
    [int] $Timeout = 2000,
    [int] $Concurrency = 16,
    [int] $MaxProbesPerSecond = 50,
    [int] $Jitter = 250,
    [int] $MaxProbes,
    [switch] $AllowLarge,
    [switch] $AllowCidr,   # Off by default: a group bound to a CIDR prefix is refused unless the operator opts in explicitly.
    [switch] $Icmp,
    [switch] $DryRun,
    [switch] $NoOperator,
    [switch] $Force,
    [switch] $Quiet,
    [switch] $Version
)
