# PortProof test harness - FixtureResolver.
#
# A table-driven implementation of the Resolver seam: PSTypeName
# 'PortProof.Resolver', Kind 'Fixture', an Invocations counter (incremented by the caller,
# Resolve-PPProbeList, before every Resolve call - not by this file), and a Resolve scriptblock
# property `[string] -> [System.Net.IPAddress[]]`. Never touches DNS: name lookup is a hashtable
# lookup, and every address is produced by [System.Net.IPAddress]::Parse on a string already in
# the table.
#
# Loopback-only guard: every address a Resolve call would return is
# checked against 127.0.0.0/8 / ::1 before it is handed back. An entry that legitimately resolves
# to a refused-class address (the AC15 resolved-class fixtures: broadcast/multicast/link-local/
# this-network/unspecified, so the Gate's own class-check can be proven) must be marked
# RefusedClass in the table; that is the only bypass besides the single PORTPROOF_TEST_OFFHOST=1
# opt-in gate (the same variable Test-PPOffHostOptIn in Harness.ps1 checks - inlined here rather
# than called, see the comment at the check itself). Anything else that would leave 127.0.0.0/8
# throws 'PortProofTest.NonLoopbackAddress' instead of resolving - a harness safety error, distinct
# from the tool's own 'PortProof.DnsFailure'.

function Get-PPFixtureResolver {
    <#
        -Table maps a lowercase-insensitive name to either a bare address string / string[] (the
        common case: implicitly loopback-only, RefusedClass = $false), or a hashtable
        @{ Addresses = <string[]>; RefusedClass = <bool> } for an AC15 resolved-class fixture that
        must deliberately resolve off loopback. An unknown name throws an ErrorRecord with
        FullyQualifiedErrorId 'PortProof.DnsFailure', matching what the live DNS resolver raises on
        failure. A known name whose address would leave 127.0.0.0/8 / ::1, and is
        neither RefusedClass nor covered by Test-PPOffHostOptIn, throws
        'PortProofTest.NonLoopbackAddress' instead.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [hashtable] $Table)

    $normalized = @{}
    foreach ($key in $Table.Keys) {
        $raw = $Table[$key]
        if ($raw -is [hashtable]) {
            $addresses = @($raw.Addresses)
            $refusedClass = [bool] $raw.RefusedClass
        } else {
            $addresses = @($raw)
            $refusedClass = $false
        }
        $normalized[$key.ToString().ToLowerInvariant()] = [pscustomobject]@{
            Addresses    = $addresses
            RefusedClass = $refusedClass
        }
    }

    $resolver = [pscustomobject]@{
        PSTypeName  = 'PortProof.Resolver'
        Kind        = 'Fixture'
        Invocations = 0
        Resolve     = $null
    }

    $resolver.Resolve = {
        param([string] $Name)
        $key = $Name.ToLowerInvariant()
        if (-not $normalized.ContainsKey($key)) {
            $exception = [System.InvalidOperationException]::new(
                "PortProof: fixture resolver has no table entry for '$Name'.")
            $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                $exception, 'PortProof.DnsFailure',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound, $Name)
            throw $errorRecord
        }

        $entry = $normalized[$key]
        $parsed = [System.Net.IPAddress[]] ($entry.Addresses | ForEach-Object { [System.Net.IPAddress]::Parse($_) })

        # Deliberately inlined rather than calling Test-PPOffHostOptIn (Harness.ps1): a scriptblock
        # built with GetNewClosure() is not reliably able to resolve a function from the caller's
        # dynamic scope once invoked from inside a test framework's own scope/module boundaries
        # (observed under Pester). The check itself is two lines and stable, so both copies are
        # kept in sync by inspection rather than by a cross-file call.
        $offHostAllowed = ($env:PORTPROOF_TEST_OFFHOST -eq '1') -or [bool] $env:PORTPROOF_TEST_TIMEOUT_TARGET

        if (-not $entry.RefusedClass -and -not $offHostAllowed) {
            foreach ($addr in $parsed) {
                $isV4Loopback = $addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $addr.GetAddressBytes()[0] -eq 127
                $isV6Loopback = $addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $addr.Equals([System.Net.IPAddress]::IPv6Loopback)
                if (-not $isV4Loopback -and -not $isV6Loopback) {
                    $exception = [System.InvalidOperationException]::new(
                        "PortProof test harness: fixture resolver entry for '$Name' would return " +
                        "'$addr', which is neither 127.0.0.0/8 nor ::1. Mark the entry RefusedClass " +
                        "if this is an intentional AC15 resolved-class fixture, or set " +
                        "PORTPROOF_TEST_OFFHOST=1 to opt in.")
                    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
                        $exception, 'PortProofTest.NonLoopbackAddress',
                        [System.Management.Automation.ErrorCategory]::SecurityError, $Name)
                    throw $errorRecord
                }
            }
        }

        $parsed
    }.GetNewClosure()

    return $resolver
}

function Get-PPResolverTableFixture {
    <#
        Loads tests/Fixtures/resolver-table.json (or -Path) into the hashtable shape
        Get-PPFixtureResolver expects. On-disk JSON shape per entry:
        "name": { "addresses": ["..."], "refused_class": true|false }  (refused_class optional,
        default false). Never touches DNS: this only reads a committed file and parses strings.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([string] $Path)

    if (-not $Path) {
        $Path = Join-Path (Get-PPRepoRoot) 'tests\Fixtures\resolver-table.json'
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "PortProof test harness: resolver table fixture not found at '$Path'."
    }

    $doc = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    $table = @{}
    foreach ($prop in $doc.PSObject.Properties) {
        $entry = $prop.Value
        $refused = $false
        if ($entry.PSObject.Properties.Name -contains 'refused_class') {
            $refused = [bool] $entry.refused_class
        }
        $table[$prop.Name] = @{
            Addresses    = @($entry.addresses)
            RefusedClass = $refused
        }
    }
    return $table
}
