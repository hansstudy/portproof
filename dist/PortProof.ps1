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
# ---- src/05-Contract.ps1 ----
# PortProof contract: constants, closed vocabularies, shapes, the refused-class predicate, the
# target grammar and the refusal helper. Function definitions only, no top-level execution.

function Get-PPContract {
    # Returns a NEW hashtable per call, so no caller can change another caller's constants.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    @{
        ToolVersion          = '1.0.0'
        DefaultCeiling       = 1024
        AbsoluteProbeCeiling = 8192
        Ranges               = @{
            Timeout            = @(100, 30000)
            Concurrency        = @(1, 64)
            MaxProbesPerSecond = @(1, 500)
            Jitter             = @(0, 5000)
        }
        Defaults             = @{ Timeout = 2000; Concurrency = 16; MaxProbesPerSecond = 50; Jitter = 250 }
        Formats              = @('Html', 'Csv', 'Json')
        ProfileProtocols     = @('TCP', 'UDP')
        ResultProtocols      = @('TCP', 'UDP', 'ICMP')
        RequiredValues       = @('yes', 'no')
        Outcomes             = @('Pass', 'Fail', 'Inconclusive')
        States               = @{
            TCP  = @('Open', 'Closed', 'Unreachable')
            UDP  = @('Open', 'Closed', 'Open|Filtered')
            ICMP = @('Reply', 'NoReply')
        }
        StateNotClassified   = ''
        # ProbeError: any other exception or status (outcome Inconclusive).
        # LocalPolicy: the operator host's own policy (firewall, VPN, endpoint security)
        # refused the attempt locally; nothing was sent (State '', outcome Inconclusive).
        Errors               = @('None', 'ConnectionRefused', 'Timeout', 'IcmpUnreachable', 'NoResponse',
            'DnsFailure', 'HostUnreachable', 'ProbeError', 'LocalPolicy')
        CidrSupported        = $true
        CidrPrefixRange      = @(24, 30)
        ResolveTimeoutMs     = 5000
        MaxProfileBytes      = 4194304
        MaxProfileRows       = 8192
        MaxGroupItems        = 8192
        ExpansionFactor      = 8
        MaxJsonDepth         = 8
        MaxFieldLength       = @{ Source = 253; Target = 253; Service = 128; Notes = 1024; Name = 128; Version = 64 }
        OutputFileNames      = @{
            Html = 'portproof-report.html'
            Csv  = 'portproof-results.csv'
            Json = 'portproof-results.json'
        }
        NoticeLine1          = 'Run this only against systems you own or have written authorisation to assess.'
        # AUTHORIZED-USE-NOTICE: keep this text byte-identical to the copy in src/00-Header.ps1 and the clause in .DESCRIPTION above; edit all copies together.
        AuthorizedUseClause  = 'It sends TCP connects, UDP datagrams and (with -Icmp) ICMP echoes to the hosts and ports the profile and -Set declare, plus DNS lookups for host names. It does not exploit or log in to anything and reads only what classifies each port.'
        NoticeLine3          = 'You are responsible for handling that output and for having permission to run it.'
        OriginNoteFormat     = 'All probes were sent from {0}; Source values are labels from the profile.'
        ProfileSchemaId      = 'portproof-profile/1'
        ResultSchemaId       = 'portproof-result/1'
        DefaultAdapters      = @{ TCP = 'Invoke-TcpProbe'; UDP = 'Invoke-UdpProbe'; ICMP = 'Invoke-IcmpProbe' }
    }
}

function ConvertTo-CanonicalAddress {
    # IPv4-mapped IPv6 -> the IPv4 address; anything else unchanged.
    [CmdletBinding()]
    [OutputType([System.Net.IPAddress])]
    param([Parameter(Mandatory)] [System.Net.IPAddress] $Address)

    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $Address.IsIPv4MappedToIPv6) {
        return $Address.MapToIPv4()
    }
    return $Address
}

function Get-PPIPv4Class {
    # The refused-address-class table, evaluated over four network-order bytes. Class '' = not refused.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [byte[]] $Bytes)

    $class = ''
    $label = ''
    if ($Bytes[0] -eq 0) {
        $class = 'this-network'; $label = 'this network (0.0.0.0/8)'
    }
    elseif ($Bytes[0] -eq 255 -and $Bytes[1] -eq 255 -and $Bytes[2] -eq 255 -and $Bytes[3] -eq 255) {
        $class = 'limited-broadcast'; $label = 'limited broadcast (255.255.255.255)'
    }
    elseif (($Bytes[0] -band 0xF0) -eq 0xE0) {
        $class = 'multicast'; $label = 'multicast (224.0.0.0/4)'
    }
    elseif ($Bytes[0] -eq 169 -and $Bytes[1] -eq 254) {
        $class = 'link-local'; $label = 'link-local (169.254.0.0/16)'
    }
    [pscustomobject]@{ Class = $class; Label = $label }
}

function Test-RefusedTargetClass {
    # Canonicalise, then evaluate the class table top to bottom; first match wins.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [System.Net.IPAddress] $Address)

    $canonical = ConvertTo-CanonicalAddress -Address $Address
    $b = $canonical.GetAddressBytes()
    $class = ''
    $label = ''

    if ($canonical.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        $v4 = Get-PPIPv4Class -Bytes $b
        $class = $v4.Class
        $label = $v4.Label
    }
    elseif ($canonical.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        $allZero = $true
        foreach ($octet in $b) { if ($octet -ne 0) { $allZero = $false; break } }
        if ($allZero) {
            $class = 'unspecified'; $label = 'unspecified address (::)'
        }
        elseif ($b[0] -eq 0xFF) {
            $class = 'multicast'; $label = 'multicast (ff00::/8)'
        }
        elseif ($b[0] -eq 0xFE -and ($b[1] -band 0xC0) -eq 0x80) {
            $class = 'link-local'; $label = 'link-local (fe80::/10)'
        }
        else {
            # Embedded IPv4: a translator or tunnel on the path would emit to the embedded address,
            # so it gets checked against the IPv4 class table too.
            $embedded = $null
            $form = ''
            $zero0to7 = ($b[0] -eq 0 -and $b[1] -eq 0 -and $b[2] -eq 0 -and $b[3] -eq 0 -and $b[4] -eq 0 -and $b[5] -eq 0 -and $b[6] -eq 0 -and $b[7] -eq 0)
            $zero8to11 = ($b[8] -eq 0 -and $b[9] -eq 0 -and $b[10] -eq 0 -and $b[11] -eq 0)
            $isLoopback6 = ($zero0to7 -and $zero8to11 -and $b[12] -eq 0 -and $b[13] -eq 0 -and $b[14] -eq 0 -and $b[15] -eq 1)
            if ($zero0to7 -and $zero8to11 -and -not $isLoopback6) {
                $embedded = [byte[]]@($b[12], $b[13], $b[14], $b[15]); $form = 'IPv4-compatible ::/96'
            }
            elseif ($zero0to7 -and $b[8] -eq 0xFF -and $b[9] -eq 0xFF -and $b[10] -eq 0 -and $b[11] -eq 0) {
                $embedded = [byte[]]@($b[12], $b[13], $b[14], $b[15]); $form = 'IPv4-translated ::ffff:0:0/96'
            }
            elseif ($b[0] -eq 0x00 -and $b[1] -eq 0x64 -and $b[2] -eq 0xFF -and $b[3] -eq 0x9B -and
                $b[4] -eq 0 -and $b[5] -eq 0 -and $b[6] -eq 0 -and $b[7] -eq 0 -and $zero8to11) {
                $embedded = [byte[]]@($b[12], $b[13], $b[14], $b[15]); $form = 'NAT64 64:ff9b::/96'
            }
            elseif ($b[0] -eq 0x20 -and $b[1] -eq 0x02) {
                $embedded = [byte[]]@($b[2], $b[3], $b[4], $b[5]); $form = '6to4 2002::/16'
            }
            elseif ($b[0] -eq 0x20 -and $b[1] -eq 0x01 -and $b[2] -eq 0x00 -and $b[3] -eq 0x00) {
                $embedded = [byte[]]@(($b[12] -bxor 0xFF), ($b[13] -bxor 0xFF), ($b[14] -bxor 0xFF), ($b[15] -bxor 0xFF))
                $form = 'Teredo 2001::/32 client'
            }
            if ($null -ne $embedded) {
                $v4 = Get-PPIPv4Class -Bytes $embedded
                if ($v4.Class -ne '') {
                    $class = $v4.Class
                    $label = '{0}, embedded as {1} in {2} ({3})' -f $v4.Label, ([System.Net.IPAddress]::new($embedded)).ToString(),
                        $canonical.ToString(), $form
                }
            }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.ClassVerdict'
        Refused    = ($class -ne '')
        Class      = $class
        ClassLabel = $label
        Canonical  = $canonical
    }
}

function Get-PPTargetKind {
    # Classifies target-string syntax only. Never resolves; never throws;
    # TryParse only. Every regex is anchored \A...\z and matched case-sensitively (-cmatch) with
    # explicit ASCII classes, so no culture (tr-TR, az-Latn-AZ) and no compatibility letter (U+212A
    # KELVIN SIGN, U+017F, U+0130, U+0131) changes what a character class accepts.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)

    $kind = 'Invalid'
    $outText = $Text
    $address = $null
    $reason = ''

    if ($null -eq $Text -or $Text.Length -eq 0) {
        $reason = 'the value is empty'
    }
    elseif ($Text -cmatch '[\u0000-\u001F\u007F-\u009F]') {
        # Rule 1: control characters anywhere.
        $reason = 'the value contains a control character'
    }
    elseif ([char]::IsWhiteSpace($Text[0]) -or [char]::IsWhiteSpace($Text[$Text.Length - 1])) {
        $reason = 'the value has leading or trailing whitespace'
    }
    elseif ($Text -cmatch '\A%([A-Za-z][A-Za-z0-9_]{0,31})%\z') {
        # Rule 2: a group reference that is the whole field.
        $kind = 'Group'
        $outText = $Matches[1].ToUpperInvariant()
    }
    else {
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($Text, [ref]$parsed)) {
            # Rule 3: anything TryParse accepts is a literal, whatever it looks like.
            $address = $parsed
            $v4 = '\A(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\z'
            if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $Text -cmatch $v4) {
                $kind = 'IPv4'
                $outText = $parsed.ToString()
            }
            elseif ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and
                $Text -cmatch '\A[0-9A-Fa-f:.]+\z' -and $Text.Contains(':') -and $parsed.ScopeId -eq 0) {
                $kind = 'IPv6'
                $outText = $parsed.ToString()
            }
            else {
                $kind = 'NonCanonicalLiteral'
                $reason = 'write the address in dotted-decimal or standard IPv6 form'
            }
        }
        elseif ($Text.Contains('%')) {
            # Rule 2, second half: only after TryParse has failed.
            $reason = 'a group reference must be the whole field'
        }
        else {
            # Rule 4: hostname.
            $name = $Text
            if ($name.EndsWith('.', [System.StringComparison]::Ordinal)) { $name = $name.Substring(0, $name.Length - 1) }
            $labelPattern = '\A[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z'
            if ($name.Length -lt 1 -or $name.Length -gt 253) {
                $reason = 'a host name must be 1 to 253 characters'
            }
            else {
                $labels = $name.Split('.')
                $badLabel = $false
                $hexLabel = $false
                $allNumeric = $true
                foreach ($label in $labels) {
                    if ($label -cnotmatch $labelPattern) { $badLabel = $true; break }
                    if ($label -cmatch '\A0[xX][0-9A-Fa-f]*\z') { $hexLabel = $true }
                    if ($label -cnotmatch '\A[0-9]+\z') { $allNumeric = $false }
                }
                if ($badLabel) {
                    $reason = 'not an IP address or a valid host name'
                }
                elseif ($hexLabel) {
                    $reason = 'a host name label may not be a hex literal (0x...)'
                }
                elseif ($allNumeric) {
                    $reason = 'a host name may not consist only of numbers'
                }
                elseif ($labels[$labels.Length - 1] -cnotmatch '[A-Za-z]') {
                    $reason = 'the last label of a host name must contain a letter'
                }
                elseif ($name.ToLowerInvariant() -cmatch '\.ipv6-literal\.net\z') {
                    # Windows maps these names to an IPv6 literal without DNS.
                    $reason = 'write the IPv6 literal, not an .ipv6-literal.net name'
                }
                else {
                    $kind = 'Hostname'
                    $outText = $name.ToLowerInvariant()
                }
            }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.TargetKind'
        Kind       = $kind
        Text       = $outText
        Address    = $address
        Reason     = $reason
    }
}

function Get-PPRefusingResolver {
    # The resolver seam installed under -DryRun so no name lookup can happen. Its Resolve always throws.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    [pscustomobject][ordered]@{
        PSTypeName  = 'PortProof.Resolver'
        Kind        = 'Refusing'
        Invocations = 0
        Resolve     = {
            param([string] $Name)
            Invoke-PPRefusal -Code 'DryRunResolutionAttempted' -Message ([string]::Format([cultureinfo]::InvariantCulture, "internal error: name resolution was attempted under -DryRun for '{0}'.", (Get-PPSafeText -Text $Name)))
        }
    }
}

function Invoke-PPRefusal {
    # Always throws. The message is passed through Get-PPSafeText; the error id is PortProof.<Code>.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Code,
        [Parameter(Mandatory)] [string] $Message,
        [int] $Row = 0,
        [hashtable] $Detail = @{}
    )

    $exception = [System.InvalidOperationException]::new('PortProof: ' + (Get-PPSafeText -Text $Message -Max 1024))
    $target = [pscustomobject][ordered]@{ Code = $Code; Row = $Row; Detail = $Detail }
    $record = [System.Management.Automation.ErrorRecord]::new($exception, ('PortProof.' + $Code),
        [System.Management.Automation.ErrorCategory]::InvalidArgument, $target)
    throw $record
}

function Get-PPOutcome {
    # Carries its outcome table as literals and calls nothing, so it is safe to invoke from the
    # runspace workers.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Protocol,
        [AllowEmptyString()] [string] $State,
        [Parameter(Mandatory)] [string] $ErrorName
    )

    if ($State -ceq 'Open' -or $State -ceq 'Reply') { return 'Pass' }
    if ($Protocol -ceq 'TCP' -and ($State -ceq 'Closed' -or $State -ceq 'Unreachable')) { return 'Fail' }
    if ($Protocol -ceq 'UDP' -and $State -ceq 'Closed') { return 'Fail' }
    if ($Protocol -ceq 'UDP' -and $State -ceq 'Open|Filtered') { return 'Inconclusive' }
    if ($Protocol -ceq 'ICMP' -and $State -ceq 'NoReply' -and ($ErrorName -ceq 'Timeout' -or $ErrorName -ceq 'HostUnreachable')) { return 'Fail' }
    if ($State -ceq '' -and $ErrorName -ceq 'DnsFailure') { return 'Fail' }
    # LocalPolicy (refused on the operator host, nothing sent) is Inconclusive, like ProbeError.
    if ($State -ceq '' -and $ErrorName -ceq 'LocalPolicy') { return 'Inconclusive' }
    return 'Inconclusive'
}

function Get-PPExitCode {
    # 0 when every Required 'yes' row has Outcome 'Pass' (vacuously 0 with none); else 1.
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows)

    foreach ($row in $Rows) {
        if ($row.Required -ceq 'yes' -and $row.Outcome -cne 'Pass') { return 1 }
    }
    return 0
}

function Get-PPShapeFields {
    # The normative field order; renderers and tests read column order here.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Name kept fixed on purpose; every renderer and test calls this function by this exact name.')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ResultRow', 'RunHeader', 'Flags', 'Summary', 'ProfileRow', 'ExpandedRow', 'Probe', 'ExecProbe', 'ProbeResult', 'AdapterResult', IgnoreCase = $false)]
        [string] $Shape
    )

    switch -CaseSensitive ($Shape) {
        'ResultRow' {
            @('RunId', 'Timestamp', 'SourceName', 'SourceIp', 'TargetName', 'TargetIp', 'ResolvedAddresses', 'Port',
                'Protocol', 'Service', 'Required', 'Outcome', 'State', 'LatencyMs', 'Error', 'ProfileRow', 'SourceGroup',
                'TargetGroup', 'Notes')
        }
        'RunHeader' {
            @('ToolVersion', 'ProfileName', 'ProfileVersion', 'ProfileSha256', 'RunId', 'StartedUtc', 'StartedLocal',
                'OperatorUser', 'OperatorHost', 'ProbeCount', 'Flags', 'IgnoredColumns', 'AuthorizedUseNotice',
                'OriginNote', 'ProbeCountBasis', 'WorstCaseSeconds')
        }
        'Flags' {
            @('AllowLarge', 'AllowCidr', 'Icmp', 'DryRun', 'NoOperator', 'Force', 'Quiet', 'Ceiling', 'EffectiveCap',
                'TimeoutMs', 'Concurrency', 'MaxProbesPerSecond', 'JitterMs', 'GroupOverrides', 'ExecutionPath')
        }
        'Summary' {
            @('Total', 'Pass', 'Fail', 'Inconclusive', 'RequiredTotal', 'RequiredNotPassed', 'ExitCode', 'ElapsedMs')
        }
        'ProfileRow' {
            @('Row', 'Source', 'Target', 'Port', 'Protocol', 'Required', 'Service', 'Notes')
        }
        'ExpandedRow' {
            @('Row', 'SourceName', 'SourceGroup', 'SourceIp', 'TargetName', 'TargetGroup', 'TargetKind', 'Port',
                'Protocol', 'Service', 'Required', 'Notes', 'ProbeKey')
        }
        'Probe' {
            @('ProbeKey', 'Target', 'TargetKind', 'Address', 'Port', 'Protocol', 'Rows')
        }
        'ExecProbe' {
            @('ExecKey', 'TargetIp', 'Port', 'Protocol', 'JitterMs')
        }
        'ProbeResult' {
            @('ExecKey', 'TargetIp', 'Port', 'Protocol', 'State', 'ErrorName', 'Outcome', 'LatencyMs', 'Timestamp')
        }
        'AdapterResult' {
            @('State', 'ErrorName', 'LatencyMs')
        }
    }
}

function Get-PPAuthorizedUseNotice {
    # The three notice lines, in order.
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $contract = Get-PPContract
    @($contract.NoticeLine1, $contract.AuthorizedUseClause, $contract.NoticeLine3)
}

function Get-PPSafeText {
    # Console and error text only: U+0000-U+001F and U+007F-U+009F (ESC included) become '?',
    # then the text is truncated to $Max characters.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [AllowNull()] [string] $Text, [int] $Max = 200)

    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $clean = [regex]::Replace($Text, '[\u0000-\u001F\u007F-\u009F]', '?', [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if ($Max -ge 0 -and $clean.Length -gt $Max) {
        $cut = $Max
        if ($cut -gt 0 -and [char]::IsHighSurrogate($clean[$cut - 1])) { $cut-- }
        $clean = $clean.Substring(0, $cut)
    }
    return $clean
}
# ---- src/10-Parser.ps1 ----
# PortProof parser: bytes-to-text decode, strict CSV/JSON readers, closed-domain row validation,
# and the literal refused-class check. Function definitions only.
#
# No hand-rolled crypto or codecs, and no API substitution to dodge a static-scanner rule. UTF-16
# decode uses `[System.Text.UnicodeEncoding]` (throwOnInvalidBytes) and the profile SHA-256 uses
# `[System.Security.Cryptography.SHA256]::Create()`/`ComputeHash` - both scoped to this file on
# tests/Static/settings/AllowedTypes.psd1. The bounded profile read uses a plain
# `$Stream.Read(...)` loop on the `[System.IO.FileStream] $Stream` parameter, which
# Test-ProbeProhibitions.ps1's `Find-PPReadReceiverFinding` allows by that parameter's declared
# type, never the stream's own Length.

function Read-PPProfileText {
    # Reads at most MaxProfileBytes + 1 bytes from
    # the stream itself, in a bounded loop - never FileInfo.Length or Stream.Length - so a file that
    # grows after the caller's existence check cannot exceed the cap. BOM sniff, strict UTF-8/UTF-16
    # decode, embedded-NUL check. Returns @{ Bytes = [byte[]]; Text = [string] }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.IO.FileStream] $Stream,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $maxBytes = [int]$Contract.MaxProfileBytes
    $limit = $maxBytes + 1
    $buffer = [byte[]]::new($limit)
    $total = 0
    while ($total -lt $limit) {
        $read = $Stream.Read($buffer, $total, $limit - $total)
        if ($read -le 0) { break }
        $total += $read
    }
    if ($total -gt $maxBytes) {
        Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('profile exceeds the maximum size of {0} bytes.' -f $maxBytes.ToString([cultureinfo]::InvariantCulture))
    }
    $bytes = [byte[]]::new($total)
    [System.Array]::Copy($buffer, $bytes, $total)

    $body = $bytes
    $decodeError = $false
    $text = ''

    if ($total -ge 4 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00) {
        $decodeError = $true
    }
    elseif ($total -ge 4 -and $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) {
        $decodeError = $true
    }
    elseif ($total -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $body = [byte[]]::new($total - 3)
        [System.Array]::Copy($bytes, 3, $body, 0, $total - 3)
        try {
            $decoder = [System.Text.UTF8Encoding]::new($false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }
    elseif ($total -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $body = [byte[]]::new($total - 2)
        [System.Array]::Copy($bytes, 2, $body, 0, $total - 2)
        try {
            $decoder = [System.Text.UnicodeEncoding]::new($false, $false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }
    elseif ($total -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $body = [byte[]]::new($total - 2)
        [System.Array]::Copy($bytes, 2, $body, 0, $total - 2)
        try {
            $decoder = [System.Text.UnicodeEncoding]::new($true, $false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }
    else {
        try {
            $decoder = [System.Text.UTF8Encoding]::new($false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }

    if (-not $decodeError -and $text.IndexOf([char]0) -ge 0) { $decodeError = $true }
    if ($decodeError) {
        Invoke-PPRefusal -Code 'Profile.Encoding' -Message 'profile is not valid UTF-8/UTF-16; save the profile as UTF-8.'
    }

    [pscustomobject][ordered]@{ Bytes = $bytes; Text = $text }
}

function Get-PPSha256Hex {
    # Plain .NET SHA-256, scoped to this file
    # on tests/Static/settings/AllowedTypes.psd1 (Create()/ComputeHash(byte[]) only). Returns
    # lowercase hex. Disposes the algorithm instance in finally.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($Bytes)
    }
    finally {
        $sha256.Dispose()
    }
    $sb = [System.Text.StringBuilder]::new(64)
    foreach ($byteValue in $hash) { [void]$sb.Append($byteValue.ToString('x2', [cultureinfo]::InvariantCulture)) }
    return $sb.ToString()
}

function ConvertFrom-PPCsvText {
    # Own RFC 4180 state machine (never Import-Csv). Returns a
    # List[string[]] of raw records (record 0 is the header); quote handling and record splitting
    # only - header/ragged/blank-record/domain checks are the caller's (Import-PPProfile).
    # $MaxRecords (header + MaxProfileRows data rows) is enforced the
    # instant each record completes - including a blank one - so a hostile file of millions of
    # bare line breaks can never build more than MaxRecords + 1 record objects, whatever its true
    # line count is.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $MaxRecords)

    $records = [System.Collections.Generic.List[object]]::new()
    $fields = [System.Collections.Generic.List[string]]::new()
    $field = [System.Text.StringBuilder]::new()
    $inQuotes = $false
    $quoteJustClosed = $false
    $len = $Text.Length
    $line = 1

    for ($i = 0; $i -lt $len; ) {
        $ch = $Text[$i]

        if (-not $inQuotes -and $quoteJustClosed -and $ch -cne ',' -and $ch -cne "`r" -and $ch -cne "`n") {
            Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} line {1}: a character after a closing quote must be a comma or end of line.' -f ($records.Count + 1), $line)
        }

        if ($inQuotes) {
            if ($ch -ceq '"') {
                if ($i + 1 -lt $len -and $Text[$i + 1] -ceq '"') {
                    [void]$field.Append('"')
                    $i += 2
                    continue
                }
                $inQuotes = $false
                $quoteJustClosed = $true
                $i++
                continue
            }
            if ($ch -ceq "`n") { $line++ }
            [void]$field.Append($ch)
            $i++
            continue
        }

        if ($ch -ceq '"') {
            if ($field.Length -gt 0) {
                Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} line {1}: a quote character inside an unquoted field.' -f ($records.Count + 1), $line)
            }
            $inQuotes = $true
            $i++
            continue
        }
        if ($ch -ceq ',') {
            $fields.Add($field.ToString())
            [void]$field.Clear()
            $quoteJustClosed = $false
            $i++
            continue
        }
        if ($ch -ceq "`r" -or $ch -ceq "`n") {
            $fields.Add($field.ToString())
            [void]$field.Clear()
            $quoteJustClosed = $false
            if ($ch -ceq "`r" -and $i + 1 -lt $len -and $Text[$i + 1] -ceq "`n") { $i += 2 } else { $i++ }
            $line++
            $records.Add([string[]]$fields.ToArray())
            $fields = [System.Collections.Generic.List[string]]::new()
            if ($records.Count -gt $MaxRecords) {
                Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has more than {0} records.' -f $MaxRecords.ToString([cultureinfo]::InvariantCulture))
            }
            continue
        }
        [void]$field.Append($ch)
        $i++
    }

    if ($inQuotes) {
        Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} line {1}: EOF inside quotes (an opening quote was never closed).' -f ($records.Count + 1), $line)
    }
    if ($field.Length -gt 0 -or $fields.Count -gt 0) {
        $fields.Add($field.ToString())
        $records.Add([string[]]$fields.ToArray())
        if ($records.Count -gt $MaxRecords) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has more than {0} records.' -f $MaxRecords.ToString([cultureinfo]::InvariantCulture))
        }
    }

    return , $records
}

function Read-PPJsonPosition {
    # Line number (1-based) of a character offset, for JSON syntax error messages.
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Offset)

    $line = 1
    $stop = $Offset
    if ($stop -gt $Text.Length) { $stop = $Text.Length }
    for ($i = 0; $i -lt $stop; $i++) { if ($Text[$i] -ceq "`n") { $line++ } }
    return $line
}

function Measure-PPJsonWhitespace {
    # Returns the index of the next non-whitespace character at or after $Pos (JSON whitespace:
    # space, tab, CR, LF only).
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos)

    $i = $Pos
    $len = $Text.Length
    while ($i -lt $len) {
        $c = $Text[$i]
        if ($c -ceq ' ' -or $c -ceq "`t" -or $c -ceq "`r" -or $c -ceq "`n") { $i++ } else { break }
    }
    return $i
}

function Invoke-PPJsonSyntaxError {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Offset, [Parameter(Mandatory)] [string] $Reason)

    $line = Read-PPJsonPosition -Text $Text -Offset $Offset
    Invoke-PPRefusal -Code 'Profile.JsonSyntax' -Message ('line {0}: {1}' -f $line.ToString([cultureinfo]::InvariantCulture), $Reason)
}

function Read-PPJsonString {
    # Reads a JSON string starting at $Text[$Pos] (which must be '"'). Returns @{ Value; Next }.
    # Unescaped runs are appended in bulk (one $Text.Substring/StringBuilder.Append per run, not per
    # character) - per-character appends measured as a major cost at object/array member-count
    # scale, since a profile's realistic key/value strings are almost always entirely unescaped.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos)

    $len = $Text.Length
    $i = $Pos + 1
    $runStart = $i
    # Fast path: a string with no escape and no control character needs neither a StringBuilder nor
    # a run-by-run copy - one Substring returns the whole value. Falls through to the general
    # (correctness-preserving) loop below the moment either is seen.
    while ($i -lt $len) {
        $fc = $Text[$i]
        if ($fc -ceq '"') { return [pscustomobject]@{ Value = $Text.Substring($runStart, $i - $runStart); Next = $i + 1 } }
        if ($fc -ceq '\' -or [int][char]$fc -le 0x1F) { break }
        $i++
    }
    $sb = [System.Text.StringBuilder]::new()
    while ($true) {
        if ($i -ge $len) { Invoke-PPJsonSyntaxError -Text $Text -Offset $Pos -Reason 'unterminated string.' }
        $c = $Text[$i]
        if ($c -ceq '"') {
            if ($i -gt $runStart) { [void]$sb.Append($Text.Substring($runStart, $i - $runStart)) }
            $i++
            break
        }
        if ($c -ceq '\') {
            if ($i -gt $runStart) { [void]$sb.Append($Text.Substring($runStart, $i - $runStart)) }
            if ($i + 1 -ge $len) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'unterminated escape.' }
            $e = $Text[$i + 1]
            switch -CaseSensitive ($e) {
                '"' { [void]$sb.Append('"'); $i += 2 }
                '\' { [void]$sb.Append('\'); $i += 2 }
                '/' { [void]$sb.Append('/'); $i += 2 }
                'b' { [void]$sb.Append([char]8); $i += 2 }
                'f' { [void]$sb.Append([char]12); $i += 2 }
                'n' { [void]$sb.Append([char]10); $i += 2 }
                'r' { [void]$sb.Append([char]13); $i += 2 }
                't' { [void]$sb.Append([char]9); $i += 2 }
                'u' {
                    if ($i + 5 -ge $len) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'incomplete \u escape.' }
                    $hex = $Text.Substring($i + 2, 4)
                    $code = 0
                    $validHex = $true
                    foreach ($hc in $hex.ToCharArray()) {
                        $digit = -1
                        if ($hc -cge '0' -and $hc -cle '9') { $digit = [int][char]$hc - [int][char]'0' }
                        elseif ($hc -cge 'a' -and $hc -cle 'f') { $digit = [int][char]$hc - [int][char]'a' + 10 }
                        elseif ($hc -cge 'A' -and $hc -cle 'F') { $digit = [int][char]$hc - [int][char]'A' + 10 }
                        else { $validHex = $false; break }
                        $code = ($code * 16) + $digit
                    }
                    if (-not $validHex) {
                        Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'invalid \u escape.'
                    }
                    [void]$sb.Append([char]$code)
                    $i += 6
                }
                default { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason ('invalid escape ''\{0}''.' -f $e) }
            }
            $runStart = $i
            continue
        }
        if ([int][char]$c -le 0x1F) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'a raw control character is not permitted in a JSON string.' }
        $i++
    }
    [pscustomobject]@{ Value = $sb.ToString(); Next = $i }
}

function Read-PPJsonNumber {
    # RFC 8259 number grammar only: no leading zero in the integer part (except a lone 0).
    # Returns @{ Value ([long] or [double]); Next }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos)

    # Digit tests are direct char-range comparisons, not -cmatch '[0-9]' (a regex engine call per
    # character measured as a significant cost at MaxProfileRows scale).
    $len = $Text.Length
    $start = $Pos
    $i = $Pos
    if ($i -lt $len -and $Text[$i] -ceq '-') { $i++ }
    if ($i -ge $len -or $Text[$i] -clt '0' -or $Text[$i] -cgt '9') { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'expected a number.' }
    if ($Text[$i] -ceq '0') {
        $i++
        if ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') {
            Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'a leading zero is not a valid JSON number token.'
        }
    }
    else {
        while ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') { $i++ }
    }
    $isFloat = $false
    if ($i -lt $len -and $Text[$i] -ceq '.') {
        $isFloat = $true
        $i++
        if ($i -ge $len -or $Text[$i] -clt '0' -or $Text[$i] -cgt '9') { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'a fraction needs at least one digit.' }
        while ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') { $i++ }
    }
    if ($i -lt $len -and ($Text[$i] -ceq 'e' -or $Text[$i] -ceq 'E')) {
        $isFloat = $true
        $i++
        if ($i -lt $len -and ($Text[$i] -ceq '+' -or $Text[$i] -ceq '-')) { $i++ }
        if ($i -ge $len -or $Text[$i] -clt '0' -or $Text[$i] -cgt '9') { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'an exponent needs at least one digit.' }
        while ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') { $i++ }
    }
    $token = $Text.Substring($start, $i - $start)
    if ($isFloat) {
        $value = [double]::Parse($token, [cultureinfo]::InvariantCulture)
    }
    else {
        $value = [long]::Parse($token, [cultureinfo]::InvariantCulture)
    }
    [pscustomobject]@{ Value = $value; Next = $i }
}

function Read-PPJsonValue {
    # Dispatches on the next non-whitespace character. Returns @{ Value; Next }.
    # $ValueBudget is a document-wide counter (a hashtable, a
    # reference type, so every recursive call shares the same one) - every value read anywhere in
    # the document, container or scalar, counts against it; Import-PPProfile sets its Limit to
    # Contract.MaxProfileRows x 16. This is what stops a document built from many small siblings
    # (say 255 arrays of 8192 zeros each): no single array or object exceeds its own MaxItems, and
    # none of them nests past the schema's real depth, so neither of those checks alone catches it -
    # but 255 x 8192 = 2,088,960 values blows through this total long before the document finishes.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos, [Parameter(Mandatory)] [int] $Depth, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [hashtable] $ValueBudget)

    $ValueBudget.Count = $ValueBudget.Count + 1
    if ($ValueBudget.Count -gt $ValueBudget.Limit) {
        Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the document has more than {0} JSON values.' -f $ValueBudget.Limit.ToString([cultureinfo]::InvariantCulture))
    }

    # Whitespace skip inlined (not a Measure-PPJsonWhitespace call): this dispatch runs once per
    # array/object member, and the per-call overhead of PowerShell's advanced-function machinery
    # measured as the dominant cost at MaxProfileRows scale, not the scan itself.
    $p = $Pos
    $textLen = $Text.Length
    while ($p -lt $textLen) {
        $wc = $Text[$p]
        if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $p++ } else { break }
    }
    if ($p -ge $textLen) { Invoke-PPJsonSyntaxError -Text $Text -Offset $p -Reason 'unexpected end of input; expected a value.' }
    $c = $Text[$p]
    if ($c -ceq '{') { return Read-PPJsonObject -Text $Text -Pos $p -Depth $Depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget }
    if ($c -ceq '[') { return Read-PPJsonArray -Text $Text -Pos $p -Depth $Depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget }
    if ($c -ceq '"') {
        $r = Read-PPJsonString -Text $Text -Pos $p
        return [pscustomobject]@{ Value = $r.Value; Next = $r.Next }
    }
    if ($c -ceq '-' -or ($c -cge '0' -and $c -cle '9')) { return Read-PPJsonNumber -Text $Text -Pos $p }
    if ($p + 4 -le $Text.Length -and $Text.Substring($p, 4) -ceq 'true') { return [pscustomobject]@{ Value = $true; Next = $p + 4 } }
    if ($p + 5 -le $Text.Length -and $Text.Substring($p, 5) -ceq 'false') { return [pscustomobject]@{ Value = $false; Next = $p + 5 } }
    if ($p + 4 -le $Text.Length -and $Text.Substring($p, 4) -ceq 'null') { return [pscustomobject]@{ Value = $null; Next = $p + 4 } }
    if ($c -ceq '/') { Invoke-PPJsonSyntaxError -Text $Text -Offset $p -Reason 'JSON does not allow comments.' }
    Invoke-PPJsonSyntaxError -Text $Text -Offset $p -Reason ('unexpected character ''{0}''.' -f $c)
}

function ConvertTo-PPJsonObjectValue {
    # Wraps a parsed JSON object's [ordered] dictionary in a discriminated marker. The marker
    # (JsonKind/Data) is used instead of an `-is`/`-isnot` type check against the dictionary's own
    # .NET type, because that type is not on tests/Static/settings/AllowedTypes.psd1 and `[ordered]`
    # itself only resolves as a hashtable-literal cast prefix, not as a general type reference.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Data)

    [pscustomobject]@{ JsonKind = 'Object'; Data = $Data }
}

function ConvertTo-PPJsonArrayValue {
    # See ConvertTo-PPJsonObjectValue for why this marker exists instead of a type check.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Data)

    [pscustomobject]@{ JsonKind = 'Array'; Data = $Data }
}

function Test-PPJsonValueKind {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Value, [Parameter(Mandatory)] [string] $Kind)

    return [bool]($Value -is [pscustomobject] -and $null -ne $Value.JsonKind -and $Value.JsonKind -ceq $Kind)
}

function Read-PPJsonObject {
    # An object is capped at $MaxItems members, the same
    # bound Read-PPJsonArray uses for elements - the profile schema defines no groups-specific
    # member-count constant (MaxGroupItems bounds the item count *within* one bound group's value, a
    # different thing), so this reuses MaxItems/Contract.MaxProfileRows uniformly, exactly as arrays
    # already do. Checked the instant a new key is accepted, before its value is even parsed -
    # earlier than the array check can be (an array element has no name to count until its value is
    # read).
    #
    # The profile schema never nests a container past this depth
    # (root object -> "rows" array/"groups" object -> row object, at incoming $Depth 0/1/2 in turn -
    # a row object's own fields, and a group's own value, are always scalars). A container that
    # opens at incoming $Depth 3 or deeper is refused outright: nothing legitimate needs it, and it
    # is cheap insurance against a container stuffed somewhere a scalar was expected. Depth alone
    # cannot catch every hostile shape (an illegitimate array standing where a row object belongs
    # sits at the *same* depth as a legitimate row object would) - $ValueBudget above is what stops
    # that one.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos, [Parameter(Mandatory)] [int] $Depth, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [hashtable] $ValueBudget)

    if ($Depth -ge 3) {
        Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message 'nesting deeper than the profile schema ever needs (the profile schema nests no container past depth 2).'
    }
    $depth = $Depth + 1
    if ($depth -gt $MaxDepth) { Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message ('nesting exceeds the maximum depth of {0}.' -f $MaxDepth.ToString([cultureinfo]::InvariantCulture)) }
    $obj = [ordered]@{}
    $seen = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $i = $Pos + 1
    $i = Measure-PPJsonWhitespace -Text $Text -Pos $i
    if ($i -lt $Text.Length -and $Text[$i] -ceq '}') {
        return [pscustomobject]@{ Value = (ConvertTo-PPJsonObjectValue -Data $obj); Next = $i + 1 }
    }
    $textLen = $Text.Length
    while ($true) {
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $textLen -or $Text[$i] -cne '"') { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected a string key.' }
        # Key names are read inline (not via a Read-PPJsonString call) for the common unescaped
        # case - every member pays this cost once for its key
        # and once for a string value, and the per-call overhead of PowerShell's advanced-function
        # machinery was measured as the dominant remaining cost at 8192-member scale. Read-PPJsonString
        # (with its own identical fast path) still runs for the rare escaped/control-character key.
        $keyScan = $i + 1
        $keyHasEscape = $false
        while ($keyScan -lt $textLen) {
            $kc = $Text[$keyScan]
            if ($kc -ceq '"') { break }
            if ($kc -ceq '\' -or [int][char]$kc -le 0x1F) { $keyHasEscape = $true; break }
            $keyScan++
        }
        if (-not $keyHasEscape -and $keyScan -lt $textLen) {
            $keyResult = [pscustomobject]@{ Value = $Text.Substring($i + 1, $keyScan - $i - 1); Next = $keyScan + 1 }
        }
        else {
            $keyResult = Read-PPJsonString -Text $Text -Pos $i
        }
        $key = $keyResult.Value
        if ($seen.ContainsKey($key)) { Invoke-PPRefusal -Code 'Profile.JsonDuplicateKey' -Message ("duplicate object key '{0}'." -f (Get-PPSafeText -Text $key)) }
        $seen[$key] = $true
        if ($seen.Count -gt $MaxItems) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('an object exceeds the maximum size of {0} members.' -f $MaxItems.ToString([cultureinfo]::InvariantCulture))
        }
        $i = $keyResult.Next
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $textLen -or $Text[$i] -cne ':') { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected '':'' after an object key.' }
        $i++
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        # Fast path for a string-valued member (DESIGN's own "groups" object shape: every value is a
        # string) - skips Read-PPJsonValue's generic dispatch layer entirely for the common case,
        # and (like the key above) reads the common unescaped case inline rather than through a
        # Read-PPJsonString call. Read-PPJsonValue/Read-PPJsonString still handle everything else
        # (objects, arrays, numbers, booleans, null, and any escaped/control-character string)
        # exactly as before.
        if ($i -lt $textLen -and $Text[$i] -ceq '"') {
            # A fast-pathed value bypasses Read-PPJsonValue entirely (that is the point of the fast
            # path), so it must still count against $ValueBudget itself here - otherwise a document
            # built entirely of fast-pathable string-valued members would never be counted at all.
            $ValueBudget.Count = $ValueBudget.Count + 1
            if ($ValueBudget.Count -gt $ValueBudget.Limit) {
                Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the document has more than {0} JSON values.' -f $ValueBudget.Limit.ToString([cultureinfo]::InvariantCulture))
            }
            $valScan = $i + 1
            $valHasEscape = $false
            while ($valScan -lt $textLen) {
                $vc = $Text[$valScan]
                if ($vc -ceq '"') { break }
                if ($vc -ceq '\' -or [int][char]$vc -le 0x1F) { $valHasEscape = $true; break }
                $valScan++
            }
            if (-not $valHasEscape -and $valScan -lt $textLen) {
                $valueResult = [pscustomobject]@{ Value = $Text.Substring($i + 1, $valScan - $i - 1); Next = $valScan + 1 }
            }
            else {
                $valueResult = Read-PPJsonString -Text $Text -Pos $i
            }
        }
        else {
            $valueResult = Read-PPJsonValue -Text $Text -Pos $i -Depth $depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget
        }
        $obj[$key] = $valueResult.Value
        $i = $valueResult.Next
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'unterminated object.' }
        if ($Text[$i] -ceq ',') {
            # Trailing comma (",}"): not special-cased with an extra whitespace-skip (same
            # performance reasoning as Read-PPJsonArray) - the next iteration's "expected a string
            # key" naturally rejects '}', still Profile.JsonSyntax.
            $i++
            continue
        }
        if ($Text[$i] -ceq '}') { return [pscustomobject]@{ Value = (ConvertTo-PPJsonObjectValue -Data $obj); Next = $i + 1 } }
        Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected '','' or ''}''.'
    }
}

function Read-PPJsonArray {
    # An array is capped at $MaxItems elements, checked the instant each one
    # is added - never after the whole (possibly hostile) array has been parsed and allocated. This
    # applies to every array in the document (not only "rows"), since a huge single-level array
    # anywhere (e.g. an unknown top-level key) is not bounded by the depth check. This bounds the
    # work to at most MaxItems + 1 elements' worth of parsing, however large the hostile array
    # claims to be - a full lexical pre-scan of the whole array was tried and measured slower for
    # the largest inputs (its own per-character cost scales with the array's full length, where
    # this per-element cap does not), so it was not kept.
    #
    # Same schema-depth reasoning as Read-PPJsonObject (a container
    # opening at incoming $Depth 3+ is refused outright - the schema never nests one there), plus
    # $ValueBudget, the document-wide counter that is what actually stops many sibling arrays, each
    # individually within $MaxItems, from together parsing millions of values.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos, [Parameter(Mandatory)] [int] $Depth, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [hashtable] $ValueBudget)

    if ($Depth -ge 3) {
        Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message 'nesting deeper than the profile schema ever needs (the profile schema nests no container past depth 2).'
    }
    $depth = $Depth + 1
    if ($depth -gt $MaxDepth) { Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message ('nesting exceeds the maximum depth of {0}.' -f $MaxDepth.ToString([cultureinfo]::InvariantCulture)) }
    $list = [System.Collections.Generic.List[object]]::new()
    $i = $Pos + 1
    $i = Measure-PPJsonWhitespace -Text $Text -Pos $i
    if ($i -lt $Text.Length -and $Text[$i] -ceq ']') {
        return [pscustomobject]@{ Value = (ConvertTo-PPJsonArrayValue -Data $list); Next = $i + 1 }
    }
    $textLen2 = $Text.Length
    while ($true) {
        while ($i -lt $textLen2) {
            $awc = $Text[$i]
            if ($awc -ceq ' ' -or $awc -ceq "`t" -or $awc -ceq "`r" -or $awc -ceq "`n") { $i++ } else { break }
        }
        # Fast path for a number or plain-string element (the same
        # element-count budget check as before, now also proven at true document-wide scale, so the
        # per-element dispatch overhead this bypasses matters far more than it used to) - skips
        # Read-PPJsonValue's dispatch layer entirely for the two most common element shapes, calling
        # Read-PPJsonNumber/Read-PPJsonString directly instead; $ValueBudget is still counted here,
        # since it bypasses the one place that normally counts it. Objects, arrays, booleans and null
        # still go through Read-PPJsonValue exactly as before (depth and recursion still apply).
        if ($i -lt $textLen2 -and (($Text[$i] -cge '0' -and $Text[$i] -cle '9') -or $Text[$i] -ceq '-' -or $Text[$i] -ceq '"')) {
            $ValueBudget.Count = $ValueBudget.Count + 1
            if ($ValueBudget.Count -gt $ValueBudget.Limit) {
                Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the document has more than {0} JSON values.' -f $ValueBudget.Limit.ToString([cultureinfo]::InvariantCulture))
            }
            if ($Text[$i] -ceq '"') {
                $valScan2 = $i + 1
                $valHasEscape2 = $false
                while ($valScan2 -lt $textLen2) {
                    $vc2 = $Text[$valScan2]
                    if ($vc2 -ceq '"') { break }
                    if ($vc2 -ceq '\' -or [int][char]$vc2 -le 0x1F) { $valHasEscape2 = $true; break }
                    $valScan2++
                }
                if (-not $valHasEscape2 -and $valScan2 -lt $textLen2) {
                    $valueResult = [pscustomobject]@{ Value = $Text.Substring($i + 1, $valScan2 - $i - 1); Next = $valScan2 + 1 }
                }
                else {
                    $valueResult = Read-PPJsonString -Text $Text -Pos $i
                }
            }
            else {
                # Fast path for the common plain-integer token (no fraction, no exponent, no
                # leading zero beyond a lone "0") - the dominant remaining per-element cost at this
                # scale was Read-PPJsonNumber's own call overhead, not its body. Anything else
                # (a fraction, an exponent, or a leading zero worth its own JsonSyntax message)
                # still falls back to the real function, unchanged.
                $numScan = $i
                if ($numScan -lt $textLen2 -and $Text[$numScan] -ceq '-') { $numScan++ }
                $numStart = $numScan
                while ($numScan -lt $textLen2 -and $Text[$numScan] -cge '0' -and $Text[$numScan] -cle '9') { $numScan++ }
                $isSimple = ($numScan -gt $numStart) -and (-not ($Text[$numStart] -ceq '0' -and $numScan -gt ($numStart + 1))) -and
                (-not ($numScan -lt $textLen2 -and ($Text[$numScan] -ceq '.' -or $Text[$numScan] -ceq 'e' -or $Text[$numScan] -ceq 'E')))
                if ($isSimple) {
                    $valueResult = [pscustomobject]@{ Value = [long]::Parse($Text.Substring($i, $numScan - $i), [cultureinfo]::InvariantCulture); Next = $numScan }
                }
                else {
                    $valueResult = Read-PPJsonNumber -Text $Text -Pos $i
                }
            }
        }
        else {
            $valueResult = Read-PPJsonValue -Text $Text -Pos $i -Depth $depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget
        }
        [void]$list.Add($valueResult.Value)
        if ($list.Count -gt $MaxItems) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('an array exceeds the maximum size of {0} items.' -f $MaxItems.ToString([cultureinfo]::InvariantCulture))
        }
        $i = $valueResult.Next
        while ($i -lt $Text.Length) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'unterminated array.' }
        if ($Text[$i] -ceq ',') {
            # A trailing comma (",]") is not special-cased here with an extra whitespace-skip
            # (performance: this loop runs once per array element) - the
            # next iteration's Read-PPJsonValue naturally rejects ']' as "unexpected character",
            # still Profile.JsonSyntax, just with a more generic message.
            $i++
            continue
        }
        if ($Text[$i] -ceq ']') { return [pscustomobject]@{ Value = (ConvertTo-PPJsonArrayValue -Data $list); Next = $i + 1 } }
        Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected '','' or '']''.'
    }
}

function ConvertFrom-PPStrictJson {
    # Own recursive-descent reader (never ConvertFrom-Json). RFC 8259 grammar only:
    # no comments, no trailing commas, no single quotes, no NaN; depth > MaxDepth ->
    # Profile.JsonDepth; case-insensitive duplicate member names -> Profile.JsonDuplicateKey; any
    # array/object over MaxItems elements/members -> Profile.TooLarge, checked while reading;
    # a container nested past the schema's own real depth,
    # or the whole document parsing more than $MaxValues JSON values in total -> refused before
    # finishing, whichever fires first.
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [int] $MaxValues)

    $valueBudget = @{ Count = 0; Limit = $MaxValues }
    $start = Measure-PPJsonWhitespace -Text $Text -Pos 0
    if ($start -ge $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'the document is empty.' }
    $result = Read-PPJsonValue -Text $Text -Pos $start -Depth 0 -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $valueBudget
    $tail = Measure-PPJsonWhitespace -Text $Text -Pos $result.Next
    if ($tail -lt $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $tail -Reason 'unexpected content after the document.' }
    return $result.Value
}

function Assert-PPLiteralTargetClass {
    # Calls Test-RefusedTargetClass; throws PortProof.RefusedTargetClass. Called by
    # the parser for every row-level literal and by the Expander for every literal a group or CIDR
    # produces.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [int] $Row,
        [Parameter(Mandatory)] [string] $Field,
        [Parameter(Mandatory)] [string] $Origin
    )

    $verdict = Test-RefusedTargetClass -Address $Address
    if ($verdict.Refused) {
        Invoke-PPRefusal -Code 'RefusedTargetClass' -Row $Row -Message (
            "row {0} {1} '{2}' resolves to {3}: {4}; PortProof refuses this address class" -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field, (Get-PPSafeText -Text $Origin), $verdict.Canonical.ToString(), $verdict.ClassLabel)
    }
}

function Test-PPCredentialLikeName {
    # Flags a CSV column name that looks like it would carry a credential. Lower-cased with
    # ToLowerInvariant first, then matched case-sensitively, so no culture (tr-TR) changes what
    # this matches (the culture-invariant-comparison fix already applied elsewhere in src/).
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)

    $lower = $Name.ToLowerInvariant()
    return [bool]($lower -cmatch 'pass|pwd|secret|token|cred|apikey|api_key|private')
}

function Test-PPSameName {
    # Ordinal, case-insensitive equality (never PowerShell's culture-sensitive -ieq/-eq on
    # strings; see 05-Contract.ps1/90-Main.ps1 for the same established fix in this codebase).
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $A, [Parameter(Mandatory)] [AllowEmptyString()] [string] $B)

    return [string]::Equals($A, $B, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-PPTargetGrammar {
    # Shared Source/Target validation for one field of one row:
    # non-empty, not Invalid, literal classes checked before the NonCanonical domain rejection.
    # Returns the PortProof.TargetKind verdict (Kind is 'Group'|'IPv4'|'IPv6'|'Hostname' on success).
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter(Mandatory)] [int] $Row,
        [Parameter(Mandatory)] [string] $Field
    )

    if ([string]::IsNullOrEmpty($Text)) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} is empty.' -f $Row.ToString([cultureinfo]::InvariantCulture), $Field)
    }
    $kind = Get-PPTargetKind -Text $Text
    if ($kind.Kind -ceq 'Invalid') {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} ''{2}'' is not a valid address, host name or group reference: {3}.' -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field, (Get-PPSafeText -Text $Text), $kind.Reason)
    }
    if ($kind.Kind -ceq 'IPv4' -or $kind.Kind -ceq 'IPv6' -or $kind.Kind -ceq 'NonCanonicalLiteral') {
        Assert-PPLiteralTargetClass -Address $kind.Address -Row $Row -Field $Field -Origin $Text
        if ($kind.Kind -ceq 'NonCanonicalLiteral') {
            Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} ''{2}'' is not canonical: {3}.' -f
                $Row.ToString([cultureinfo]::InvariantCulture), $Field, (Get-PPSafeText -Text $Text), $kind.Reason)
        }
    }
    return $kind
}

function Assert-PPFieldLength {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $Max, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [string] $Field)

    if ($Text.Length -gt $Max) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} exceeds the maximum length of {2} characters.' -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field, $Max.ToString([cultureinfo]::InvariantCulture))
    }
}

function Assert-PPNoControlChar {
    # The same control-character rule Source/Target already apply
    # (Get-PPTargetKind's rule 1, [\u0000-\u001F\u007F-\u009F] anywhere -> Invalid) extended to
    # every other free-text profile field - Service and Notes here, matching the profile-level
    # name/version checks in Import-PPProfile, which already carried this rule.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [string] $Field)

    if ($Text -cmatch '[\u0000-\u001F\u007F-\u009F]') {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} contains a control character.' -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field)
    }
}

function Assert-PPCsvHeader {
    # Validates the CSV header row. Returns @{ Index = <name -> column index dictionary>;
    # Ignored = [string[]]; Warnings = [string[]] }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Header)

    $required = @('Source', 'Target', 'Port', 'Protocol', 'Required')
    $optional = @('Service', 'Notes')
    $index = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ignored = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $Header.Length; $i++) {
        $name = $Header[$i]
        if ($name -cne $name.Trim()) {
            Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ("column '{0}' has leading or trailing whitespace." -f (Get-PPSafeText -Text $name))
        }
        if ($index.ContainsKey($name)) {
            Invoke-PPRefusal -Code 'Profile.DuplicateColumn' -Message ("column '{0}' is listed twice." -f (Get-PPSafeText -Text $name))
        }
        $index[$name] = $i
    }
    foreach ($name in $required) {
        if (-not $index.ContainsKey($name)) {
            Invoke-PPRefusal -Code 'Profile.MissingColumn' -Message ("required column '{0}' is missing." -f $name)
        }
    }
    foreach ($name in $Header) {
        $isKnown = $false
        foreach ($known in $required) { if (Test-PPSameName -A $known -B $name) { $isKnown = $true } }
        foreach ($known in $optional) { if (Test-PPSameName -A $known -B $name) { $isKnown = $true } }
        if (-not $isKnown) {
            $ignored.Add($name)
            $warning = "column '{0}' is not a known column; its values are ignored." -f (Get-PPSafeText -Text $name)
            if (Test-PPCredentialLikeName -Name $name) { $warning += ' (looks like a credential field; its values were not read)' }
            $warnings.Add($warning)
        }
    }
    [pscustomobject]@{ Index = $index; Ignored = [string[]]$ignored.ToArray(); Warnings = [string[]]$warnings.ToArray() }
}

function Get-PPCsvFieldByName {
    # Looks up one named column's raw value in one CSV data record, '' when the column is absent
    # (an optional column the header did not carry).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Record, [Parameter(Mandatory)] $HeaderInfo, [Parameter(Mandatory)] [string] $Name)

    $idx = $null
    if ($HeaderInfo.Index.TryGetValue($Name, [ref]$idx)) { return $Record[$idx] }
    return ''
}

function ConvertTo-PPCsvRow {
    # Validates one CSV data record into a PortProof.ProfileRow.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Record, [Parameter(Mandatory)] $HeaderInfo, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [hashtable] $Contract)

    $sourceText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Source'
    $targetText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Target'
    $portText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Port'
    $protocolText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Protocol'
    $requiredText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Required'
    $serviceText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Service'
    $notesText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Notes'

    $null = Assert-PPTargetGrammar -Text $sourceText -Row $Row -Field 'Source'
    $null = Assert-PPTargetGrammar -Text $targetText -Row $Row -Field 'Target'
    Assert-PPFieldLength -Text $sourceText -Max ([int]$Contract.MaxFieldLength.Source) -Row $Row -Field 'Source'
    Assert-PPFieldLength -Text $targetText -Max ([int]$Contract.MaxFieldLength.Target) -Row $Row -Field 'Target'

    if ($portText -cnotmatch '\A[1-9][0-9]{0,4}\z') {
        $reason = 'is not a plain integer'
        if ($portText -cmatch '\A0[0-9]+\z') { $reason = 'has a leading zero' }
        elseif ($portText -cmatch '[-,*]') { $reason = 'has a range, list or wildcard; PortProof has no port ranges' }
        elseif ($portText -cmatch '\A0\z') { $reason = 'is 0, out of range 1..65535' }
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} Port ''{1}'' {2}.' -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $portText), $reason)
    }
    $port = [int]::Parse($portText, [cultureinfo]::InvariantCulture)
    if ($port -lt 1 -or $port -gt 65535) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} Port {1} is out of range 1..65535.' -f $Row.ToString([cultureinfo]::InvariantCulture), $port.ToString([cultureinfo]::InvariantCulture))
    }

    $protocol = $null
    foreach ($known in $Contract.ProfileProtocols) { if (Test-PPSameName -A $known -B $protocolText) { $protocol = $known } }
    if ($null -eq $protocol) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ("row {0} Protocol '{1}' is not TCP or UDP." -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $protocolText))
    }

    $required = $null
    foreach ($known in $Contract.RequiredValues) { if (Test-PPSameName -A $known -B $requiredText) { $required = $known } }
    if ($null -eq $required) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ("row {0} Required '{1}' is not yes or no." -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $requiredText))
    }

    Assert-PPFieldLength -Text $serviceText -Max ([int]$Contract.MaxFieldLength.Service) -Row $Row -Field 'Service'
    Assert-PPFieldLength -Text $notesText -Max ([int]$Contract.MaxFieldLength.Notes) -Row $Row -Field 'Notes'
    Assert-PPNoControlChar -Text $serviceText -Row $Row -Field 'Service'
    Assert-PPNoControlChar -Text $notesText -Row $Row -Field 'Notes'

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.ProfileRow'
        Row        = $Row
        Source     = $sourceText
        Target     = $targetText
        Port       = $port
        Protocol   = $protocol
        Required   = $required
        Service    = $serviceText
        Notes      = $notesText
    }
}

function ConvertTo-PPJsonRow {
    # Validates one JSON row object into a PortProof.ProfileRow.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $RowObject, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [hashtable] $Contract)

    if (-not (Test-PPJsonValueKind -Value $RowObject -Kind 'Object')) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} must be a JSON object.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }
    $data = $RowObject.Data
    $required = @('source', 'target', 'port', 'protocol', 'required')
    $optional = @('service', 'notes')
    $keyIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $data.Keys) { $keyIndex[$key] = $true }
    foreach ($name in $required) {
        if (-not $keyIndex.ContainsKey($name)) {
            Invoke-PPRefusal -Code 'Profile.MissingColumn' -Row $Row -Message ("row {0} is missing required key '{1}'." -f $Row.ToString([cultureinfo]::InvariantCulture), $name)
        }
    }
    foreach ($key in $data.Keys) {
        $known = $false
        foreach ($name in $required) { if (Test-PPSameName -A $name -B $key) { $known = $true } }
        foreach ($name in $optional) { if (Test-PPSameName -A $name -B $key) { $known = $true } }
        if (-not $known) {
            Invoke-PPRefusal -Code 'Profile.UnknownKey' -Row $Row -Message ("row {0} has an unknown key '{1}'." -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $key))
        }
    }

    $sourceValue = $data['source']
    $targetValue = $data['target']
    if ($sourceValue -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} source must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
    if ($targetValue -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} target must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
    $null = Assert-PPTargetGrammar -Text $sourceValue -Row $Row -Field 'source'
    $null = Assert-PPTargetGrammar -Text $targetValue -Row $Row -Field 'target'
    Assert-PPFieldLength -Text $sourceValue -Max ([int]$Contract.MaxFieldLength.Source) -Row $Row -Field 'source'
    Assert-PPFieldLength -Text $targetValue -Max ([int]$Contract.MaxFieldLength.Target) -Row $Row -Field 'target'

    $portValue = $data['port']
    if ($portValue -is [long]) {
        if ($portValue -lt 1L -or $portValue -gt 65535L) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port {1} is out of range 1..65535, or has a sign, not a bare integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture), $portValue.ToString([cultureinfo]::InvariantCulture))
        }
        $port = [int]$portValue
    }
    elseif ($portValue -is [double]) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port has a fraction or exponent, not a bare integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }
    elseif ($portValue -is [string]) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port is given as a JSON string, not an integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }
    else {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port must be a JSON integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }

    $protocolValue = $data['protocol']
    $protocol = $null
    if ($protocolValue -is [string]) {
        foreach ($known in $Contract.ProfileProtocols) { if (Test-PPSameName -A $known -B $protocolValue) { $protocol = $known } }
    }
    if ($null -eq $protocol) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} protocol is not TCP or UDP.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }

    $requiredValue = $data['required']
    $requiredOut = $null
    if ($requiredValue -is [string]) {
        foreach ($known in $Contract.RequiredValues) { if (Test-PPSameName -A $known -B $requiredValue) { $requiredOut = $known } }
    }
    if ($null -eq $requiredOut) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} required must be the string ''yes'' or ''no''.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }

    $serviceValue = ''
    if ($keyIndex.ContainsKey('service')) {
        if ($data['service'] -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} service must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
        $serviceValue = $data['service']
    }
    $notesValue = ''
    if ($keyIndex.ContainsKey('notes')) {
        if ($data['notes'] -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} notes must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
        $notesValue = $data['notes']
    }
    Assert-PPFieldLength -Text $serviceValue -Max ([int]$Contract.MaxFieldLength.Service) -Row $Row -Field 'service'
    Assert-PPFieldLength -Text $notesValue -Max ([int]$Contract.MaxFieldLength.Notes) -Row $Row -Field 'notes'
    Assert-PPNoControlChar -Text $serviceValue -Row $Row -Field 'service'
    Assert-PPNoControlChar -Text $notesValue -Row $Row -Field 'notes'

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.ProfileRow'
        Row        = $Row
        Source     = $sourceValue
        Target     = $targetValue
        Port       = $port
        Protocol   = $protocol
        Required   = $requiredOut
        Service    = $serviceValue
        Notes      = $notesValue
    }
}

function Assert-PPNoDuplicateRow {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Collections.Generic.List[object]] $Rows)

    $seen = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Rows) {
        $key = '{0}|{1}|{2}|{3}' -f $row.Source, $row.Target, $row.Port, $row.Protocol
        if ($seen.ContainsKey($key)) {
            Invoke-PPRefusal -Code 'Profile.DuplicateRow' -Row $row.Row -Message ('row {0} duplicates row {1}.' -f $row.Row.ToString([cultureinfo]::InvariantCulture), $seen[$key].ToString([cultureinfo]::InvariantCulture))
        }
        $seen[$key] = $row.Row
    }
}

function Import-PPProfile {
    # Reads and validates a whole profile file -> PortProof.Profile. $Path is a resolved, existing full provider path.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [hashtable] $Contract)

    $fileName = [System.IO.Path]::GetFileName($Path)
    $isJson = (Test-PPSameName -A ([System.IO.Path]::GetExtension($Path)) -B '.json')
    $format = if ($isJson) { 'Json' } else { 'Csv' }

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $read = Read-PPProfileText -Stream $stream -Contract $Contract
    }
    finally {
        $stream.Dispose()
    }
    $sha256 = Get-PPSha256Hex -Bytes $read.Bytes
    $text = $read.Text

    $rows = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $ignoredColumns = [string[]]@()
    $name = ''
    $version = ''
    $groups = [ordered]@{}

    if ($isJson) {
        $docValue = ConvertFrom-PPStrictJson -Text $text -MaxDepth ([int]$Contract.MaxJsonDepth) -MaxItems ([int]$Contract.MaxProfileRows) -MaxValues ([int]$Contract.MaxProfileRows * 16)
        if (-not (Test-PPJsonValueKind -Value $docValue -Kind 'Object')) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message 'the document must be a JSON object.'
        }
        $doc = $docValue.Data
        $topRequired = @('schema', 'name', 'rows')
        $topOptional = @('version', 'groups')
        $topIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $doc.Keys) { $topIndex[$key] = $true }
        foreach ($required in @('schema', 'name')) {
            if (-not $topIndex.ContainsKey($required)) { Invoke-PPRefusal -Code 'Profile.MissingColumn' -Message ("required top-level key '{0}' is missing." -f $required) }
        }
        if (-not $topIndex.ContainsKey('rows')) { Invoke-PPRefusal -Code 'Profile.MissingColumn' -Message "required top-level key 'rows' is missing." }
        foreach ($key in $doc.Keys) {
            $known = $false
            foreach ($allowed in $topRequired) { if (Test-PPSameName -A $allowed -B $key) { $known = $true } }
            foreach ($allowed in $topOptional) { if (Test-PPSameName -A $allowed -B $key) { $known = $true } }
            if (-not $known) { Invoke-PPRefusal -Code 'Profile.UnknownKey' -Message ("unknown top-level key '{0}'." -f (Get-PPSafeText -Text $key)) }
        }

        $schemaValue = $doc['schema']
        if ($schemaValue -isnot [string] -or $schemaValue -cne $Contract.ProfileSchemaId) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message ("schema must be exactly '{0}'." -f $Contract.ProfileSchemaId)
        }
        $nameValue = $doc['name']
        if ($nameValue -isnot [string] -or $nameValue.Length -lt 1 -or $nameValue.Length -gt [int]$Contract.MaxFieldLength.Name -or $nameValue -cmatch '[\u0000-\u001F\u007F-\u009F]') {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message 'name must be 1 to 128 characters with no control characters.'
        }
        $name = $nameValue
        if ($topIndex.ContainsKey('version')) {
            $versionValue = $doc['version']
            if ($versionValue -isnot [string] -or $versionValue.Length -gt [int]$Contract.MaxFieldLength.Version -or $versionValue -cmatch '[\u0000-\u001F\u007F-\u009F]') {
                Invoke-PPRefusal -Code 'Profile.Domain' -Message 'version must be 0 to 64 characters with no control characters.'
            }
            $version = $versionValue
        }
        if ($topIndex.ContainsKey('groups')) {
            $groupsRaw = $doc['groups']
            if (-not (Test-PPJsonValueKind -Value $groupsRaw -Kind 'Object')) {
                Invoke-PPRefusal -Code 'Profile.Domain' -Message 'groups must be a JSON object.'
            }
            $groupsValue = $groupsRaw.Data
            foreach ($key in $groupsValue.Keys) {
                if ($key -cnotmatch '\A[A-Za-z][A-Za-z0-9_]{0,31}\z') {
                    Invoke-PPRefusal -Code 'Profile.Domain' -Message ("groups key '{0}' is not a valid group name." -f (Get-PPSafeText -Text $key))
                }
                $value = $groupsValue[$key]
                if ($value -isnot [string] -or $value.Length -eq 0) {
                    Invoke-PPRefusal -Code 'Profile.Domain' -Message ("groups value for '{0}' must be a non-empty string." -f $key.ToUpperInvariant())
                }
                $groups[$key.ToUpperInvariant()] = $value
            }
        }

        $rowsRaw = $doc['rows']
        if (-not (Test-PPJsonValueKind -Value $rowsRaw -Kind 'Array')) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message 'rows must be a JSON array.'
        }
        $rowsValue = $rowsRaw.Data
        if ($rowsValue.Count -eq 0) {
            Invoke-PPRefusal -Code 'Profile.Empty' -Message 'the profile has zero data rows.'
        }
        if ($rowsValue.Count -gt [int]$Contract.MaxProfileRows) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has {0} rows; the limit is {1}.' -f $rowsValue.Count.ToString([cultureinfo]::InvariantCulture), ([int]$Contract.MaxProfileRows).ToString([cultureinfo]::InvariantCulture))
        }
        for ($i = 0; $i -lt $rowsValue.Count; $i++) {
            $rowNumber = $i + 1
            $rows.Add((ConvertTo-PPJsonRow -RowObject $rowsValue[$i] -Row $rowNumber -Contract $Contract))
        }
    }
    else {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $records = ConvertFrom-PPCsvText -Text $text -MaxRecords ([int]$Contract.MaxProfileRows + 1)
        if ($records.Count -eq 0) {
            Invoke-PPRefusal -Code 'Profile.Empty' -Message 'the profile is empty.'
        }
        $headerInfo = Assert-PPCsvHeader -Header $records[0]
        foreach ($w in $headerInfo.Warnings) { $warnings.Add($w) }
        $ignoredColumns = $headerInfo.Ignored
        $dataRecords = [System.Collections.Generic.List[object]]::new()
        for ($i = 1; $i -lt $records.Count; $i++) { $dataRecords.Add($records[$i]) }
        if ($dataRecords.Count -eq 0) {
            Invoke-PPRefusal -Code 'Profile.Empty' -Message 'the profile has zero data records.'
        }
        if ($dataRecords.Count -gt [int]$Contract.MaxProfileRows) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has {0} rows; the limit is {1}.' -f $dataRecords.Count.ToString([cultureinfo]::InvariantCulture), ([int]$Contract.MaxProfileRows).ToString([cultureinfo]::InvariantCulture))
        }
        $headerCount = $records[0].Length
        for ($i = 0; $i -lt $dataRecords.Count; $i++) {
            $rowNumber = $i + 2
            $record = $dataRecords[$i]
            if ($record.Length -ne $headerCount) {
                Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} has fewer or more fields than the header ({1} vs {2}).' -f $rowNumber.ToString([cultureinfo]::InvariantCulture), $record.Length.ToString([cultureinfo]::InvariantCulture), $headerCount.ToString([cultureinfo]::InvariantCulture))
            }
            $allEmpty = $true
            foreach ($field in $record) { if ($field.Length -gt 0) { $allEmpty = $false; break } }
            if ($allEmpty) {
                Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0}: every field is empty.' -f $rowNumber.ToString([cultureinfo]::InvariantCulture))
            }
            $rows.Add((ConvertTo-PPCsvRow -Record $record -HeaderInfo $headerInfo -Row $rowNumber -Contract $Contract))
        }
    }

    Assert-PPNoDuplicateRow -Rows $rows

    [pscustomobject][ordered]@{
        PSTypeName     = 'PortProof.Profile'
        Path           = $Path
        FileName       = $fileName
        Format         = $format
        Sha256         = $sha256
        Name           = $name
        Version        = $version
        Groups         = $groups
        IgnoredColumns = [string[]]$ignoredColumns
        Rows           = [pscustomobject[]]$rows.ToArray()
        Warnings       = [string[]]$warnings.ToArray()
    }
}
# ---- src/20-Expander.ps1 ----
# PortProof expander: group/list/CIDR expansion into the pre-resolution probe list, with the
# count-before-build early exit. Function definitions only.

function ConvertFrom-PPBinding {
    # 'NAME=VALUE' -> @{ Name; Value }. Grammar (name shape, single '=') is already checked by
    # Assert-Arguments in 90-Main.ps1; this only splits at the first '='.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Text)

    $idx = $Text.IndexOf('=')
    @{ Name = $Text.Substring(0, $idx); Value = $Text.Substring($idx + 1) }
}

function Get-PPGroupValueShape {
    # Classifies a bound group's raw text as a plain list or a CIDR attempt, without validating
    # -AllowCidr/prefix range/host bits (that is Measure-PPGroupItemCount's and
    # Expand-PPGroupValue's job, in that order). A value is a CIDR
    # candidate only when it has exactly one '/'; anything else (including two or more '/') is a
    # list, and an item that is not a valid address/host name fails its own grammar check later.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Value)

    $v4 = '\A(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\z'
    $parts = $Value.Split('/')
    if ($parts.Length -eq 2) {
        $addrText = $parts[0]
        $prefixText = $parts[1]
        if ($addrText -cmatch $v4 -and $prefixText -cmatch '\A[0-9]{1,2}\z') {
            return [pscustomobject]@{ Kind = 'Ipv4Cidr'; Address = $addrText; PrefixText = $prefixText }
        }
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($addrText, [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return [pscustomobject]@{ Kind = 'Ipv6Cidr'; Address = $addrText; PrefixText = $prefixText }
        }
    }
    return [pscustomobject]@{ Kind = 'List'; Address = ''; PrefixText = '' }
}

function Get-PPCidrPlan {
    # Shared CIDR validation (shape already known to be 'Ipv4Cidr'): -AllowCidr, prefix 8..32,
    # not Source, host bits clear - in that order, and the item count is computed only after all
    # of these pass (shape and -AllowCidr validated before any count is
    # computed, so a /0 - or anything else outside 8..32 - never reaches the 2^(32-prefix)
    # arithmetic; the prefix range check always runs first and uses [long] shifts throughout, so
    # even a would-be /0 can never wrap negative the way a 32-bit-masked shift-by-32 could).
    #
    # VLSM support: any prefix must work, not only /24, since VLSM routinely
    # uses narrow point-to-point prefixes alongside wide ones. The range is 8..32 (still gated by
    # -AllowCidr and, downstream, by the same EffectiveCap x ExpansionFactor
    # arithmetic every other expansion path already uses - a /8 or /16 is refused there, on pure
    # arithmetic, before pass 2 ever enumerates a single address). /31 and /32 need their own usable-
    # range rule, since the classic "network and broadcast excluded" formula (2^hostBits - 2) is
    # undefined for them: a /31 has no network/broadcast address at all (RFC 3021 - both of its two
    # addresses are usable, the standard point-to-point convention every VLSM design already relies
    # on), and a /32 is a single host route (the one address is directly usable; there is nothing to
    # exclude - excluding it would make a /32 always empty, which defeats accepting it at all). Every
    # other prefix (8..30) keeps the original network+1..broadcast-1 rule unchanged.
    # Returns @{ AddressLong; Prefix; HostBits; BlockMask; HostMask; Network; Broadcast; FirstUsable;
    # LastUsable; Count }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $GroupName,
        [Parameter(Mandatory)] $Shape,
        [switch] $AllowCidr,
        [Parameter(Mandatory)] [string] $Origin,
        [Parameter(Mandatory)] [int] $Row
    )

    if (-not $AllowCidr) {
        Invoke-PPRefusal -Code 'Group.CidrNotAllowed' -Row $Row -Message ("row {0} group '{1}' is a CIDR prefix; run with -AllowCidr." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName)
    }
    $prefix = [int]::Parse($Shape.PrefixText, [cultureinfo]::InvariantCulture)
    if ($prefix -lt 8 -or $prefix -gt 32) {
        Invoke-PPRefusal -Code 'Group.CidrTooWide' -Row $Row -Message ("row {0} group '{1}' prefix /{2} is outside 8..32." -f
            $Row.ToString([cultureinfo]::InvariantCulture), $GroupName, $prefix.ToString([cultureinfo]::InvariantCulture))
    }
    if ($Origin -ceq 'Source') {
        Invoke-PPRefusal -Code 'Group.CidrInSource' -Row $Row -Message ("row {0} group '{1}' is a CIDR prefix and cannot be referenced from Source." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName)
    }
    $parsed = $null
    [void][System.Net.IPAddress]::TryParse($Shape.Address, [ref]$parsed)
    $bytes = $parsed.GetAddressBytes()
    $addrLong = ([long]$bytes[0] -shl 24) -bor ([long]$bytes[1] -shl 16) -bor ([long]$bytes[2] -shl 8) -bor [long]$bytes[3]
    $hostBits = 32 - $prefix
    $blockMask = (0xFFFFFFFFL -shl $hostBits) -band 0xFFFFFFFFL
    $hostMask = (-bnot $blockMask) -band 0xFFFFFFFFL
    if (($addrLong -band $hostMask) -ne 0L) {
        Invoke-PPRefusal -Code 'Group.CidrNotAligned' -Row $Row -Message ("row {0} group '{1}' has host bits set for a /{2}; use the network address." -f
            $Row.ToString([cultureinfo]::InvariantCulture), $GroupName, $prefix.ToString([cultureinfo]::InvariantCulture))
    }
    $network = $addrLong -band $blockMask
    $broadcast = $network -bor $hostMask
    if ($prefix -eq 32) {
        # Single host route: the one address is the whole usable range.
        $firstUsable = $network
        $lastUsable = $network
    }
    elseif ($prefix -eq 31) {
        # RFC 3021 point-to-point: both addresses usable, no network/broadcast concept.
        $firstUsable = $network
        $lastUsable = $broadcast
    }
    else {
        $firstUsable = $network + 1L
        $lastUsable = $broadcast - 1L
    }
    [pscustomobject]@{
        AddressLong = $addrLong
        Prefix      = $prefix
        HostBits    = $hostBits
        BlockMask   = $blockMask
        HostMask    = $hostMask
        Network     = $network
        Broadcast   = $broadcast
        FirstUsable = $firstUsable
        LastUsable  = $lastUsable
        Count       = $lastUsable - $firstUsable + 1L
    }
}

function Measure-PPGroupItemCount {
    # Pass 1: arithmetic only, no item objects built. Validates CIDR shape/-AllowCidr/
    # prefix range/host bits/position (via Get-PPCidrPlan), or counts a list's items straight from
    # its text - counted with
    # IndexOf, never $Value.Split(), and Group.TooLarge is refused before any split happens; the
    # per-item empty-item/nested-group grammar checks are Expand-PPGroupValue's, pass 2's, job -
    # they need the actual item strings, which pass 1 never builds). Group.TooLarge/MaxGroupItems
    # applies to list counts only, unchanged by CIDR support - a CIDR's count is bounded by a different mechanism entirely: it
    # is pure O(1) arithmetic (Get-PPCidrPlan never enumerates), so however large a /8's 16,777,214
    # count is, it flows straight into Expand-PPProfile's own eTotal/pTotal x EffectiveCap x
    # ExpansionFactor check below, at no enumeration cost - a wide-enough prefix (e.g. /16 without
    # -AllowLarge, or /8 regardless) is refused there, CapExceeded.Expansion, before pass 2 ever
    # calls Expand-PPGroupValue.
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)] [string] $GroupName,
        [Parameter(Mandatory)] [string] $Value,
        [switch] $AllowCidr,
        [Parameter(Mandatory)] [string] $Origin,
        [Parameter(Mandatory)] [int] $Row,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $shape = Get-PPGroupValueShape -Value $Value
    if ($shape.Kind -ceq 'Ipv6Cidr') {
        Invoke-PPRefusal -Code 'Group.CidrIPv6' -Row $Row -Message ("row {0} group '{1}' is an IPv6 prefix; CIDR is IPv4 only." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName)
    }
    if ($shape.Kind -ceq 'Ipv4Cidr') {
        $plan = Get-PPCidrPlan -GroupName $GroupName -Shape $shape -AllowCidr:$AllowCidr -Origin $Origin -Row $Row
        return $plan.Count
    }

    $maxItems = [long]$Contract.MaxGroupItems
    $count = [long]1
    $searchFrom = -1
    while ($true) {
        $commaIndex = $Value.IndexOf(',', $searchFrom + 1)
        if ($commaIndex -lt 0) { break }
        $count++
        $searchFrom = $commaIndex
        if ($count -gt $maxItems) { break }
    }
    if ($count -gt $maxItems) {
        Invoke-PPRefusal -Code 'Group.TooLarge' -Row $Row -Message ("row {0} group '{1}' has more than {2} items." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName,
            ([int]$Contract.MaxGroupItems).ToString([cultureinfo]::InvariantCulture))
    }
    return $count
}

function Expand-PPGroupValue {
    # -> TargetKind[]. Pass 2: builds the concrete items a bound group or CIDR
    # produces (re-running the same shape/CIDR checks Measure-PPGroupItemCount already passed for
    # this exact value/-AllowCidr/-Origin in pass 1, defensively). Does not itself call
    # Assert-PPLiteralTargetClass: that check is scoped to target-position items, and the
    # caller (Expand-PPProfile) is the one that knows the row number the message should name.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Contract',
        Justification = 'This function''s signature is fixed at (Name, Value, AllowCidr, Origin, Contract). This pass-2 builder does not need a Contract-derived limit itself - Group.TooLarge is pass 1''s job (Measure-PPGroupItemCount, which already validated this exact value before Expand-PPProfile calls this function) - but the parameter stays to match the fixed interface every other unit codes against.')]
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Value,
        [switch] $AllowCidr,
        [Parameter(Mandatory)] [string] $Origin,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $shape = Get-PPGroupValueShape -Value $Value

    if ($shape.Kind -ceq 'Ipv6Cidr') {
        Invoke-PPRefusal -Code 'Group.CidrIPv6' -Message ("group '{0}' is an IPv6 prefix; CIDR is IPv4 only." -f $Name)
    }
    if ($shape.Kind -ceq 'Ipv4Cidr') {
        $plan = Get-PPCidrPlan -GroupName $Name -Shape $shape -AllowCidr:$AllowCidr -Origin $Origin -Row 0
        for ($current = $plan.FirstUsable; $current -le $plan.LastUsable; $current++) {
            $b0 = [byte](($current -shr 24) -band 0xFFL)
            $b1 = [byte](($current -shr 16) -band 0xFFL)
            $b2 = [byte](($current -shr 8) -band 0xFFL)
            $b3 = [byte]($current -band 0xFFL)
            $address = [System.Net.IPAddress]::new([byte[]]($b0, $b1, $b2, $b3))
            $results.Add([pscustomobject][ordered]@{
                    PSTypeName = 'PortProof.TargetKind'
                    Kind       = 'IPv4'
                    Text       = $address.ToString()
                    Address    = $address
                    Reason     = ''
                })
        }
        return , $results.ToArray()
    }

    foreach ($item in $Value.Split(',')) {
        if ($item.Length -eq 0) {
            Invoke-PPRefusal -Code 'Group.Syntax' -Message ("group '{0}' has an empty item between commas." -f $Name)
        }
        if ($item -cmatch '\A%([A-Za-z][A-Za-z0-9_]{0,31})%\z') {
            Invoke-PPRefusal -Code 'Group.Nested' -Message ("group '{0}' item '{1}' is itself a group reference; groups may not nest." -f $Name, (Get-PPSafeText -Text $item))
        }
        $kind = Get-PPTargetKind -Text $item
        # The same TryParse-then-class-check order used for a plain target field - a
        # NonCanonicalLiteral item (e.g. 0xe0000001) is class-checked (target position only)
        # before it is rejected as Group.Syntax, so a refused-class address reached through a
        # group names its class, exactly like a literal target does, instead of being reported as a
        # plain syntax error. Row 0: a bound group's own value has no single owning row (the same
        # convention the CIDR path above already uses).
        if ($Origin -ceq 'Target' -and $kind.Kind -ceq 'NonCanonicalLiteral') {
            Assert-PPLiteralTargetClass -Address $kind.Address -Row 0 -Field $Origin -Origin $item
        }
        if ($kind.Kind -cne 'IPv4' -and $kind.Kind -cne 'IPv6' -and $kind.Kind -cne 'Hostname') {
            Invoke-PPRefusal -Code 'Group.Syntax' -Message ("group '{0}' item '{1}' is not an address or host name (write it in dotted-decimal, standard IPv6, or as a plain host name)." -f
                $Name, (Get-PPSafeText -Text $item))
        }
        $results.Add($kind)
    }
    return , $results.ToArray()
}

function Assert-PPPreResolutionCount {
    # Throws PortProof.CapExceeded.PreResolution when Count > the effective
    # cap. Never resolves; takes counts only. Effective cap = min(Cap, Ceiling), mirroring the
    # Gate's own min(Cap, AbsoluteProbeCeiling) defence.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int] $Count,
        [Parameter(Mandatory)] [int] $Cap,
        [Parameter(Mandatory)] [int] $Ceiling
    )

    $effectiveCap = $Cap
    if ($Ceiling -lt $effectiveCap) { $effectiveCap = $Ceiling }
    if ($Count -gt $effectiveCap) {
        Invoke-PPRefusal -Code 'CapExceeded.PreResolution' -Message ('{0} probes exceed the cap of {1} (before name resolution; nothing was resolved or sent)' -f
            $Count.ToString([cultureinfo]::InvariantCulture), $effectiveCap.ToString([cultureinfo]::InvariantCulture))
    }
}

function Expand-PPProfile {
    # -> PortProof.Expansion. Pass 1 (count-before-build): pure arithmetic, no ExpandedRow/Probe
    # built, refuses Group.TooLarge/CidrIPv6/
    # CidrNotAllowed/CidrTooWide/CidrInSource/CidrNotAligned/Syntax/Nested/Unbound and
    # CapExceeded.Expansion. Pass 2: builds the deduplicated Probe list and the ExpandedRow list.
    #
    # The pass-1 limit is EffectiveCap x ExpansionFactor, using the
    # run's real effective cap. -EffectiveCap defaults to Contract.DefaultCeiling (0 or an
    # unbound/omitted value both mean "use the default") so every existing caller - including this
    # file's own tests - keeps working unchanged; 90-Main.ps1
    # passes -EffectiveCap $options.EffectiveCap.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $ProfileDocument,
        [AllowEmptyCollection()] [string[]] $Bindings,
        [switch] $AllowCidr,
        [long] $EffectiveCap = 0,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $groups = [ordered]@{}
    foreach ($key in @($ProfileDocument.Groups.Keys)) { $groups[$key] = $ProfileDocument.Groups[$key] }
    $groupOverrides = [System.Collections.Generic.List[string]]::new()
    foreach ($bindingText in @($Bindings)) {
        $parsedBinding = ConvertFrom-PPBinding -Text $bindingText
        $upperName = $parsedBinding.Name.ToUpperInvariant()
        if ($groups.Contains($upperName)) { $groupOverrides.Add($upperName) }
        $groups[$upperName] = $parsedBinding.Value
    }

    $usedGroups = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $effectiveCapInForce = $EffectiveCap
    if ($effectiveCapInForce -le 0) { $effectiveCapInForce = [long]$Contract.DefaultCeiling }
    $limit = $effectiveCapInForce * [long]$Contract.ExpansionFactor
    $eTotal = [long]0
    $pTotal = [long]0

    foreach ($row in @($ProfileDocument.Rows)) {
        $srcKind = Get-PPTargetKind -Text $row.Source
        $tgtKind = Get-PPTargetKind -Text $row.Target

        if ($srcKind.Kind -ceq 'Group') {
            $groupName = $srcKind.Text
            $usedGroups[$groupName] = $true
            if (-not $groups.Contains($groupName)) {
                Invoke-PPRefusal -Code 'Group.Unbound' -Row $row.Row -Message ("row {0} group '{1}' (Source) is not bound; add -Set '{1}=...' or a groups entry." -f
                    $row.Row.ToString([cultureinfo]::InvariantCulture), $groupName)
            }
            $sCount = Measure-PPGroupItemCount -GroupName $groupName -Value ([string]$groups[$groupName]) -AllowCidr:$AllowCidr -Origin 'Source' -Row $row.Row -Contract $Contract
        }
        else {
            $sCount = [long]1
        }

        if ($tgtKind.Kind -ceq 'Group') {
            $groupName = $tgtKind.Text
            $usedGroups[$groupName] = $true
            if (-not $groups.Contains($groupName)) {
                Invoke-PPRefusal -Code 'Group.Unbound' -Row $row.Row -Message ("row {0} group '{1}' (Target) is not bound; add -Set '{1}=...' or a groups entry." -f
                    $row.Row.ToString([cultureinfo]::InvariantCulture), $groupName)
            }
            $tCount = Measure-PPGroupItemCount -GroupName $groupName -Value ([string]$groups[$groupName]) -AllowCidr:$AllowCidr -Origin 'Target' -Row $row.Row -Contract $Contract
        }
        else {
            $tCount = [long]1
        }

        $eTotal += ($sCount * $tCount)
        $pTotal += $tCount
        if ($eTotal -gt $limit -or $pTotal -gt $limit) {
            Invoke-PPRefusal -Code 'CapExceeded.Expansion' -Row $row.Row -Message ('profile expands to {0} rows ({1} probe targets); the limit is {2} = cap x {3}; nothing was built, resolved or sent' -f
                $eTotal.ToString([cultureinfo]::InvariantCulture), $pTotal.ToString([cultureinfo]::InvariantCulture), $limit.ToString([cultureinfo]::InvariantCulture),
                ([int]$Contract.ExpansionFactor).ToString([cultureinfo]::InvariantCulture))
        }
    }

    # Pass 2: build. No ExpandedRow or Probe exists above this line.
    $expandedRows = [System.Collections.Generic.List[object]]::new()
    $probesByKey = [ordered]@{}
    $distinctTargets = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)

    foreach ($row in @($ProfileDocument.Rows)) {
        $srcKind = Get-PPTargetKind -Text $row.Source
        $tgtKind = Get-PPTargetKind -Text $row.Target

        $srcGroupName = ''
        if ($srcKind.Kind -ceq 'Group') {
            $srcGroupName = $srcKind.Text
            $sourceItems = Expand-PPGroupValue -Name $srcGroupName -Value ([string]$groups[$srcGroupName]) -AllowCidr:$AllowCidr -Origin 'Source' -Contract $Contract
        }
        else {
            $sourceItems = , $srcKind
        }

        $tgtGroupName = ''
        if ($tgtKind.Kind -ceq 'Group') {
            $tgtGroupName = $tgtKind.Text
            $targetItems = Expand-PPGroupValue -Name $tgtGroupName -Value ([string]$groups[$tgtGroupName]) -AllowCidr:$AllowCidr -Origin 'Target' -Contract $Contract
            foreach ($targetItem in $targetItems) {
                if ($targetItem.Kind -ceq 'IPv4' -or $targetItem.Kind -ceq 'IPv6') {
                    Assert-PPLiteralTargetClass -Address $targetItem.Address -Row $row.Row -Field 'Target' -Origin $targetItem.Text
                }
            }
        }
        else {
            $targetItems = , $tgtKind
        }

        foreach ($sourceItem in $sourceItems) {
            $sourceName = $sourceItem.Text
            if ($srcGroupName.Length -gt 0) {
                if ($sourceItem.Kind -ceq 'Hostname') { $sourceName = '{0}:{1}' -f $srcGroupName, $sourceItem.Text }
                else { $sourceName = $srcGroupName }
            }
            $sourceIp = ''
            if ($sourceItem.Kind -ceq 'IPv4' -or $sourceItem.Kind -ceq 'IPv6') { $sourceIp = $sourceItem.Text }

            foreach ($targetItem in $targetItems) {
                $targetName = $targetItem.Text
                if ($tgtGroupName.Length -gt 0) {
                    if ($targetItem.Kind -ceq 'Hostname') { $targetName = '{0}:{1}' -f $tgtGroupName, $targetItem.Text }
                    else { $targetName = $tgtGroupName }
                }

                $probeKey = '{0}|{1}|{2}' -f $targetItem.Text, ([int]$row.Port).ToString([cultureinfo]::InvariantCulture), $row.Protocol
                if (-not $probesByKey.Contains($probeKey)) {
                    $probesByKey[$probeKey] = [pscustomobject][ordered]@{
                        PSTypeName = 'PortProof.Probe'
                        ProbeKey   = $probeKey
                        Target     = $targetItem.Text
                        TargetKind = $targetItem.Kind
                        Address    = $targetItem.Address
                        Port       = $row.Port
                        Protocol   = $row.Protocol
                        Rows       = [System.Collections.Generic.List[int]]::new()
                    }
                    $distinctTargets[$targetItem.Text] = $true
                }
                $probeRowList = $probesByKey[$probeKey].Rows
                if (-not $probeRowList.Contains([int]$row.Row)) { [void]$probeRowList.Add([int]$row.Row) }

                $expandedRows.Add([pscustomobject][ordered]@{
                        PSTypeName  = 'PortProof.ExpandedRow'
                        Row         = $row.Row
                        SourceName  = $sourceName
                        SourceGroup = $srcGroupName
                        SourceIp    = $sourceIp
                        TargetName  = $targetName
                        TargetGroup = $tgtGroupName
                        TargetKind  = $targetItem.Kind
                        Port        = $row.Port
                        Protocol    = $row.Protocol
                        Service     = $row.Service
                        Required    = $row.Required
                        Notes       = $row.Notes
                        ProbeKey    = $probeKey
                    })
            }
        }
    }

    $probes = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $probesByKey.Keys) {
        $probeEntry = $probesByKey[$key]
        $probes.Add([pscustomobject][ordered]@{
                PSTypeName = 'PortProof.Probe'
                ProbeKey   = $probeEntry.ProbeKey
                Target     = $probeEntry.Target
                TargetKind = $probeEntry.TargetKind
                Address    = $probeEntry.Address
                Port       = $probeEntry.Port
                Protocol   = $probeEntry.Protocol
                Rows       = [int[]]$probeEntry.Rows.ToArray()
            })
    }

    $unusedGroups = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $groups.Keys) {
        if (-not $usedGroups.ContainsKey($key)) { $unusedGroups.Add($key) }
    }

    [pscustomobject][ordered]@{
        PSTypeName      = 'PortProof.Expansion'
        Rows            = [pscustomobject[]]$expandedRows.ToArray()
        Probes          = [pscustomobject[]]$probes.ToArray()
        GroupOverrides  = [string[]]$groupOverrides.ToArray()
        UnusedGroups    = [string[]]$unusedGroups.ToArray()
        DistinctTargets = [int]$distinctTargets.Count
    }
}
# ---- src/30-Resolver.ps1 ----
# PortProof resolver. The only file in src/ that references System.Net.Dns or any
# resolving API (AC11-4). Function definitions only.

function Get-PPDnsResolver {
    # The live Resolver seam: Kind 'Dns', an Invocations counter (incremented by
    # Resolve-PPProbeList, not here) and a Resolve scriptblock property. Resolve returns one or more
    # [IPAddress]; a timeout, a resolver exception or an empty answer throws an ErrorRecord whose
    # FullyQualifiedErrorId is 'PortProof.DnsFailure'. The closure calls no PortProof function (a
    # GetNewClosure() block runs in its own module scope and cannot see the script's functions), so
    # it builds its error record inline.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([int] $TimeoutMs = 5000)

    $waitMs = $TimeoutMs
    if ($waitMs -lt 1) { $waitMs = 1 }

    $resolve = {
        param([string] $Name)

        $answer = $null
        $reason = 'did not resolve'
        try {
            $pending = [System.Net.Dns]::BeginGetHostAddresses($Name, $null, $null)
            if ($pending.AsyncWaitHandle.WaitOne($waitMs)) {
                $answer = [System.Net.Dns]::EndGetHostAddresses($pending)
                $pending.AsyncWaitHandle.Close()
            }
            else {
                # The lookup is abandoned, not cancelled: the OS resolver has no cancel. Its wait
                # handle is left to the finaliser because the lookup may still signal it.
                $reason = 'timed out'
            }
        }
        catch {
            $answer = $null
            $reason = 'did not resolve'
        }

        if ($null -eq $answer -or @($answer).Count -eq 0) {
            $shown = [regex]::Replace([string]$Name, '[\u0000-\u001F\u007F-\u009F]', '?',
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
            if ($shown.Length -gt 253) { $shown = $shown.Substring(0, 253) }
            $exception = [System.InvalidOperationException]::new("PortProof: name '$shown' $reason.")
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'PortProof.DnsFailure',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound, $shown)
            throw $record
        }
        $answer
    }.GetNewClosure()

    [pscustomobject][ordered]@{
        PSTypeName  = 'PortProof.Resolver'
        Kind        = 'Dns'
        Invocations = 0
        Resolve     = $resolve
    }
}

function Resolve-PPProbeList {
    # -> PortProof.Resolution. Literals are canonicalised without a Resolve call.
    # Names get one Resolve call per distinct lowercase name (cache); TargetIp is the canonical
    # first address and ResolvedAddresses holds every returned address, canonical, in returned
    # order. PortProof.DnsFailure marks the entry Failed and produces no ExecProbe; any other
    # exception (PortProof.DryRunResolutionAttempted included) propagates unchanged. ExecProbes are
    # deduplicated on ExecKey, so CountAfter <= CountBefore by construction. JitterMs is left 0: the
    # Gate assigns it.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Probes,
        [Parameter(Mandatory)] [pscustomobject] $Resolver
    )

    $inv = [cultureinfo]::InvariantCulture
    $entries = @{}
    $cache = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $execByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $execProbes = [System.Collections.Generic.List[object]]::new()
    $countBefore = 0

    foreach ($probe in $Probes) {
        if ($null -eq $probe) { continue }
        $countBefore++
        $probeKey = [string]$probe.ProbeKey
        $kind = [string]$probe.TargetKind
        $addresses = $null
        $failed = $false

        if ($kind -ceq 'IPv4' -or $kind -ceq 'IPv6') {
            if ($probe.Address -isnot [System.Net.IPAddress]) {
                Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: literal probe '{0}' carries no address." -f (Get-PPSafeText -Text $probeKey))
            }
            $addresses = @(ConvertTo-CanonicalAddress -Address $probe.Address)
        }
        elseif ($kind -ceq 'Hostname') {
            $name = ([string]$probe.Target).ToLowerInvariant()
            if (-not $cache.ContainsKey($name)) {
                $Resolver.Invocations = [int]$Resolver.Invocations + 1
                $outcome = $null
                try {
                    $returned = @(& $Resolver.Resolve $name)
                    $canonical = [System.Collections.Generic.List[object]]::new()
                    foreach ($item in $returned) {
                        if ($item -isnot [System.Net.IPAddress]) {
                            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: the resolver returned a non-address for '{0}'." -f (Get-PPSafeText -Text $name))
                        }
                        $canonical.Add((ConvertTo-CanonicalAddress -Address $item))
                    }
                    if ($canonical.Count -gt 0) { $outcome = $canonical.ToArray() }
                }
                catch {
                    if ([string]$_.FullyQualifiedErrorId -cne 'PortProof.DnsFailure') { throw }
                    $outcome = $null
                }
                $cache[$name] = $outcome
            }
            $addresses = $cache[$name]
            if ($null -eq $addresses) { $failed = $true }
        }
        else {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: probe '{0}' has target kind '{1}'." -f (Get-PPSafeText -Text $probeKey), (Get-PPSafeText -Text $kind))
        }

        $targetIp = $null
        $resolvedText = [string[]]@()
        if (-not $failed) {
            $targetIp = $addresses[0]
            $texts = [System.Collections.Generic.List[string]]::new()
            foreach ($a in $addresses) { $texts.Add($a.ToString()) }
            $resolvedText = $texts.ToArray()
        }

        $entries[$probeKey] = [pscustomobject][ordered]@{
            PSTypeName        = 'PortProof.ResolutionEntry'
            TargetIp          = $targetIp
            ResolvedAddresses = $resolvedText
            Failed            = $failed
            TargetName        = [string]$probe.Target
            Rows              = @($probe.Rows)
        }

        if ($failed) { continue }
        $port = [int]$probe.Port
        $protocol = [string]$probe.Protocol
        $execKey = '{0}|{1}|{2}' -f $targetIp.ToString(), $port.ToString($inv), $protocol
        if ($execByKey.ContainsKey($execKey)) { continue }
        $exec = [pscustomobject][ordered]@{
            PSTypeName = 'PortProof.ExecProbe'
            ExecKey    = $execKey
            TargetIp   = $targetIp
            Port       = $port
            Protocol   = $protocol
            JitterMs   = 0
        }
        $execByKey[$execKey] = $exec
        $execProbes.Add($exec)
    }

    [pscustomobject][ordered]@{
        PSTypeName  = 'PortProof.Resolution'
        Entries     = $entries
        ExecProbes  = $execProbes.ToArray()
        CountBefore = $countBefore
        CountAfter  = $execProbes.Count
    }
}
# ---- src/35-Gate.ps1 ----
# PortProof Gate: the sole admission point between resolution and the first socket,
# and the only caller of Invoke-ProbeSchedule in src/ (AC30). Function definitions only.

function Invoke-PPGate {
    # Order, all before any socket: (1) invariant and effective cap, (2) class check on every
    # resolved address and on every ExecProbe.TargetIp, (3) ICMP echoes, (4) the one authoritative
    # cap, (5) jitter, (6) OnAdmitted, then the Scheduler. Throws only PortProof.InternalInvariant,
    # PortProof.RefusedTargetClass and PortProof.CapExceeded.Admitted.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Resolution,
        [Parameter(Mandatory)] [int] $Cap,
        [switch] $Icmp,
        [Parameter(Mandatory)] [hashtable] $Schedule,
        [Parameter(Mandatory)] [hashtable] $Adapters,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder,
        [scriptblock] $OnAdmitted
    )

    $inv = [cultureinfo]::InvariantCulture

    # 1. Invariant. The counts the resolver reports must match what it built, and resolution must
    #    never have grown the list. The effective cap can never exceed the absolute ceiling.
    $execProbes = @($Resolution.ExecProbes | Where-Object { $null -ne $_ })
    $countBefore = [int]$Resolution.CountBefore
    $countAfter = [int]$Resolution.CountAfter
    if ($countAfter -ne $execProbes.Count -or $countAfter -gt $countBefore) {
        Invoke-PPRefusal -Code 'InternalInvariant' -Message ('internal error: resolution count invariant violated (before {0}, after {1}, built {2}).' -f
            $countBefore.ToString($inv), $countAfter.ToString($inv), $execProbes.Count.ToString($inv))
    }
    $effectiveCap = [Math]::Min($Cap, [int](Get-PPContract).AbsoluteProbeCeiling)

    # 2. Class check, twice over, with one predicate call per distinct address text (the verdict is
    #    cached), so the cost stays linear in distinct addresses at the 8192 ceiling.
    #    (a) Every address every non-failed entry resolved to, in a deterministic order:
    #    lowest profile row first, then ProbeKey.
    $verdicts = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $entries = $Resolution.Entries
    if ($null -eq $entries) { $entries = @{} }
    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $entries.Keys) {
        $entry = $entries[$k]
        if ($null -eq $entry -or [bool]$entry.Failed) { continue }
        $first = 0
        foreach ($r in @($entry.Rows)) {
            if ($null -eq $r) { continue }
            $n = [int]$r
            if ($first -eq 0 -or $n -lt $first) { $first = $n }
        }
        $pending.Add([pscustomobject]@{ Row = $first; Key = [string]$k; Entry = $entry })
    }
    $firstByIp = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @($pending | Sort-Object -Property Row, Key -CaseSensitive)) {
        $name = [string]$item.Entry.TargetName
        $candidates = [System.Collections.Generic.List[object]]::new()
        foreach ($text in @($item.Entry.ResolvedAddresses)) {
            $parsed = $null
            if (-not [System.Net.IPAddress]::TryParse([string]$text, [ref]$parsed)) {
                Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: resolved address '{0}' for '{1}' does not parse." -f
                    (Get-PPSafeText -Text ([string]$text)), (Get-PPSafeText -Text $name))
            }
            $candidates.Add($parsed)
        }
        if ($item.Entry.TargetIp -is [System.Net.IPAddress]) { $candidates.Add($item.Entry.TargetIp) }
        foreach ($address in $candidates) {
            $verdict = $null
            if (-not $verdicts.TryGetValue($address.ToString(), [ref]$verdict)) {
                $verdict = Test-RefusedTargetClass -Address $address
                $verdicts[$address.ToString()] = $verdict
            }
            if ($verdict.Refused) { Invoke-PPClassRefusal -Address $address -Verdict $verdict -Row $item.Row -Name $name }
            $canonicalText = $verdict.Canonical.ToString()
            if (-not $firstByIp.ContainsKey($canonicalText)) { $firstByIp[$canonicalText] = @($item.Row, $name) }
        }
    }

    #    (b) Every ExecProbe about to be scheduled, whatever Entries says (the check does not depend
    #    on how Entries was built). Shape checks fail closed as an internal error. The admitted
    #    list carries the canonical address the predicate judged.
    $admitted = [System.Collections.Generic.List[object]]::new()
    foreach ($probe in $execProbes) {
        if ($probe.TargetIp -isnot [System.Net.IPAddress]) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: ExecProbe '{0}' carries no address." -f (Get-PPSafeText -Text ([string]$probe.ExecKey)))
        }
        $protocol = [string]$probe.Protocol
        $port = [int]$probe.Port
        if (($protocol -cne 'TCP' -and $protocol -cne 'UDP') -or $port -lt 1 -or $port -gt 65535) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: ExecProbe '{0}' is not a TCP/UDP probe to port 1..65535." -f (Get-PPSafeText -Text ([string]$probe.ExecKey)))
        }
        $verdict = $null
        if (-not $verdicts.TryGetValue($probe.TargetIp.ToString(), [ref]$verdict)) {
            $verdict = Test-RefusedTargetClass -Address $probe.TargetIp
            $verdicts[$probe.TargetIp.ToString()] = $verdict
        }
        if ($verdict.Refused) {
            $ipText = $verdict.Canonical.ToString()
            $row = 0
            $name = $ipText
            if ($firstByIp.ContainsKey($ipText)) {
                $row = [int]$firstByIp[$ipText][0]
                $name = [string]$firstByIp[$ipText][1]
            }
            Invoke-PPClassRefusal -Address $probe.TargetIp -Verdict $verdict -Row $row -Name $name
        }
        $admitted.Add([pscustomobject][ordered]@{
                PSTypeName = 'PortProof.ExecProbe'
                ExecKey    = [string]$probe.ExecKey
                TargetIp   = $verdict.Canonical
                Port       = $port
                Protocol   = $protocol
                JitterMs   = 0
            })
    }

    # 3. ICMP: one echo per distinct TargetIp, appended after the TCP/UDP probes.
    $icmpCount = 0
    if ($Icmp) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($probe in @($admitted.ToArray())) {
            $ipText = $probe.TargetIp.ToString()
            if (-not $seen.Add($ipText)) { continue }
            $admitted.Add([pscustomobject][ordered]@{
                    PSTypeName = 'PortProof.ExecProbe'
                    ExecKey    = $ipText + '|0|ICMP'
                    TargetIp   = $probe.TargetIp
                    Port       = 0
                    Protocol   = 'ICMP'
                    JitterMs   = 0
                })
            $icmpCount++
        }
    }

    # 4. The one authoritative cap, over resolved probes with ICMP included.
    $total = $admitted.Count
    if ($total -gt $effectiveCap) {
        Invoke-PPRefusal -Code 'CapExceeded.Admitted' -Message ('{0} admitted probes exceed the cap of {1}; nothing was sent' -f
            $total.ToString($inv), $effectiveCap.ToString($inv))
    }

    # 5. Jitter, precomputed on this thread from one generator (no identical seeds across workers).
    $jitter = [int]$Schedule['JitterMs']
    if ($jitter -gt 0) {
        $random = [System.Random]::new()
        foreach ($probe in $admitted) { $probe.JitterMs = $random.Next(0, $jitter + 1) }
    }

    # 6. Admission is final: tell the caller, then schedule. The admitted list is frozen into an
    #    array first: the callback runs in a child scope of this function, so it can see this
    #    function's variables by name, and nothing it does may change what is scheduled. Its output
    #    is discarded.
    $requested = [string]$Schedule['ExecutionPath']
    if ([string]::IsNullOrEmpty($requested)) { $requested = 'Auto' }
    $executionPath = Get-PPExecutionPath -Requested $requested
    $scheduled = $admitted.ToArray()
    if ($null -ne $OnAdmitted) { $null = & $OnAdmitted $total }
    if ($scheduled.Count -ne $total) {
        Invoke-PPRefusal -Code 'InternalInvariant' -Message 'internal error: the admitted probe list changed during admission.'
    }

    $scheduleArgs = @{
        Probes        = $scheduled
        Adapters      = $Adapters
        Recorder      = $Recorder
        ExecutionPath = $executionPath
    }
    foreach ($name in @('Concurrency', 'MaxProbesPerSecond', 'TimeoutMs')) {
        if ($Schedule.ContainsKey($name) -and $null -ne $Schedule[$name]) { $scheduleArgs[$name] = [int]$Schedule[$name] }
    }
    $results = @(Invoke-ProbeSchedule @scheduleArgs)
    if ($total -eq 0) { $executionPath = 'None' }

    [pscustomobject][ordered]@{
        PSTypeName    = 'PortProof.GateResult'
        Results       = $results
        AdmittedCount = $total
        IcmpCount     = $icmpCount
        ExecutionPath = $executionPath
    }
}

function Invoke-PPClassRefusal {
    # Throws PortProof.RefusedTargetClass naming the row, the name as written, the address and the
    # class label.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [pscustomobject] $Verdict,
        [int] $Row,
        [AllowEmptyString()] [string] $Name
    )

    $message = "row {0} target '{1}' resolves to {2}: {3}; PortProof refuses this address class" -f
        $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $Name), $Address.ToString(), $Verdict.ClassLabel
    Invoke-PPRefusal -Code 'RefusedTargetClass' -Message $message -Row $Row -Detail @{
        Name = $Name; Address = $Address.ToString(); Class = [string]$Verdict.Class
    }
}
# ---- src/40-Scheduler.ps1 ----
# PortProof scheduler. Function definitions only.
#
# Per-target serial queues are the per-target lock: probes are grouped by canonical TargetIp and
# one queue runs strictly in order inside one worker, so two probes to one address never overlap
# on either execution path. Concurrency is the number of queues in flight. One rate gate is shared
# by reference across all workers. Adapters are taken by function NAME and called exactly once per
# probe; there is no retry anywhere.
#
# Worker set (transported into worker runspaces, closed under calls - Test-WorkerClosure.ps1):
# Invoke-PPTargetQueue, Wait-PPRateSlot, Get-PPOutcome (05-Contract.ps1) and the adapters named in
# -Adapters. These call only each other, .NET and Start-Sleep. Function text reaches a worker only
# through Get-PPWorkerDefinition: SessionStateFunctionEntry on the 5.1
# runspace-pool path, one function-drive Set-Item inside the -Parallel block on the 7.x path.

function Get-PPExecutionPath {
    # 'Auto' -> 'Parallel' on PowerShell 7 or later, else 'Runspace'. 'Parallel' below 7 is refused.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Requested)

    $major = [int]$PSVersionTable.PSVersion.Major
    if ($Requested -ceq 'Auto') {
        if ($major -ge 7) { return 'Parallel' }
        return 'Runspace'
    }
    if ($Requested -ceq 'Runspace') { return 'Runspace' }
    if ($Requested -ceq 'Parallel') {
        if ($major -lt 7) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message 'internal error: the Parallel execution path needs PowerShell 7 or later.'
        }
        return 'Parallel'
    }
    Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: unknown execution path '{0}'." -f (Get-PPSafeText -Text $Requested))
}

function Get-PPWorkerDefinition {
    # The one reader of function text for transport: an [ordered] name -> source text
    # map, read only through Get-Command -CommandType Function for names from the fixed worker set
    # and the -Adapters map. Also records, per name, whether the function declares -Recorder, so that
    # decision is made here on the calling thread and travels to the worker as a boolean.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Names,
        [Parameter(Mandatory)] [hashtable] $TakesRecorder
    )

    $definitions = [ordered]@{}
    foreach ($n in $Names) {
        if ($definitions.Contains($n)) { continue }
        if ($n -cnotmatch '\A[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*\z') {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: '{0}' is not a function name." -f (Get-PPSafeText -Text $n))
        }
        $found = @(Get-Command -CommandType Function -Name $n -ErrorAction SilentlyContinue)
        if ($found.Count -ne 1) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: worker function '{0}' is not loaded." -f (Get-PPSafeText -Text $n))
        }
        $definitions[$n] = $found[0].ScriptBlock.ToString()
        $TakesRecorder[$n] = [bool]$found[0].Parameters.ContainsKey('Recorder')
    }
    $definitions
}

function Invoke-ProbeSchedule {
    # -> ProbeResult[], exactly one per ExecProbe (returned in input order). Called
    # only from Invoke-PPGate (AC30). Disposes every worker in finally, Ctrl+C included.
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Probes,
        [Parameter(Mandatory)] [hashtable] $Adapters,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder,
        [ValidateRange(1, 64)] [int] $Concurrency = 16,
        [ValidateRange(1, 500)] [int] $MaxProbesPerSecond = 50,
        [ValidateRange(100, 30000)] [int] $TimeoutMs = 2000,
        [ValidateSet('Auto', 'Runspace', 'Parallel')] [string] $ExecutionPath = 'Auto'
    )

    $work = @($Probes | Where-Object { $null -ne $_ })
    if ($work.Count -eq 0) { return }
    $path = Get-PPExecutionPath -Requested $ExecutionPath

    # Adapter names: one per protocol in use, all from -Adapters.
    $adapterNames = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $Adapters.Keys) {
        $value = [string]$Adapters[$key]
        if (-not $adapterNames.Contains($value)) { $adapterNames.Add($value) }
    }
    foreach ($probe in $work) {
        $protocol = [string]$probe.Protocol
        if (-not $Adapters.ContainsKey($protocol) -or [string]::IsNullOrEmpty([string]$Adapters[$protocol])) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: no adapter for protocol '{0}'." -f (Get-PPSafeText -Text $protocol))
        }
    }
    $takesRecorder = @{}
    $names = [string[]](@('Invoke-PPTargetQueue', 'Wait-PPRateSlot', 'Get-PPOutcome') + $adapterNames.ToArray())
    $defs = Get-PPWorkerDefinition -Names $names -TakesRecorder $takesRecorder

    # The rate gate, shared by reference by every worker.
    $rate = [hashtable]::Synchronized(@{
            NextTicks     = [long]0
            IntervalTicks = [long]([System.Diagnostics.Stopwatch]::Frequency / $MaxProbesPerSecond)
        })

    # Per-target queues: groups in first-appearance order of canonical TargetIp, probes in input order.
    $queueByIp = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $queueOrder = [System.Collections.Generic.List[string]]::new()
    foreach ($probe in $work) {
        $ipText = $probe.TargetIp.ToString()
        if (-not $queueByIp.ContainsKey($ipText)) {
            $queueByIp[$ipText] = [System.Collections.Generic.List[object]]::new()
            $queueOrder.Add($ipText)
        }
        $adapterName = [string]$Adapters[[string]$probe.Protocol]
        $queueByIp[$ipText].Add([pscustomobject][ordered]@{
                ExecKey      = [string]$probe.ExecKey
                TargetIp     = $probe.TargetIp
                Port         = [int]$probe.Port
                Protocol     = [string]$probe.Protocol
                JitterMs     = [int]$probe.JitterMs
                AdapterName  = $adapterName
                PassRecorder = ([bool]$takesRecorder[$adapterName] -and $null -ne $Recorder)
            })
    }
    $workItems = [System.Collections.Generic.List[object]]::new()
    foreach ($ipText in $queueOrder) {
        $workItems.Add([pscustomobject][ordered]@{
                Queue     = $queueByIp[$ipText].ToArray()
                Rate      = $rate
                Recorder  = $Recorder
                TimeoutMs = $TimeoutMs
            })
    }

    $collected = [System.Collections.Generic.List[object]]::new()
    if ($path -ceq 'Parallel') {
        # 7.x path. NOT-VERIFIED on this host (no pwsh): runs in the PS7 test group in CI. The work
        # item carries the shared rate gate and Recorder by reference; the only $using: value is the
        # worker definitions from Get-PPWorkerDefinition.
        # Failure handling mirrors the 5.1 path exactly: a queue's output is kept only when the whole
        # queue completed (EndInvoke throws and yields nothing when a 5.1 worker fails); a failed
        # queue comes back as one PortProof.WorkerFailure marker, which becomes the same warning
        # here, and its probes become ProbeError rows in the fill step below. No retry. The worker's
        # error stream is discarded, as the 5.1 path never reads PowerShell.Streams.Error, so no
        # error record can reach a caller running with ErrorActionPreference 'Stop'.
        $parallelOut = $workItems | ForEach-Object -Parallel {
            try {
                $workerDefs = $using:defs
                foreach ($d in $workerDefs.GetEnumerator()) { Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value }
                $queueOut = @(Invoke-PPTargetQueue -Queue $_.Queue -Rate $_.Rate -Recorder $_.Recorder -TimeoutMs $_.TimeoutMs 2>$null)
                $queueOut
            }
            catch {
                [pscustomobject]@{ PSTypeName = 'PortProof.WorkerFailure'; Message = [string]$_.Exception.Message }
            }
        } -ThrottleLimit $Concurrency
        foreach ($o in @($parallelOut)) {
            if ($null -eq $o) { continue }
            if ($o.PSObject.TypeNames[0] -ceq 'PortProof.WorkerFailure') {
                Write-Warning -Message ('PortProof: a probe worker failed: {0}' -f (Get-PPSafeText -Text ([string]$o.Message)))
                continue
            }
            $collected.Add($o)
        }
    }
    else {
        # 5.1 path: one runspace pool of $Concurrency, one [PowerShell] per queue.
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        foreach ($d in $defs.GetEnumerator()) {
            $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($d.Key, $d.Value))
        }
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Concurrency, $iss, $Host)
        $jobs = [System.Collections.Generic.List[object]]::new()
        try {
            $pool.Open()
            foreach ($item in $workItems) {
                $ps = [System.Management.Automation.PowerShell]::Create()
                $jobs.Add([pscustomobject]@{ PowerShell = $ps; Handle = $null })
                $ps.RunspacePool = $pool
                [void]$ps.AddCommand('Invoke-PPTargetQueue').AddParameter('Queue', $item.Queue).AddParameter('Rate', $item.Rate).AddParameter('Recorder', $item.Recorder).AddParameter('TimeoutMs', $item.TimeoutMs)
                $jobs[$jobs.Count - 1].Handle = $ps.BeginInvoke()
            }
            foreach ($job in $jobs) {
                # A bounded wait in a loop, so Ctrl+C is honoured between waits and reaches finally.
                while (-not $job.Handle.AsyncWaitHandle.WaitOne(100)) { continue }
                try {
                    foreach ($o in $job.PowerShell.EndInvoke($job.Handle)) { if ($null -ne $o) { $collected.Add($o) } }
                }
                catch {
                    Write-Warning -Message ('PortProof: a probe worker failed: {0}' -f (Get-PPSafeText -Text $_.Exception.Message))
                }
            }
        }
        finally {
            foreach ($job in $jobs) { $job.PowerShell.Dispose() }
            try { $pool.Close() } catch { $null = $_ }   # a pool that never opened has nothing to close
            $pool.Dispose()
        }
    }

    # Exactly one result per ExecProbe: a queue whose worker failed yields ProbeError rows, never
    # missing rows; a result for a key nobody asked for, or a second result for a key, is dropped.
    $byKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($r in $collected) {
        $k = [string]$r.ExecKey
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = $r }
    }
    $missing = 0
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($probe in $work) {
        $k = [string]$probe.ExecKey
        if ($byKey.ContainsKey($k)) {
            $results.Add($byKey[$k])
            continue
        }
        $missing++
        $results.Add([pscustomobject][ordered]@{
                PSTypeName = 'PortProof.ProbeResult'
                ExecKey    = $k
                TargetIp   = $probe.TargetIp.ToString()
                Port       = [int]$probe.Port
                Protocol   = [string]$probe.Protocol
                State      = ''
                ErrorName  = 'ProbeError'
                Outcome    = Get-PPOutcome -Protocol ([string]$probe.Protocol) -State '' -ErrorName 'ProbeError'
                LatencyMs  = $null
                Timestamp  = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)
            })
    }
    if ($missing -gt 0) {
        Write-Warning -Message ('PortProof: {0} probe(s) produced no result from their worker and are reported as ProbeError.' -f
            $missing.ToString([cultureinfo]::InvariantCulture))
    }
    $results.ToArray()
}

function Invoke-PPTargetQueue {
    # Worker set. Runs one target's probes strictly in order: sleep JitterMs, take a rate slot,
    # stamp the time, call the adapter exactly once, classify via Get-PPOutcome. No retry. The one
    # dynamic call in the worker set is the adapter dispatch on $AdapterName; its value is always a
    # name the caller took from the -Adapters map.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Queue,
        [Parameter(Mandatory)] [hashtable] $Rate,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder,
        [Parameter(Mandatory)] [int] $TimeoutMs,
        [string] $AdapterName = ''
    )

    foreach ($item in $Queue) {
        if ([int]$item.JitterMs -gt 0) { Start-Sleep -Milliseconds ([int]$item.JitterMs) }
        Wait-PPRateSlot -Rate $Rate
        $stamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)

        $protocol = [string]$item.Protocol
        $AdapterName = [string]$item.AdapterName
        $callArgs = @{ Address = $item.TargetIp; Port = [int]$item.Port; TimeoutMs = $TimeoutMs }
        if ([bool]$item.PassRecorder) { $callArgs['Recorder'] = $Recorder }

        $state = ''
        $errorName = 'ProbeError'
        $latency = $null
        try {
            $returned = @(& $AdapterName @callArgs)
            if ($returned.Count -eq 1 -and $null -ne $returned[0]) {
                $state = [string]$returned[0].State
                $errorName = [string]$returned[0].ErrorName
                if ($null -ne $returned[0].LatencyMs) { $latency = [int]$returned[0].LatencyMs }
            }
        }
        catch {
            $state = ''
            $errorName = 'ProbeError'
            $latency = $null
        }

        # The adapter's State must be one its protocol can report (DESIGN 3.8.3); anything else is
        # a ProbeError, never a guess (a stray 'Open' on UDP silence would be a lie, AC7).
        $known = $false
        if ($state -ceq '' -or $errorName -ceq 'ProbeError') { $known = $true }
        elseif ($protocol -ceq 'TCP') { $known = ($state -ceq 'Open' -or $state -ceq 'Closed' -or $state -ceq 'Unreachable') }
        elseif ($protocol -ceq 'UDP') { $known = ($state -ceq 'Open' -or $state -ceq 'Closed' -or $state -ceq 'Open|Filtered') }
        elseif ($protocol -ceq 'ICMP') { $known = ($state -ceq 'Reply' -or $state -ceq 'NoReply') }
        if (-not $known -or [string]::IsNullOrEmpty($errorName)) {
            $state = ''
            $errorName = 'ProbeError'
        }
        if ($errorName -ceq 'ProbeError') { $state = '' }

        [pscustomobject][ordered]@{
            PSTypeName = 'PortProof.ProbeResult'
            ExecKey    = [string]$item.ExecKey
            TargetIp   = $item.TargetIp.ToString()
            Port       = [int]$item.Port
            Protocol   = $protocol
            State      = $state
            ErrorName  = $errorName
            Outcome    = Get-PPOutcome -Protocol $protocol -State $state -ErrorName $errorName
            LatencyMs  = $latency
            Timestamp  = $stamp
        }
    }
}

function Wait-PPRateSlot {
    # Worker set. Process-wide token bucket of one: take the next slot under the gate's lock
    # (slot = max(now, NextTicks); NextTicks = slot + IntervalTicks), then sleep until the slot, so
    # attempt starts are at least 1/R apart across every worker (AC29 c).
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Rate)

    $slot = [long]0
    $syncRoot = $Rate.SyncRoot
    [System.Threading.Monitor]::Enter($syncRoot)
    try {
        $now = [System.Diagnostics.Stopwatch]::GetTimestamp()
        $next = [long]$Rate['NextTicks']
        $slot = $next
        if ($now -gt $next) { $slot = $now }
        $Rate['NextTicks'] = $slot + [long]$Rate['IntervalTicks']
    }
    finally {
        [System.Threading.Monitor]::Exit($syncRoot)
    }

    $frequency = [double][System.Diagnostics.Stopwatch]::Frequency
    while ($true) {
        $remaining = $slot - [System.Diagnostics.Stopwatch]::GetTimestamp()
        if ($remaining -le 0) { break }
        $ms = [int][Math]::Ceiling(($remaining * 1000.0) / $frequency)
        if ($ms -lt 1) { $ms = 1 }
        Start-Sleep -Milliseconds $ms
    }
}
# ---- src/50-Probe.Tcp.ps1 ----
# PortProof TCP adapter. Function definitions only.

function Invoke-TcpProbe {
    # One full connect via TcpClient.BeginConnect bounded by an explicit wait. On success the socket
    # is closed at once: no stream, nothing read or written, no local bind. Never throws: any
    # exception becomes State '' / ProbeError. Worker set: calls no other function.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [int] $TimeoutMs
    )

    $state = ''
    $errorName = 'ProbeError'
    $client = $null
    $pending = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $client = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
        $pending = $client.BeginConnect($Address, $Port, $null, $null)
        if ($pending.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            try {
                $client.EndConnect($pending)
                $stopwatch.Stop()
                $state = 'Open'
                $errorName = 'None'
            }
            catch {
                $stopwatch.Stop()
                $code = ''
                $e = $_.Exception
                while ($null -ne $e) {
                    if ($null -ne $e.SocketErrorCode) { $code = [string]$e.SocketErrorCode; break }
                    $e = $e.InnerException
                }
                if ($code -ceq 'ConnectionRefused') { $state = 'Closed'; $errorName = 'ConnectionRefused' }
                elseif ($code -ceq 'TimedOut') { $state = 'Unreachable'; $errorName = 'Timeout' }
                elseif ($code -ceq 'HostUnreachable' -or $code -ceq 'NetworkUnreachable') { $state = 'Unreachable'; $errorName = 'HostUnreachable' }
                # AccessDenied (WSAEACCES 10013) on this connect means a policy on this host refused the attempt
                # before any packet left (observed live: a VPN's DNS-leak filter denies every connect to port
                # 53, even to 127.0.0.x with a listener bound). It proves nothing about the path: State '' and
                # LocalPolicy, Outcome Inconclusive. Any other code stays ProbeError.
                elseif ($code -ceq 'AccessDenied') { $state = ''; $errorName = 'LocalPolicy' }
                else { $state = ''; $errorName = 'ProbeError' }
            }
        }
        else {
            $stopwatch.Stop()
            $state = 'Unreachable'
            $errorName = 'Timeout'
            $client.Close()
            try {
                $client.EndConnect($pending)
            }
            catch {
                # Releases the abandoned connect's async state only; the outcome is already Timeout.
                $null = $_
            }
        }
    }
    catch {
        $state = ''
        $errorName = 'ProbeError'
    }
    finally {
        $stopwatch.Stop()
        if ($null -ne $pending) {
            try { $pending.AsyncWaitHandle.Close() } catch { $null = $_ }
        }
        if ($null -ne $client) {
            try { $client.Close() } catch { $null = $_ }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.AdapterResult'
        State      = $state
        ErrorName  = $errorName
        LatencyMs  = [int][Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
    }
}
# ---- src/55-Probe.Udp.ps1 ----
# PortProof UDP adapter. The only file in src/ allowed to receive (AC16).
# Function definitions only.

function Invoke-UdpProbe {
    # One zero-length datagram on a connected UdpClient, then one receive bounded by ReceiveTimeout.
    # Connecting is what makes Windows surface an ICMP port-unreachable as SocketError
    # ConnectionReset on the receive. A received datagram is discarded unread: neither its contents
    # nor its length is kept. Silence is Open|Filtered, never Open (AC7). No local bind. Never
    # throws. Worker set: calls no other function.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [int] $TimeoutMs
    )

    $state = ''
    $errorName = 'ProbeError'
    $udp = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $wait = $TimeoutMs
        if ($wait -lt 1) { $wait = 1 }   # 0 would mean "wait forever"
        $any = [System.Net.IPAddress]::Any
        if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $any = [System.Net.IPAddress]::IPv6Any }

        $udp = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
        $udp.Client.ReceiveTimeout = $wait
        $udp.Connect([System.Net.IPEndPoint]::new($Address, $Port))
        [void]$udp.Send([byte[]]::new(0), 0)
        $remote = [System.Net.IPEndPoint]::new($any, 0)
        try {
            [void]$udp.Receive([ref]$remote)
            $stopwatch.Stop()
            $state = 'Open'
            $errorName = 'None'
        }
        catch {
            $stopwatch.Stop()
            $code = ''
            $e = $_.Exception
            while ($null -ne $e) {
                if ($null -ne $e.SocketErrorCode) { $code = [string]$e.SocketErrorCode; break }
                $e = $e.InnerException
            }
            if ($code -ceq 'ConnectionReset') { $state = 'Closed'; $errorName = 'IcmpUnreachable' }
            elseif ($code -ceq 'TimedOut') { $state = 'Open|Filtered'; $errorName = 'NoResponse' }
            elseif ($code -ceq 'HostUnreachable' -or $code -ceq 'NetworkUnreachable') { $state = 'Closed'; $errorName = 'HostUnreachable' }
            # AccessDenied (WSAEACCES 10013) on this connect means a policy on this host refused the attempt
            # before any packet left (observed live: a VPN's DNS-leak filter denies every connect to port
            # 53, even to 127.0.0.x with a listener bound). It proves nothing about the path: State '' and
            # LocalPolicy, Outcome Inconclusive. Any other code stays ProbeError.
            elseif ($code -ceq 'AccessDenied') { $state = ''; $errorName = 'LocalPolicy' }
            else { $state = ''; $errorName = 'ProbeError' }
        }
    }
    catch {
        $state = ''
        $errorName = 'ProbeError'
    }
    finally {
        $stopwatch.Stop()
        if ($null -ne $udp) {
            try { $udp.Close() } catch { $null = $_ }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.AdapterResult'
        State      = $state
        ErrorName  = $errorName
        LatencyMs  = [int][Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
    }
}
# ---- src/58-Probe.Icmp.ps1 ----
# PortProof ICMP adapter. Function definitions only.

function Invoke-IcmpProbe {
    # One zero-length ICMP echo through System.Net.NetworkInformation.Ping (no raw socket, no
    # administrator rights, no payload). Never throws. Worker set: calls no other function.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Port',
        Justification = 'Port is part of the one adapter signature the Scheduler calls for every protocol; an ICMP echo has no port, so the value (always 0) is accepted and not used.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [int] $Port = 0,
        [Parameter(Mandatory)] [int] $TimeoutMs
    )

    $state = ''
    $errorName = 'ProbeError'
    $ping = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send($Address, $TimeoutMs, [byte[]]::new(0))
        $stopwatch.Stop()
        $status = $reply.Status
        if ($status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $state = 'Reply'; $errorName = 'None' }
        elseif ($status -eq [System.Net.NetworkInformation.IPStatus]::TimedOut) { $state = 'NoReply'; $errorName = 'Timeout' }
        elseif ($status -eq [System.Net.NetworkInformation.IPStatus]::DestinationHostUnreachable -or
            $status -eq [System.Net.NetworkInformation.IPStatus]::DestinationNetworkUnreachable) { $state = 'NoReply'; $errorName = 'HostUnreachable' }
        else { $state = ''; $errorName = 'ProbeError' }
    }
    catch {
        $state = ''
        $errorName = 'ProbeError'
    }
    finally {
        $stopwatch.Stop()
        if ($null -ne $ping) {
            try { $ping.Dispose() } catch { $null = $_ }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.AdapterResult'
        State      = $state
        ErrorName  = $errorName
        LatencyMs  = [int][Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
    }
}
# ---- src/70-Render.Html.ps1 ----
# PortProof HTML renderer. A self-contained matrix report: CSP meta
# tag, one inline <style>, no <script>, no external reference of any kind. An own escaper,
# ConvertTo-PPHtmlText, is used in text and attribute positions alike - this replaces
# WebUtility.HtmlEncode, whose treatment of non-ASCII/astral characters differs between .NET
# Framework and .NET. Pure: no clock, environment, filesystem, randomness or
# culture dependency. Literal member access only: no computed member names.

function ConvertTo-PPHtmlText {
    # Maps '&' '<' '>' '"' ''' to their entities; every other character (incl. non-ASCII and
    # astral surrogate pairs) passes through raw. String.Replace is ordinal, not culture-sensitive,
    # so this is byte-identical under every culture and host.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [AllowNull()] [string] $Text)

    $t = $Text
    if ($null -eq $t) { return '' }
    $t = $t.Replace('&', '&amp;')
    $t = $t.Replace('<', '&lt;')
    $t = $t.Replace('>', '&gt;')
    $t = $t.Replace('"', '&quot;')
    $t = $t.Replace("'", '&#39;')
    return $t
}

function ConvertTo-PPHtmlScalarText {
    # Value -> plain (unescaped) display text: booleans lowercase, integers invariant, null empty,
    # everything else as-is. The caller still runs the result through ConvertTo-PPHtmlText.
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'true' }; return 'false' }
    if ($Value -is [int] -or $Value -is [long]) { return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function Get-PPHtmlMatrixColumnKey {
    # Distinct Service, or "<Protocol>/<Port>" when Service is empty.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $Row)

    $service = [string]$Row.Service
    if (-not [string]::IsNullOrEmpty($service)) { return $service }
    return '{0}/{1}' -f [string]$Row.Protocol, ([int]$Row.Port).ToString([System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-PPHtml {
    # Sections, in order: title; authorized-use notice; run-header table; matrix
    # (rows = distinct SourceName, columns = distinct Service/"<Protocol>/<Port>", cell = worst
    # outcome, text "n/m pass", class from the closed map Pass->ok/Fail->bad/Inconclusive->warn);
    # detail table of every ResultRow; legend explaining Open|Filtered; footnote = OriginNote.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $ResultSet)

    $header = $ResultSet.Header
    $flags = $header.Flags
    $rows = @($ResultSet.Rows)

    # --- Run-header pairs (Flags flattened as "Flags.<Name>", same order as the CSV render and
    #     90-Main.ps1's Write-PPRunHeader console rendering). ---
    $headerPairs = [System.Collections.Generic.List[object]]::new()
    $headerPairs.Add(@{ Name = 'ToolVersion'; Value = $header.ToolVersion })
    $headerPairs.Add(@{ Name = 'ProfileName'; Value = $header.ProfileName })
    $headerPairs.Add(@{ Name = 'ProfileVersion'; Value = $header.ProfileVersion })
    $headerPairs.Add(@{ Name = 'ProfileSha256'; Value = $header.ProfileSha256 })
    $headerPairs.Add(@{ Name = 'RunId'; Value = $header.RunId })
    $headerPairs.Add(@{ Name = 'StartedUtc'; Value = $header.StartedUtc })
    $headerPairs.Add(@{ Name = 'StartedLocal'; Value = $header.StartedLocal })
    $headerPairs.Add(@{ Name = 'OperatorUser'; Value = $header.OperatorUser })
    $headerPairs.Add(@{ Name = 'OperatorHost'; Value = $header.OperatorHost })
    $headerPairs.Add(@{ Name = 'ProbeCount'; Value = $header.ProbeCount })
    $headerPairs.Add(@{ Name = 'Flags.AllowLarge'; Value = $flags.AllowLarge })
    $headerPairs.Add(@{ Name = 'Flags.AllowCidr'; Value = $flags.AllowCidr })
    $headerPairs.Add(@{ Name = 'Flags.Icmp'; Value = $flags.Icmp })
    $headerPairs.Add(@{ Name = 'Flags.DryRun'; Value = $flags.DryRun })
    $headerPairs.Add(@{ Name = 'Flags.NoOperator'; Value = $flags.NoOperator })
    $headerPairs.Add(@{ Name = 'Flags.Force'; Value = $flags.Force })
    $headerPairs.Add(@{ Name = 'Flags.Quiet'; Value = $flags.Quiet })
    $headerPairs.Add(@{ Name = 'Flags.Ceiling'; Value = $flags.Ceiling })
    $headerPairs.Add(@{ Name = 'Flags.EffectiveCap'; Value = $flags.EffectiveCap })
    $headerPairs.Add(@{ Name = 'Flags.TimeoutMs'; Value = $flags.TimeoutMs })
    $headerPairs.Add(@{ Name = 'Flags.Concurrency'; Value = $flags.Concurrency })
    $headerPairs.Add(@{ Name = 'Flags.MaxProbesPerSecond'; Value = $flags.MaxProbesPerSecond })
    $headerPairs.Add(@{ Name = 'Flags.JitterMs'; Value = $flags.JitterMs })
    $headerPairs.Add(@{ Name = 'Flags.GroupOverrides'; Value = (@($flags.GroupOverrides) -join '; ') })
    $headerPairs.Add(@{ Name = 'Flags.ExecutionPath'; Value = $flags.ExecutionPath })
    $headerPairs.Add(@{ Name = 'IgnoredColumns'; Value = (@($header.IgnoredColumns) -join '; ') })
    $headerPairs.Add(@{ Name = 'AuthorizedUseNotice'; Value = $header.AuthorizedUseNotice })
    $headerPairs.Add(@{ Name = 'OriginNote'; Value = $header.OriginNote })
    $headerPairs.Add(@{ Name = 'ProbeCountBasis'; Value = $header.ProbeCountBasis })
    $headerPairs.Add(@{ Name = 'WorstCaseSeconds'; Value = $header.WorstCaseSeconds })

    $headerRows = [System.Collections.Generic.List[string]]::new()
    foreach ($pair in $headerPairs) {
        $valueText = ConvertTo-PPHtmlText -Text (ConvertTo-PPHtmlScalarText -Value $pair.Value)
        $headerRows.Add('<tr><td>' + $pair.Name + '</td><td>' + $valueText + '</td></tr>')
    }

    # --- Matrix: rows = distinct SourceName, columns = distinct Service/"<Protocol>/<Port>". ---
    $rowOrder = [System.Collections.Generic.List[string]]::new()
    $colOrder = [System.Collections.Generic.List[string]]::new()
    $bySource = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($row in $rows) {
        if ($null -eq $row) { continue }
        $srcKey = [string]$row.SourceName
        $colKey = Get-PPHtmlMatrixColumnKey -Row $row
        if (-not $rowOrder.Contains($srcKey)) { [void]$rowOrder.Add($srcKey) }
        if (-not $colOrder.Contains($colKey)) { [void]$colOrder.Add($colKey) }
        if (-not $bySource.ContainsKey($srcKey)) {
            $bySource[$srcKey] = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        }
        $cols = $bySource[$srcKey]
        if (-not $cols.ContainsKey($colKey)) {
            $cols[$colKey] = [pscustomobject]@{ Pass = 0; Total = 0; HasFail = $false; HasInconclusive = $false }
        }
        $cell = $cols[$colKey]
        $cell.Total = $cell.Total + 1
        if ($row.Outcome -ceq 'Pass') { $cell.Pass = $cell.Pass + 1 }
        elseif ($row.Outcome -ceq 'Fail') { $cell.HasFail = $true }
        else { $cell.HasInconclusive = $true }
    }

    $matrixHead = [System.Collections.Generic.List[string]]::new()
    $matrixHead.Add('<th></th>')
    foreach ($col in $colOrder) { $matrixHead.Add('<th>' + (ConvertTo-PPHtmlText -Text $col) + '</th>') }

    $matrixBody = [System.Collections.Generic.List[string]]::new()
    foreach ($src in $rowOrder) {
        $cells = [System.Collections.Generic.List[string]]::new()
        $cells.Add('<th>' + (ConvertTo-PPHtmlText -Text $src) + '</th>')
        $cols = $bySource[$src]
        foreach ($col in $colOrder) {
            if ($cols.ContainsKey($col)) {
                $cell = $cols[$col]
                $class = 'ok'
                if ($cell.HasFail) { $class = 'bad' } elseif ($cell.HasInconclusive) { $class = 'warn' }
                $text = '{0}/{1} pass' -f $cell.Pass.ToString([System.Globalization.CultureInfo]::InvariantCulture), $cell.Total.ToString([System.Globalization.CultureInfo]::InvariantCulture)
                $cells.Add('<td class="' + $class + '">' + $text + '</td>')
            }
            else {
                $cells.Add('<td></td>')
            }
        }
        $matrixBody.Add('<tr>' + ($cells -join '') + '</tr>')
    }

    # --- Detail table: every ResultRow, field order from Get-PPShapeFields. ---
    $detailFieldNames = @(Get-PPShapeFields -Shape 'ResultRow')
    $detailHead = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $detailFieldNames) { $detailHead.Add('<th>' + (ConvertTo-PPHtmlText -Text $name) + '</th>') }

    $detailBody = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $rows) {
        if ($null -eq $row) { continue }
        $values = @(
            $row.RunId, $row.Timestamp, $row.SourceName, $row.SourceIp, $row.TargetName, $row.TargetIp,
            (@($row.ResolvedAddresses) -join ';'), $row.Port, $row.Protocol, $row.Service, $row.Required,
            $row.Outcome, $row.State, $row.LatencyMs, $row.Error, $row.ProfileRow, $row.SourceGroup,
            $row.TargetGroup, $row.Notes
        )
        $cells = [System.Collections.Generic.List[string]]::new()
        foreach ($value in $values) {
            $cells.Add('<td>' + (ConvertTo-PPHtmlText -Text (ConvertTo-PPHtmlScalarText -Value $value)) + '</td>')
        }
        $detailBody.Add('<tr>' + ($cells -join '') + '</tr>')
    }

    $noticeText = ConvertTo-PPHtmlText -Text $header.AuthorizedUseNotice
    $originText = ConvertTo-PPHtmlText -Text $header.OriginNote

    $html = [System.Collections.Generic.List[string]]::new()
    [void]$html.Add('<!DOCTYPE html>')
    [void]$html.Add('<html lang="en">')
    [void]$html.Add('<head>')
    [void]$html.Add('<meta charset="utf-8">')
    [void]$html.Add('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">')
    [void]$html.Add('<title>PortProof Report</title>')
    [void]$html.Add('<style>')
    [void]$html.Add('body { font-family: Arial, Helvetica, sans-serif; margin: 1.5em; color: #111111; background: #ffffff; }')
    [void]$html.Add('h1, h2 { color: #111111; }')
    [void]$html.Add('table { border-collapse: collapse; margin-bottom: 1.5em; }')
    [void]$html.Add('th, td { border: 1px solid #999999; padding: 4px 8px; text-align: left; vertical-align: top; }')
    [void]$html.Add('th { background: #eeeeee; }')
    [void]$html.Add('td.ok { background: #d4edda; }')
    [void]$html.Add('td.bad { background: #f8d7da; }')
    [void]$html.Add('td.warn { background: #fff3cd; }')
    [void]$html.Add('footer { font-size: 0.9em; color: #555555; }')
    [void]$html.Add('</style>')
    [void]$html.Add('</head>')
    [void]$html.Add('<body>')
    [void]$html.Add('<h1>PortProof Report</h1>')
    [void]$html.Add('<section id="notice">')
    [void]$html.Add('<h2>Authorized use</h2>')
    [void]$html.Add('<p>' + $noticeText + '</p>')
    [void]$html.Add('</section>')
    [void]$html.Add('<section id="run-header">')
    [void]$html.Add('<h2>Run header</h2>')
    [void]$html.Add('<table>')
    [void]$html.Add('<tbody>')
    foreach ($line in $headerRows) { [void]$html.Add($line) }
    [void]$html.Add('</tbody>')
    [void]$html.Add('</table>')
    [void]$html.Add('</section>')
    [void]$html.Add('<section id="matrix">')
    [void]$html.Add('<h2>Matrix</h2>')
    [void]$html.Add('<table>')
    [void]$html.Add('<thead>')
    [void]$html.Add('<tr>' + ($matrixHead -join '') + '</tr>')
    [void]$html.Add('</thead>')
    [void]$html.Add('<tbody>')
    foreach ($line in $matrixBody) { [void]$html.Add($line) }
    [void]$html.Add('</tbody>')
    [void]$html.Add('</table>')
    [void]$html.Add('</section>')
    [void]$html.Add('<section id="detail">')
    [void]$html.Add('<h2>Detail</h2>')
    [void]$html.Add('<table>')
    [void]$html.Add('<thead>')
    [void]$html.Add('<tr>' + ($detailHead -join '') + '</tr>')
    [void]$html.Add('</thead>')
    [void]$html.Add('<tbody>')
    foreach ($line in $detailBody) { [void]$html.Add($line) }
    [void]$html.Add('</tbody>')
    [void]$html.Add('</table>')
    [void]$html.Add('</section>')
    [void]$html.Add('<section id="legend">')
    [void]$html.Add('<h2>Legend</h2>')
    [void]$html.Add('<p>ok: every probe in the cell passed. warn: at least one probe was inconclusive and none failed - for example Open|Filtered, where a UDP port received no reply, which happens whether the port is open or a firewall silently drops the probe; PortProof cannot tell those two apart from a missing reply alone. bad: at least one probe failed. Each cell also carries its own pass count as text, so the result does not depend on colour alone.</p>')
    [void]$html.Add('</section>')
    [void]$html.Add('<footer>')
    [void]$html.Add('<p>' + $originText + '</p>')
    [void]$html.Add('</footer>')
    [void]$html.Add('</body>')
    [void]$html.Add('</html>')

    return (($html -join "`n") + "`n")
}
# ---- src/72-Render.Csv.ps1 ----
# PortProof CSV renderer. One writer function,
# ConvertTo-PPCsvField, emits every field in the file - header records included, no exception for
# numeric columns. Pure: no clock, environment, filesystem, randomness or culture dependency;
# byte-identical under 5.1 and 7. Literal member access only: no computed member
# names; field order matches Get-PPShapeFields (90-Main.ps1's Write-PPRunHeader uses the identical
# order for its console rendering of the same shapes).

function ConvertTo-PPCsvField {
    # Anti-CSV-injection encoding for spreadsheet formula triggers. (1) CR/LF become a space. (2) The trigger
    # check runs on the first character AFTER stripping all leading Unicode whitespace (which
    # happens after the CR/LF -> space replacement above, so a value that starts with a CR, a tab
    # or plain spaces before '=' is still caught): '=' '+' '-' '@' and their fullwidth counterparts
    # U+FF1D U+FF0B U+FF0D U+FF20 all trigger a leading "'". (3) The (possibly prefixed) value is
    # then double-quoted, with '"' doubled.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [AllowNull()] [string] $Value)

    $v = $Value
    if ($null -eq $v) { $v = '' }
    $v = $v.Replace("`r`n", ' ').Replace("`r", ' ').Replace("`n", ' ')

    $prefix = ''
    $trimmed = $v.TrimStart()
    if ($trimmed.Length -gt 0) {
        $first = [string]$trimmed[0]
        $firstCode = [int]$trimmed[0]
        if ($first -ceq '=' -or $first -ceq '+' -or $first -ceq '-' -or $first -ceq '@' -or
            $firstCode -eq 0xFF1D -or $firstCode -eq 0xFF0B -or $firstCode -eq 0xFF0D -or $firstCode -eq 0xFF20) {
            $prefix = "'"
        }
    }

    $withPrefix = $prefix + $v
    $escaped = $withPrefix.Replace('"', '""')
    return '"' + $escaped + '"'
}

function ConvertTo-PPCsvScalarText {
    # Value -> plain text before CSV encoding: booleans lowercase, integers invariant, null empty,
    # everything else as-is. Arrays are joined by the caller (different fields use different
    # separators - RunHeader arrays '; ', ResolvedAddresses ';' - so this function only ever sees
    # a scalar).
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'true' }; return 'false' }
    if ($Value -is [int] -or $Value -is [long]) { return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function ConvertTo-PPCsv {
    # Run-header records first (one "#<Field>","<value>" record per RunHeader
    # field; Flags flattened to "#Flags.<Name>" records), then the RFC 4180 table (header row of
    # ResultRow field names, then one record per row). CRLF line endings; one trailing newline.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $ResultSet)

    $header = $ResultSet.Header
    $flags = $header.Flags
    $rows = @($ResultSet.Rows)

    $headerPairs = [System.Collections.Generic.List[object]]::new()
    $headerPairs.Add(@{ Name = 'ToolVersion'; Value = $header.ToolVersion })
    $headerPairs.Add(@{ Name = 'ProfileName'; Value = $header.ProfileName })
    $headerPairs.Add(@{ Name = 'ProfileVersion'; Value = $header.ProfileVersion })
    $headerPairs.Add(@{ Name = 'ProfileSha256'; Value = $header.ProfileSha256 })
    $headerPairs.Add(@{ Name = 'RunId'; Value = $header.RunId })
    $headerPairs.Add(@{ Name = 'StartedUtc'; Value = $header.StartedUtc })
    $headerPairs.Add(@{ Name = 'StartedLocal'; Value = $header.StartedLocal })
    $headerPairs.Add(@{ Name = 'OperatorUser'; Value = $header.OperatorUser })
    $headerPairs.Add(@{ Name = 'OperatorHost'; Value = $header.OperatorHost })
    $headerPairs.Add(@{ Name = 'ProbeCount'; Value = $header.ProbeCount })
    $headerPairs.Add(@{ Name = 'Flags.AllowLarge'; Value = $flags.AllowLarge })
    $headerPairs.Add(@{ Name = 'Flags.AllowCidr'; Value = $flags.AllowCidr })
    $headerPairs.Add(@{ Name = 'Flags.Icmp'; Value = $flags.Icmp })
    $headerPairs.Add(@{ Name = 'Flags.DryRun'; Value = $flags.DryRun })
    $headerPairs.Add(@{ Name = 'Flags.NoOperator'; Value = $flags.NoOperator })
    $headerPairs.Add(@{ Name = 'Flags.Force'; Value = $flags.Force })
    $headerPairs.Add(@{ Name = 'Flags.Quiet'; Value = $flags.Quiet })
    $headerPairs.Add(@{ Name = 'Flags.Ceiling'; Value = $flags.Ceiling })
    $headerPairs.Add(@{ Name = 'Flags.EffectiveCap'; Value = $flags.EffectiveCap })
    $headerPairs.Add(@{ Name = 'Flags.TimeoutMs'; Value = $flags.TimeoutMs })
    $headerPairs.Add(@{ Name = 'Flags.Concurrency'; Value = $flags.Concurrency })
    $headerPairs.Add(@{ Name = 'Flags.MaxProbesPerSecond'; Value = $flags.MaxProbesPerSecond })
    $headerPairs.Add(@{ Name = 'Flags.JitterMs'; Value = $flags.JitterMs })
    $headerPairs.Add(@{ Name = 'Flags.GroupOverrides'; Value = (@($flags.GroupOverrides) -join '; ') })
    $headerPairs.Add(@{ Name = 'Flags.ExecutionPath'; Value = $flags.ExecutionPath })
    $headerPairs.Add(@{ Name = 'IgnoredColumns'; Value = (@($header.IgnoredColumns) -join '; ') })
    $headerPairs.Add(@{ Name = 'AuthorizedUseNotice'; Value = $header.AuthorizedUseNotice })
    $headerPairs.Add(@{ Name = 'OriginNote'; Value = $header.OriginNote })
    $headerPairs.Add(@{ Name = 'ProbeCountBasis'; Value = $header.ProbeCountBasis })
    $headerPairs.Add(@{ Name = 'WorstCaseSeconds'; Value = $header.WorstCaseSeconds })

    $sb = [System.Text.StringBuilder]::new()
    foreach ($pair in $headerPairs) {
        [void]$sb.Append((ConvertTo-PPCsvField -Value ('#' + $pair.Name)))
        [void]$sb.Append(',')
        [void]$sb.Append((ConvertTo-PPCsvField -Value (ConvertTo-PPCsvScalarText -Value $pair.Value)))
        [void]$sb.Append("`r`n")
    }

    $fieldNames = @(Get-PPShapeFields -Shape 'ResultRow')
    for ($i = 0; $i -lt $fieldNames.Count; $i++) {
        [void]$sb.Append((ConvertTo-PPCsvField -Value $fieldNames[$i]))
        if ($i -lt $fieldNames.Count - 1) { [void]$sb.Append(',') }
    }
    [void]$sb.Append("`r`n")

    foreach ($row in $rows) {
        if ($null -eq $row) { continue }
        $values = @(
            $row.RunId, $row.Timestamp, $row.SourceName, $row.SourceIp, $row.TargetName, $row.TargetIp,
            (@($row.ResolvedAddresses) -join ';'), $row.Port, $row.Protocol, $row.Service, $row.Required,
            $row.Outcome, $row.State, $row.LatencyMs, $row.Error, $row.ProfileRow, $row.SourceGroup,
            $row.TargetGroup, $row.Notes
        )
        for ($i = 0; $i -lt $values.Count; $i++) {
            [void]$sb.Append((ConvertTo-PPCsvField -Value (ConvertTo-PPCsvScalarText -Value $values[$i])))
            if ($i -lt $values.Count - 1) { [void]$sb.Append(',') }
        }
        [void]$sb.Append("`r`n")
    }

    return $sb.ToString()
}
# ---- src/74-Render.Json.ps1 ----
# PortProof JSON renderer. An own serializer (not ConvertTo-Json,
# whose escaping and layout differ between 5.1 and 7): two-space indent, ": " separator, one
# member/element per line, "[]"/"{}" for empties. Pure: no clock, environment, filesystem,
# randomness or culture dependency. Literal member access only: no computed member
# names - each shape's fields are read one at a time by name, in the normative field order.

function ConvertTo-PPJsonString {
    # A JSON string literal: quote and backslash are escaped; U+0008/U+000C/U+000A/U+000D/U+0009
    # use the short two-character forms; every other C0 control character (U+0000 to U+001F) is a
    # six-character escape (lowercase hex); the angle brackets, ampersand, and the two line and
    # paragraph separator code points also get the six-character escape - they are otherwise legal
    # inside a JSON string, but dangerous if this document is ever read back into an HTML script
    # block or a JS string literal; every other character (including non-ASCII and
    # astral surrogate pairs) is written raw. Every escape is built at runtime from its numeric code
    # point via [string]::Format, never typed as a literal escape sequence in this file's own
    # source, so no text-processing step upstream of the PowerShell parser can decode it first.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowEmptyString()] [AllowNull()] [string] $Text)

    $t = $Text
    if ($null -eq $t) { $t = '' }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $escapePrefix = [string]::Format($inv, '{0}u', [char]0x5C)
    $sb = [System.Text.StringBuilder]::new($t.Length + 2)
    [void]$sb.Append('"')
    $chars = $t.ToCharArray()
    foreach ($ch in $chars) {
        $s = [string]$ch
        $code = [int]$ch
        if ($s -ceq '"') { [void]$sb.Append([string]::Format($inv, '{0}"', [char]0x5C)) }
        elseif ($code -eq 0x5C) { [void]$sb.Append([string]::Format($inv, '{0}{0}', [char]0x5C)) }
        elseif ($code -eq 0x08) { [void]$sb.Append([string]::Format($inv, '{0}b', [char]0x5C)) }
        elseif ($code -eq 0x0C) { [void]$sb.Append([string]::Format($inv, '{0}f', [char]0x5C)) }
        elseif ($code -eq 0x0A) { [void]$sb.Append([string]::Format($inv, '{0}n', [char]0x5C)) }
        elseif ($code -eq 0x0D) { [void]$sb.Append([string]::Format($inv, '{0}r', [char]0x5C)) }
        elseif ($code -eq 0x09) { [void]$sb.Append([string]::Format($inv, '{0}t', [char]0x5C)) }
        elseif ($s -ceq '<' -or $s -ceq '>' -or $s -ceq '&' -or $code -eq 0x2028 -or $code -eq 0x2029) {
            [void]$sb.Append($escapePrefix)
            [void]$sb.Append($code.ToString('x4', $inv))
        }
        elseif ($code -ge 0 -and $code -le 0x1F) {
            [void]$sb.Append($escapePrefix)
            [void]$sb.Append($code.ToString('x4', $inv))
        }
        else {
            [void]$sb.Append($ch)
        }
    }
    [void]$sb.Append('"')
    return $sb.ToString()
}

function ConvertTo-PPJsonScalarText {
    # Value -> its JSON token text: null, true/false, an invariant integer, or a JSON string.
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' }; return 'false' }
    if ($Value -is [int] -or $Value -is [long]) { return $Value.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    return (ConvertTo-PPJsonString -Text ([string]$Value))
}

function ConvertTo-PPJsonArrayText {
    # A JSON array of strings: "[]" when empty, else one quoted element per line at $Level + 1,
    # closing bracket aligned with $Level (the indent of the member line the array value sits on).
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string[]] $Items, [Parameter(Mandatory)] [int] $Level)

    $items = @($Items)
    if ($items.Count -eq 0) { return '[]' }
    $pad = '  ' * $Level
    $childPad = '  ' * ($Level + 1)
    $lines = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $items.Count; $i++) {
        $suffix = ''
        if ($i -lt $items.Count - 1) { $suffix = ',' }
        $lines.Add($childPad + (ConvertTo-PPJsonString -Text ([string]$items[$i])) + $suffix)
    }
    return "[`n" + ($lines -join "`n") + "`n" + $pad + ']'
}

function Format-PPJsonMemberLine {
    # One '"Key": <value text>[,]' line at $Pad, where $ValueText may itself be a multi-line
    # nested object/array block (its own closing bracket is already aligned by the caller).
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Pad,
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] [string] $ValueText,
        [Parameter(Mandatory)] [bool] $IsLast
    )

    $comma = ''
    if (-not $IsLast) { $comma = ',' }
    return $Pad + (ConvertTo-PPJsonString -Text $Key) + ': ' + $ValueText + $comma
}

function ConvertTo-PPJsonFlagsText {
    # PortProof.Flags, nested under RunHeader.Flags.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $Flags, [Parameter(Mandatory)] [int] $Level)

    $pad = '  ' * $Level
    $childPad = '  ' * ($Level + 1)
    $m = [System.Collections.Generic.List[string]]::new()
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'AllowLarge' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.AllowLarge) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'AllowCidr' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.AllowCidr) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Icmp' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.Icmp) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'DryRun' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.DryRun) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'NoOperator' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.NoOperator) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Force' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.Force) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Quiet' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.Quiet) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Ceiling' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.Ceiling) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'EffectiveCap' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.EffectiveCap) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'TimeoutMs' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.TimeoutMs) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Concurrency' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.Concurrency) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'MaxProbesPerSecond' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.MaxProbesPerSecond) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'JitterMs' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.JitterMs) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'GroupOverrides' -ValueText (ConvertTo-PPJsonArrayText -Items ([string[]]@($Flags.GroupOverrides)) -Level ($Level + 1)) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ExecutionPath' -ValueText (ConvertTo-PPJsonScalarText -Value $Flags.ExecutionPath) -IsLast $true))
    return "{`n" + ($m -join "`n") + "`n" + $pad + '}'
}

function ConvertTo-PPJsonHeaderText {
    # PortProof.RunHeader; Flags stays a nested object (unlike the CSV render,
    # which flattens it).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $Header, [Parameter(Mandatory)] [int] $Level)

    $pad = '  ' * $Level
    $childPad = '  ' * ($Level + 1)
    $flagsText = ConvertTo-PPJsonFlagsText -Flags $Header.Flags -Level ($Level + 1)
    $m = [System.Collections.Generic.List[string]]::new()
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ToolVersion' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.ToolVersion) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ProfileName' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.ProfileName) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ProfileVersion' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.ProfileVersion) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ProfileSha256' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.ProfileSha256) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'RunId' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.RunId) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'StartedUtc' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.StartedUtc) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'StartedLocal' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.StartedLocal) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'OperatorUser' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.OperatorUser) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'OperatorHost' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.OperatorHost) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ProbeCount' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.ProbeCount) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Flags' -ValueText $flagsText -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'IgnoredColumns' -ValueText (ConvertTo-PPJsonArrayText -Items ([string[]]@($Header.IgnoredColumns)) -Level ($Level + 1)) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'AuthorizedUseNotice' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.AuthorizedUseNotice) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'OriginNote' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.OriginNote) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ProbeCountBasis' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.ProbeCountBasis) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'WorstCaseSeconds' -ValueText (ConvertTo-PPJsonScalarText -Value $Header.WorstCaseSeconds) -IsLast $true))
    return "{`n" + ($m -join "`n") + "`n" + $pad + '}'
}

function ConvertTo-PPJsonRowText {
    # PortProof.ResultRow, 19 fields in shape order.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $Row, [Parameter(Mandatory)] [int] $Level)

    $pad = '  ' * $Level
    $childPad = '  ' * ($Level + 1)
    $m = [System.Collections.Generic.List[string]]::new()
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'RunId' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.RunId) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Timestamp' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Timestamp) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'SourceName' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.SourceName) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'SourceIp' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.SourceIp) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'TargetName' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.TargetName) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'TargetIp' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.TargetIp) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ResolvedAddresses' -ValueText (ConvertTo-PPJsonArrayText -Items ([string[]]@($Row.ResolvedAddresses)) -Level ($Level + 1)) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Port' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Port) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Protocol' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Protocol) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Service' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Service) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Required' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Required) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Outcome' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Outcome) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'State' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.State) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'LatencyMs' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.LatencyMs) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Error' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Error) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ProfileRow' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.ProfileRow) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'SourceGroup' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.SourceGroup) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'TargetGroup' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.TargetGroup) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Notes' -ValueText (ConvertTo-PPJsonScalarText -Value $Row.Notes) -IsLast $true))
    return "{`n" + ($m -join "`n") + "`n" + $pad + '}'
}

function ConvertTo-PPJsonSummaryText {
    # PortProof.Summary, 8 integer fields.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $Summary, [Parameter(Mandatory)] [int] $Level)

    $pad = '  ' * $Level
    $childPad = '  ' * ($Level + 1)
    $m = [System.Collections.Generic.List[string]]::new()
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Total' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.Total) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Pass' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.Pass) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Fail' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.Fail) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'Inconclusive' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.Inconclusive) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'RequiredTotal' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.RequiredTotal) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'RequiredNotPassed' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.RequiredNotPassed) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ExitCode' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.ExitCode) -IsLast $false))
    $m.Add((Format-PPJsonMemberLine -Pad $childPad -Key 'ElapsedMs' -ValueText (ConvertTo-PPJsonScalarText -Value $Summary.ElapsedMs) -IsLast $true))
    return "{`n" + ($m -join "`n") + "`n" + $pad + '}'
}

function ConvertTo-PPJson {
    # { schema, header, results, summary }. Two-space indent; one trailing newline.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [pscustomobject] $ResultSet)

    $contract = Get-PPContract
    $header = $ResultSet.Header
    $rows = @($ResultSet.Rows)
    $summary = $ResultSet.Summary

    $headerText = ConvertTo-PPJsonHeaderText -Header $header -Level 1
    $summaryText = ConvertTo-PPJsonSummaryText -Summary $summary -Level 1

    $rowTexts = [System.Collections.Generic.List[string]]::new()
    foreach ($row in $rows) { if ($null -ne $row) { $rowTexts.Add((ConvertTo-PPJsonRowText -Row $row -Level 2)) } }

    $resultsText = '[]'
    if ($rowTexts.Count -gt 0) {
        $childPad = '  ' * 2
        $lines = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $rowTexts.Count; $i++) {
            $suffix = ''
            if ($i -lt $rowTexts.Count - 1) { $suffix = ',' }
            $lines.Add($childPad + $rowTexts[$i] + $suffix)
        }
        $resultsText = "[`n" + ($lines -join "`n") + "`n" + ('  ' * 1) + ']'
    }

    $top = [System.Collections.Generic.List[string]]::new()
    $top.Add((Format-PPJsonMemberLine -Pad '  ' -Key 'schema' -ValueText (ConvertTo-PPJsonScalarText -Value ([string]$contract.ResultSchemaId)) -IsLast $false))
    $top.Add((Format-PPJsonMemberLine -Pad '  ' -Key 'header' -ValueText $headerText -IsLast $false))
    $top.Add((Format-PPJsonMemberLine -Pad '  ' -Key 'results' -ValueText $resultsText -IsLast $false))
    $top.Add((Format-PPJsonMemberLine -Pad '  ' -Key 'summary' -ValueText $summaryText -IsLast $true))

    return "{`n" + ($top -join "`n") + "`n}`n"
}
# ---- src/90-Main.ps1 ----
# PortProof entry point: argument checks, orchestration, run header, DryRun report, output files,
# summary and exit code. Function definitions, then the guarded
# entry block, which is the last statement of the built script.

function Assert-Arguments {
    # Checks run in table order; the first failure throws PortProof.Argument.* /
    # PortProof.Output.NeedsOut (exit 2). Returns PortProof.RunOptions.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Name kept fixed on purpose; other functions call it by this exact name.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [hashtable] $Raw, [Parameter(Mandatory)] [hashtable] $Contract)

    $inv = [cultureinfo]::InvariantCulture

    # 1. -Profile present.
    $profilePath = [string]$Raw['ProfilePath']
    if ([string]::IsNullOrWhiteSpace($profilePath)) {
        Invoke-PPRefusal -Code 'Argument.Missing' -Message ('-Profile is required. Usage: PortProof.ps1 -Profile <profile.csv|profile.json> ' +
            "[-Set 'NAME=VALUE;NAME=VALUE'] [-Out <directory>] [-Format Html,Csv,Json] [-DryRun]")
    }

    # 2. Extension.
    if ($profilePath -cnotmatch '\.([Cc][Ss][Vv]|[Jj][Ss][Oo][Nn])\z') {
        Invoke-PPRefusal -Code 'Argument.Set' -Message ("-Profile '{0}' must be a .csv or .json file." -f (Get-PPSafeText -Text $profilePath))
    }

    # 3. Format: comma lists, trimmed, closed set, duplicates collapse, canonical casing and order.
    $formatGiven = $false
    $requested = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    if ($null -ne $Raw['Format']) {
        foreach ($element in @($Raw['Format'])) {
            $formatGiven = $true
            foreach ($piece in ([string]$element).Split(',')) {
                $value = $piece.Trim()
                $match = $null
                foreach ($known in $Contract.Formats) {
                    if ($value -cmatch '\A[A-Za-z]+\z' -and [string]::Equals($value.ToLowerInvariant(), $known.ToLowerInvariant(), [System.StringComparison]::Ordinal)) { $match = $known }
                }
                if ($null -eq $match) {
                    Invoke-PPRefusal -Code 'Argument.Set' -Message ("-Format '{0}' is not one of Html, Csv, Json." -f (Get-PPSafeText -Text $value))
                }
                $requested[$match] = $true
            }
        }
    }
    $formats = [string[]]@($Contract.Formats | Where-Object { $requested.ContainsKey($_) })

    # 4. Ranges.
    $units = @{ Timeout = 'ms'; Concurrency = 'targets in flight'; MaxProbesPerSecond = 'probes per second'; Jitter = 'ms' }
    $values = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($name in @('Timeout', 'Concurrency', 'MaxProbesPerSecond', 'Jitter')) {
        $value = $Raw[$name]
        if ($null -eq $value) { $value = $Contract.Defaults[$name] }
        $value = [int]$value
        $lo = $Contract.Ranges[$name][0]
        $hi = $Contract.Ranges[$name][1]
        if ($value -lt $lo -or $value -gt $hi) {
            Invoke-PPRefusal -Code 'Argument.Range' -Message ('-{0} {1} is out of range; permitted {2}..{3} ({4}).' -f $name,
                $value.ToString($inv), $lo.ToString($inv), $hi.ToString($inv), $units[$name])
        }
        $values[$name] = $value
    }

    # 5. Ceiling and -MaxProbes.
    $allowLarge = [bool]$Raw['AllowLarge']
    $absolute = [int]$Contract.AbsoluteProbeCeiling
    $ceiling = if ($allowLarge) { $absolute } else { [int]$Contract.DefaultCeiling }
    $effectiveCap = $ceiling
    if ([bool]$Raw['MaxProbesGiven']) {
        $maxProbes = [int]$Raw['MaxProbes']
        if ($maxProbes -gt $absolute) {
            Invoke-PPRefusal -Code 'Argument.Cap' -Message ('-MaxProbes {0} exceeds the ceiling in force ({1}); no parameter raises it.' -f
                $maxProbes.ToString($inv), $absolute.ToString($inv))
        }
        if ($maxProbes -gt $ceiling) {
            Invoke-PPRefusal -Code 'Argument.Cap' -Message ('-MaxProbes {0} exceeds the ceiling in force ({1}); -AllowLarge raises the ceiling to {2}.' -f
                $maxProbes.ToString($inv), $ceiling.ToString($inv), $absolute.ToString($inv))
        }
        if ($maxProbes -lt 1) {
            Invoke-PPRefusal -Code 'Argument.Cap' -Message ('-MaxProbes {0} is out of range; permitted 1..{1}.' -f
                $maxProbes.ToString($inv), $ceiling.ToString($inv))
        }
        $effectiveCap = $maxProbes
    }

    # 6. -Set syntax (the value grammar belongs to the Expander).
    $bindings = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    if ($null -ne $Raw['Set']) {
        foreach ($element in @($Raw['Set'])) {
            foreach ($piece in ([string]$element).Split(';')) {
                if ($piece.Length -eq 0) { continue }
                if ($piece -cnotmatch '\A[A-Za-z][A-Za-z0-9_]{0,31}=.+\z') {
                    Invoke-PPRefusal -Code 'Argument.SetSyntax' -Message ("-Set '{0}' is not NAME=VALUE." -f (Get-PPSafeText -Text $piece))
                }
                $bindingName = $piece.Substring(0, $piece.IndexOf('=')).ToUpperInvariant()
                if ($seen.ContainsKey($bindingName)) {
                    Invoke-PPRefusal -Code 'Argument.SetSyntax' -Message ('-Set binds {0} twice.' -f $bindingName)
                }
                $seen[$bindingName] = $true
                $bindings.Add($piece)
            }
        }
    }

    # 7. Output combination (not under -DryRun, which writes nothing).
    # OutGiven comes from $PSBoundParameters in the entry block, so -Out '' / -Out "" (both entry
    # paths bind an empty string, measured on 5.1) is "given but empty" and hits row 8. In-process
    # callers without the key fall back to "non-empty means given".
    $outRaw = [string]$Raw['Out']
    if ($Raw.ContainsKey('OutGiven')) { $outGiven = [bool]$Raw['OutGiven'] } else { $outGiven = -not [string]::IsNullOrEmpty($outRaw) }
    $dryRun = [bool]$Raw['DryRun']
    if (-not $dryRun -and -not $outGiven -and $formatGiven -and ($formats -ccontains 'Html' -or $formats.Count -gt 1)) {
        Invoke-PPRefusal -Code 'Output.NeedsOut' -Message 'Html and multi-format output need -Out.'
    }

    # 8. -Out given but blank.
    if ($outGiven -and [string]::IsNullOrWhiteSpace($outRaw)) {
        Invoke-PPRefusal -Code 'Argument.Missing' -Message '-Out is empty.'
    }

    if ($outGiven) {
        if (-not $formatGiven) { $formats = [string[]]@($Contract.Formats) }
        $emit = 'Files'
        $outValue = $outRaw
    }
    else {
        $outValue = $null
        if ($formats.Count -eq 1 -and ($formats[0] -ceq 'Csv' -or $formats[0] -ceq 'Json')) { $emit = 'Stream' } else { $emit = 'None' }
    }

    [pscustomobject][ordered]@{
        PSTypeName         = 'PortProof.RunOptions'
        ProfilePath        = $profilePath
        Bindings           = [string[]]$bindings.ToArray()
        Out                = $outValue
        Formats            = $formats
        Emit               = $emit
        TimeoutMs          = $values['Timeout']
        Concurrency        = $values['Concurrency']
        MaxProbesPerSecond = $values['MaxProbesPerSecond']
        JitterMs           = $values['Jitter']
        Ceiling            = $ceiling
        EffectiveCap       = $effectiveCap
        AllowLarge         = $allowLarge
        AllowCidr          = [bool]$Raw['AllowCidr']
        Icmp               = [bool]$Raw['Icmp']
        DryRun             = $dryRun
        NoOperator         = [bool]$Raw['NoOperator']
        Force              = [bool]$Raw['Force']
        Quiet              = [bool]$Raw['Quiet']
    }
}

function Select-PPResolver {
    # -DryRun always gets the refusing stub, whatever -Live is.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([bool] $DryRun, [pscustomobject] $Live)

    if ($DryRun) { return Get-PPRefusingResolver }
    return $Live
}

function Write-PPInfoLine {
    # One line to the information stream, forced on, tagged; text passed through Get-PPSafeText.
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $Line, [Parameter(Mandatory)] [string] $Tag)

    Write-Information -MessageData (Get-PPSafeText -Text $Line -Max 4096) -InformationAction Continue -Tags $Tag
}

function Write-PPNotice {
    # The three authorized-use lines, information stream, tag PortProof.Notice.
    [CmdletBinding()]
    param()

    foreach ($line in (Get-PPAuthorizedUseNotice)) {
        Write-PPInfoLine -Line $line -Tag 'PortProof.Notice'
    }
}

function Resolve-PPFileSystemPath {
    # Resolves like the current PowerShell
    # location does (wildcards literal); a missing drive, an unknown provider or a non-FileSystem
    # provider is refused with $Code.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Code, [Parameter(Mandatory)] [string] $What)

    $provider = $null
    $drive = $null
    $full = $null
    $failure = $null
    try {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    }
    catch {
        $failure = $_.Exception.GetType().Name
    }
    if ($null -ne $failure) {
        Invoke-PPRefusal -Code $Code -Message ("{0} '{1}' cannot be resolved to a file-system path (drive or provider not found)." -f $What, (Get-PPSafeText -Text $Path))
    }
    if ($null -eq $provider -or $provider.Name -cne 'FileSystem') {
        Invoke-PPRefusal -Code $Code -Message ("{0} '{1}' is not a file-system path." -f $What, (Get-PPSafeText -Text $Path))
    }
    return $full
}

function Measure-PPWorstCase {
    # Upper-bound estimate in whole seconds. Probes carry Target (pre-resolution)
    # or TargetIp (ExecProbe); ICMP is one extra probe per target.
    [CmdletBinding()]
    [OutputType([long])]
    param([AllowEmptyCollection()] [object[]] $Probes, [int] $IcmpTargets, $Options)

    $perProbeMs = [double]($Options.TimeoutMs + $Options.JitterMs)
    $counts = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $hostnames = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($probe in @($Probes)) {
        if ($null -eq $probe) { continue }
        $key = [string]$probe.Target
        if ($key.Length -eq 0) { $key = [string]$probe.TargetIp }
        if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
        if ([string]$probe.TargetKind -ceq 'Hostname') { $hostnames[$key] = $true }
    }
    $n = 0
    $sum = 0.0
    $max = 0.0
    foreach ($key in @($counts.Keys)) {
        $nt = $counts[$key]
        if ($IcmpTargets -gt 0) { $nt++ }
        $w = $nt * $perProbeMs
        $n += $nt
        $sum += $w
        if ($w -gt $max) { $max = $w }
    }
    $d = [double]$hostnames.Count * [double](Get-PPContract).ResolveTimeoutMs
    $rateMs = [double]$n * 1000.0 / [double]$Options.MaxProbesPerSecond
    $poolMs = ($sum / [double]$Options.Concurrency) + $max
    $totalMs = $d + [Math]::Max($rateMs, $poolMs)
    return [long][Math]::Ceiling($totalMs / 1000.0)
}

function ConvertTo-PPDuration {
    # Seconds -> hh:mm:ss (hours may exceed 24), invariant culture.
    [CmdletBinding()]
    [OutputType([string])]
    param([long] $Seconds)

    $h = [long][Math]::Floor($Seconds / 3600)
    $m = [long][Math]::Floor(($Seconds % 3600) / 60)
    $s = $Seconds % 60
    [string]::Format([cultureinfo]::InvariantCulture, '{0:00}:{1:00}:{2:00}', $h, $m, $s)
}

function Get-PPRunHeader {
    # PortProof.RunHeader, field order normative.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param($Options, $ProfileDocument, $Expansion, [int] $ProbeCount, [string] $Basis, [string] $ExecutionPath,
        [datetime] $StartedUtc, [string] $RunId, [long] $WorstCaseSeconds = 0)

    $contract = Get-PPContract
    $inv = [cultureinfo]::InvariantCulture
    if ($Options.NoOperator) {
        $user = 'redacted'
        $hostName = 'redacted'
    }
    else {
        $user = [Environment]::UserDomainName + '\' + [Environment]::UserName
        $hostName = [Environment]::MachineName
    }
    $utc = [datetime]::SpecifyKind($StartedUtc, [DateTimeKind]::Utc)
    # Under -NoOperator the local UTC offset is a location hint, so
    # StartedLocal takes the StartedUtc form ('Z').
    if ($Options.NoOperator) {
        $startedLocal = $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)
    }
    else {
        $startedLocal = $utc.ToLocalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffzzz', $inv)
    }
    $overrides = @()
    if ($null -ne $Expansion -and $null -ne $Expansion.GroupOverrides) { $overrides = @($Expansion.GroupOverrides) }
    $flags = [pscustomobject][ordered]@{
        PSTypeName         = 'PortProof.Flags'
        AllowLarge         = [bool]$Options.AllowLarge
        AllowCidr          = [bool]$Options.AllowCidr
        Icmp               = [bool]$Options.Icmp
        DryRun             = [bool]$Options.DryRun
        NoOperator         = [bool]$Options.NoOperator
        Force              = [bool]$Options.Force
        Quiet              = [bool]$Options.Quiet
        Ceiling            = [int]$Options.Ceiling
        EffectiveCap       = [int]$Options.EffectiveCap
        TimeoutMs          = [int]$Options.TimeoutMs
        Concurrency        = [int]$Options.Concurrency
        MaxProbesPerSecond = [int]$Options.MaxProbesPerSecond
        JitterMs           = [int]$Options.JitterMs
        GroupOverrides     = [string[]]$overrides
        ExecutionPath      = $ExecutionPath
    }
    $ignored = @()
    if ($null -ne $ProfileDocument.IgnoredColumns) { $ignored = @($ProfileDocument.IgnoredColumns) }
    [pscustomobject][ordered]@{
        PSTypeName          = 'PortProof.RunHeader'
        ToolVersion         = $contract.ToolVersion
        ProfileName         = [string]$ProfileDocument.Name
        ProfileVersion      = [string]$ProfileDocument.Version
        ProfileSha256       = [string]$ProfileDocument.Sha256
        RunId               = $RunId
        StartedUtc          = $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)
        StartedLocal        = $startedLocal
        OperatorUser        = $user
        OperatorHost        = $hostName
        ProbeCount          = $ProbeCount
        Flags               = $flags
        IgnoredColumns      = [string[]]$ignored
        AuthorizedUseNotice = ((Get-PPAuthorizedUseNotice) -join ' ')
        OriginNote          = [string]::Format($inv, $contract.OriginNoteFormat, $hostName)
        ProbeCountBasis     = $Basis
        WorstCaseSeconds    = $WorstCaseSeconds
    }
}

function ConvertTo-PPInfoValue {
    # Header value -> one line of text: arrays joined with '; ', booleans lowercase, invariant numbers.
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [array]) { return ((@($Value) | ForEach-Object { ConvertTo-PPInfoValue -Value $_ }) -join '; ') }
    if ($Value -is [System.IFormattable]) { return $Value.ToString($null, [cultureinfo]::InvariantCulture) }
    return [string]$Value
}

function Write-PPRunHeader {
    # Information stream, tag PortProof.Header; one "Field: value" line per field, Flags flattened.
    [CmdletBinding()]
    param($Header)

    # Literal member access only: no computed member names. The order is the
    # RunHeader and Flags field order of Get-PPShapeFields; Contract.Tests asserts they agree.
    $flags = $Header.Flags
    $pairs = @(
        @{ Name = 'ToolVersion'; Value = $Header.ToolVersion }
        @{ Name = 'ProfileName'; Value = $Header.ProfileName }
        @{ Name = 'ProfileVersion'; Value = $Header.ProfileVersion }
        @{ Name = 'ProfileSha256'; Value = $Header.ProfileSha256 }
        @{ Name = 'RunId'; Value = $Header.RunId }
        @{ Name = 'StartedUtc'; Value = $Header.StartedUtc }
        @{ Name = 'StartedLocal'; Value = $Header.StartedLocal }
        @{ Name = 'OperatorUser'; Value = $Header.OperatorUser }
        @{ Name = 'OperatorHost'; Value = $Header.OperatorHost }
        @{ Name = 'ProbeCount'; Value = $Header.ProbeCount }
        @{ Name = 'Flags.AllowLarge'; Value = $flags.AllowLarge }
        @{ Name = 'Flags.AllowCidr'; Value = $flags.AllowCidr }
        @{ Name = 'Flags.Icmp'; Value = $flags.Icmp }
        @{ Name = 'Flags.DryRun'; Value = $flags.DryRun }
        @{ Name = 'Flags.NoOperator'; Value = $flags.NoOperator }
        @{ Name = 'Flags.Force'; Value = $flags.Force }
        @{ Name = 'Flags.Quiet'; Value = $flags.Quiet }
        @{ Name = 'Flags.Ceiling'; Value = $flags.Ceiling }
        @{ Name = 'Flags.EffectiveCap'; Value = $flags.EffectiveCap }
        @{ Name = 'Flags.TimeoutMs'; Value = $flags.TimeoutMs }
        @{ Name = 'Flags.Concurrency'; Value = $flags.Concurrency }
        @{ Name = 'Flags.MaxProbesPerSecond'; Value = $flags.MaxProbesPerSecond }
        @{ Name = 'Flags.JitterMs'; Value = $flags.JitterMs }
        @{ Name = 'Flags.GroupOverrides'; Value = $flags.GroupOverrides }
        @{ Name = 'Flags.ExecutionPath'; Value = $flags.ExecutionPath }
        @{ Name = 'IgnoredColumns'; Value = $Header.IgnoredColumns }
        @{ Name = 'AuthorizedUseNotice'; Value = $Header.AuthorizedUseNotice }
        @{ Name = 'OriginNote'; Value = $Header.OriginNote }
        @{ Name = 'ProbeCountBasis'; Value = $Header.ProbeCountBasis }
        @{ Name = 'WorstCaseSeconds'; Value = $Header.WorstCaseSeconds }
    )
    foreach ($pair in $pairs) {
        Write-PPInfoLine -Line ('{0}: {1}' -f $pair.Name, (ConvertTo-PPInfoValue -Value $pair.Value)) -Tag 'PortProof.Header'
    }
}

function Write-PPDryRunReport {
    # Header block, one line per ExpandedRow, then the counts and estimates.
    [CmdletBinding()]
    param($Options, $ProfileDocument, $Expansion, $Header)

    $inv = [cultureinfo]::InvariantCulture
    $tag = 'PortProof.DryRun'
    Write-PPRunHeader -Header $Header
    Write-PPInfoLine -Line ("dry run of profile '{0}' ({1}); nothing is resolved or sent" -f (Get-PPSafeText -Text ([string]$ProfileDocument.Name)),
        (Get-PPSafeText -Text ([string]$ProfileDocument.FileName))) -Tag $tag

    $probeByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($probe in @($Expansion.Probes)) { if ($null -ne $probe) { $probeByKey[[string]$probe.ProbeKey] = $probe } }
    foreach ($row in @($Expansion.Rows)) {
        if ($null -eq $row) { continue }
        $probe = $probeByKey[[string]$row.ProbeKey]
        $where = 'unresolved (dry-run)'
        if ($null -ne $probe -and $null -ne $probe.Address) {
            $where = (ConvertTo-CanonicalAddress -Address $probe.Address).ToString()
        }
        $line = 'row {0}  {1} -> {2}  {3}/{4}  {5}  {6}' -f ([int]$row.Row).ToString($inv), (Get-PPSafeText -Text ([string]$row.SourceName)),
            (Get-PPSafeText -Text ([string]$row.TargetName)), $row.Protocol, ([int]$row.Port).ToString($inv), $row.Required, $where
        Write-PPInfoLine -Line $line -Tag $tag
    }

    $nPre = @($Expansion.Probes | Where-Object { $null -ne $_ }).Count
    Write-PPInfoLine -Line ('probes {0} (one connection attempt each; name coalescing may lower this on a live run)' -f $nPre.ToString($inv)) -Tag $tag
    $icmp = 0
    if ($Options.Icmp) {
        $icmp = [int]$Expansion.DistinctTargets
        Write-PPInfoLine -Line ('icmp echoes {0} (upper bound)' -f $icmp.ToString($inv)) -Tag $tag
    }
    $names = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($probe in @($Expansion.Probes)) { if ($null -ne $probe -and $probe.TargetKind -ceq 'Hostname') { $names[[string]$probe.Target] = $true } }
    $resolveMs = [long](Get-PPContract).ResolveTimeoutMs
    $resolveSeconds = [long][Math]::Ceiling(($names.Count * $resolveMs) / 1000.0)
    Write-PPInfoLine -Line ('name resolution up to {0} ({1} names x {2} ms, included below)' -f (ConvertTo-PPDuration -Seconds $resolveSeconds),
        $names.Count.ToString($inv), $resolveMs.ToString($inv)) -Tag $tag
    Write-PPInfoLine -Line ('worst-case duration {0} (estimate)' -f (ConvertTo-PPDuration -Seconds ([long]$Header.WorstCaseSeconds))) -Tag $tag
    Write-PPInfoLine -Line 'names are class-checked on the live run, not here' -Tag $tag
}

function Test-PPReparsePoint {
    # True when $Path exists as a reparse point (symlink or junction, dangling or not). The
    # attributes are those of the link itself; nothing is followed.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)

    # No exception on the normal path: a caught .NET exception still lands in a caller's
    # -ErrorVariable. The entry is looked up in its parent directory listing (which does not
    # follow links, so a dangling link is found); then File.GetAttributes reads the entry's own
    # attributes (0x400 = FileAttributes.ReparsePoint).
    $trimmed = $Path.TrimEnd([char]'\', [char]'/')
    if ($trimmed.Length -eq 0) { return $false }
    $parent = [System.IO.Path]::GetDirectoryName($trimmed)
    $leaf = [System.IO.Path]::GetFileName($trimmed)
    if ([string]::IsNullOrEmpty($parent) -or [string]::IsNullOrEmpty($leaf)) { return $false }
    if (-not [System.IO.Directory]::Exists($parent)) { return $false }
    if (@([System.IO.Directory]::GetFileSystemEntries($parent, $leaf)).Count -eq 0) { return $false }
    $attributes = [int][System.IO.File]::GetAttributes($trimmed)
    return (($attributes -band 0x400) -ne 0)
}

function Assert-PPNoReparsePoint {
    # A symlink or junction planted in -Out would redirect the write.
    # Refuses -Out itself or an output path that is a reparse point; writes nothing.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $What)

    if (Test-PPReparsePoint -Path $Path) {
        Invoke-PPRefusal -Code 'Output.ReparsePoint' -Message ("{0} '{1}' is a symbolic link or junction; PortProof does not write through reparse points. Remove it or choose another -Out." -f
            $What, (Get-PPSafeText -Text $Path))
    }
}

function Test-PPOutputPreflight {
    # Creates nothing. Returns the resolved directory and file paths.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param($Options)

    $contract = Get-PPContract
    $directory = Resolve-PPFileSystemPath -Path $Options.Out -Code 'Output.NotDirectory' -What '-Out'
    Assert-PPNoReparsePoint -Path $directory -What '-Out'
    if ([System.IO.File]::Exists($directory)) {
        Invoke-PPRefusal -Code 'Output.NotDirectory' -Message ("-Out '{0}' exists and is not a directory." -f (Get-PPSafeText -Text $directory))
    }
    $files = [ordered]@{}
    foreach ($format in @($Options.Formats)) {
        $path = [System.IO.Path]::Combine($directory, $contract.OutputFileNames[$format])
        Assert-PPNoReparsePoint -Path $path -What 'output file'
        if ([System.IO.Directory]::Exists($path)) {
            Invoke-PPRefusal -Code 'Output.Collision' -Message ("'{0}' exists as a directory; remove it or choose another -Out." -f (Get-PPSafeText -Text $path))
        }
        if ([System.IO.File]::Exists($path) -and -not $Options.Force) {
            Invoke-PPRefusal -Code 'Output.Collision' -Message ("'{0}' already exists; use -Force to overwrite it or choose another -Out." -f (Get-PPSafeText -Text $path))
        }
        $files[$format] = $path
    }
    [pscustomobject][ordered]@{ PSTypeName = 'PortProof.OutputPlan'; Directory = $directory; Files = $files }
}

function Write-PPOutputFile {
    # UTF-8, BOM only when asked (CSV). CreateNew unless -Force.
    [CmdletBinding()]
    param([string] $Path, [string] $Text, [bool] $Bom, [bool] $Force)

    # Re-checked here, immediately before the open, for the file and its parent (-Out).
    Assert-PPNoReparsePoint -Path ([System.IO.Path]::GetDirectoryName($Path)) -What '-Out'
    Assert-PPNoReparsePoint -Path $Path -What 'output file'
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $body = $encoding.GetBytes($Text)
    $mode = if ($Force) { [System.IO.FileMode]::Create } else { [System.IO.FileMode]::CreateNew }
    $stream = [System.IO.File]::Open($Path, $mode, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        if ($Bom) { $stream.Write([byte[]](0xEF, 0xBB, 0xBF), 0, 3) }
        $stream.Write($body, 0, $body.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function Join-PPResults {
    # ProbeResult -> ResultRow. One row per ExpandedRow; DnsFailure entries become
    # rows with State '' and Error 'DnsFailure'; ICMP rows last. Rows are never dropped.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Name kept fixed on purpose; other functions call it by this exact name.')]
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param($Expansion, $Resolution, $GateResult, [string] $RunId, [string] $ResolvedTimestamp = '')

    $byExecKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($result in @($GateResult.Results)) { if ($null -ne $result) { $byExecKey[[string]$result.ExecKey] = $result } }

    $rows = [System.Collections.Generic.List[object]]::new()
    $firstNameByIp = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($row in @($Expansion.Rows)) {
        if ($null -eq $row) { continue }
        $entry = $Resolution.Entries[[string]$row.ProbeKey]
        $targetIp = ''
        $resolved = [string[]]@()
        $state = ''
        $errorName = 'ProbeError'
        $latency = $null
        $timestamp = $ResolvedTimestamp
        if ($null -ne $entry -and $entry.Failed) {
            $errorName = 'DnsFailure'
        }
        elseif ($null -ne $entry -and $null -ne $entry.TargetIp) {
            $targetIp = $entry.TargetIp.ToString()
            $resolved = [string[]]@($entry.ResolvedAddresses)
            if (-not $firstNameByIp.ContainsKey($targetIp)) { $firstNameByIp[$targetIp] = [string]$row.TargetName }
            $execKey = '{0}|{1}|{2}' -f $targetIp, ([int]$row.Port).ToString([cultureinfo]::InvariantCulture), $row.Protocol
            $result = $byExecKey[$execKey]
            if ($null -ne $result) {
                $state = [string]$result.State
                $errorName = [string]$result.ErrorName
                $latency = $result.LatencyMs
                $timestamp = [string]$result.Timestamp
            }
        }
        $rows.Add([pscustomobject][ordered]@{
                PSTypeName        = 'PortProof.ResultRow'
                RunId             = $RunId
                Timestamp         = $timestamp
                SourceName        = [string]$row.SourceName
                SourceIp          = [string]$row.SourceIp
                TargetName        = [string]$row.TargetName
                TargetIp          = $targetIp
                ResolvedAddresses = $resolved
                Port              = [int]$row.Port
                Protocol          = [string]$row.Protocol
                Service           = [string]$row.Service
                Required          = [string]$row.Required
                Outcome           = (Get-PPOutcome -Protocol ([string]$row.Protocol) -State $state -ErrorName $errorName)
                State             = $state
                LatencyMs         = $latency
                Error             = $errorName
                ProfileRow        = [int]$row.Row
                SourceGroup       = [string]$row.SourceGroup
                TargetGroup       = [string]$row.TargetGroup
                Notes             = [string]$row.Notes
            })
    }

    $icmpRows = [System.Collections.Generic.List[object]]::new()
    foreach ($result in @($GateResult.Results)) {
        if ($null -eq $result -or $result.Protocol -cne 'ICMP') { continue }
        $ip = [string]$result.TargetIp
        $icmpRows.Add([pscustomobject][ordered]@{
                PSTypeName        = 'PortProof.ResultRow'
                RunId             = $RunId
                Timestamp         = [string]$result.Timestamp
                SourceName        = '(operator host)'
                SourceIp          = ''
                TargetName        = [string]$firstNameByIp[$ip]
                TargetIp          = $ip
                ResolvedAddresses = [string[]]@($ip)
                Port              = 0
                Protocol          = 'ICMP'
                Service           = 'ICMP echo'
                Required          = 'no'
                Outcome           = [string]$result.Outcome
                State             = [string]$result.State
                LatencyMs         = $result.LatencyMs
                Error             = [string]$result.ErrorName
                ProfileRow        = 0
                SourceGroup       = ''
                TargetGroup       = ''
                Notes             = ''
            })
    }

    $rows.Sort([System.Comparison[object]] {
            param($a, $b)
            $c = $a.ProfileRow.CompareTo($b.ProfileRow)
            if ($c -eq 0) { $c = [string]::CompareOrdinal($a.SourceName, $b.SourceName) }
            if ($c -eq 0) { $c = [string]::CompareOrdinal($a.TargetName, $b.TargetName) }
            if ($c -eq 0) { $c = $a.Port.CompareTo($b.Port) }
            if ($c -eq 0) { $c = [string]::CompareOrdinal($a.Protocol, $b.Protocol) }
            return $c
        })
    $icmpRows.Sort([System.Comparison[object]] { param($a, $b) [string]::CompareOrdinal($a.TargetIp, $b.TargetIp) })
    $all = [System.Collections.Generic.List[object]]::new()
    $all.AddRange($rows)
    $all.AddRange($icmpRows)
    return , $all.ToArray()
}

function Get-PPSummary {
    # PortProof.Summary from the result rows.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()] [object[]] $Rows, [long] $ElapsedMs)

    $pass = 0; $fail = 0; $inconclusive = 0; $requiredTotal = 0; $requiredNotPassed = 0
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        switch -CaseSensitive ($row.Outcome) {
            'Pass' { $pass++ }
            'Fail' { $fail++ }
            default { $inconclusive++ }
        }
        if ($row.Required -ceq 'yes') {
            $requiredTotal++
            if ($row.Outcome -cne 'Pass') { $requiredNotPassed++ }
        }
    }
    [pscustomobject][ordered]@{
        PSTypeName        = 'PortProof.Summary'
        Total             = @($Rows | Where-Object { $null -ne $_ }).Count
        Pass              = $pass
        Fail              = $fail
        Inconclusive      = $inconclusive
        RequiredTotal     = $requiredTotal
        RequiredNotPassed = $requiredNotPassed
        ExitCode          = (Get-PPExitCode -Rows @($Rows | Where-Object { $null -ne $_ }))
        ElapsedMs         = $ElapsedMs
    }
}

function Write-PPSummary {
    # Information stream, tag PortProof.Summary. Profile-derived text through Get-PPSafeText.
    [CmdletBinding()]
    param($ResultSet)

    $inv = [cultureinfo]::InvariantCulture
    $tag = 'PortProof.Summary'
    $s = $ResultSet.Summary
    Write-PPInfoLine -Line ('total {0}  pass {1}  fail {2}  inconclusive {3}' -f $s.Total.ToString($inv), $s.Pass.ToString($inv),
        $s.Fail.ToString($inv), $s.Inconclusive.ToString($inv)) -Tag $tag
    Write-PPInfoLine -Line ('required {0}  required not passed {1}' -f $s.RequiredTotal.ToString($inv), $s.RequiredNotPassed.ToString($inv)) -Tag $tag
    foreach ($row in @($ResultSet.Rows)) {
        if ($null -eq $row -or $row.Required -cne 'yes' -or $row.Outcome -ceq 'Pass') { continue }
        $line = 'not passed: row {0}  {1} -> {2}  {3}/{4}  {5}  {6}  {7}' -f ([int]$row.ProfileRow).ToString($inv),
            (Get-PPSafeText -Text $row.SourceName), (Get-PPSafeText -Text $row.TargetName), $row.Protocol,
            ([int]$row.Port).ToString($inv), $row.Outcome, $row.State, $row.Error
        Write-PPInfoLine -Line $line -Tag $tag
    }
    Write-PPInfoLine -Line ('exit code {0}' -f $s.ExitCode.ToString($inv)) -Tag $tag
}

function Invoke-PortProof {
    # Success output flows uncaptured; the exit code travels through [ref].
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Raw,
        [Parameter(Mandatory)] [ref] $ExitCode,
        [pscustomobject] $LiveResolver,
        [hashtable] $Adapters,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
    )

    $ErrorActionPreference = 'Stop'
    $ExitCode.Value = 2
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $quiet = [bool]$Raw['Quiet']
    try {
        $contract = Get-PPContract

        # 1. -Version: nothing else runs, nothing on the information stream.
        if ([bool]$Raw['Version']) {
            Write-Output $contract.ToolVersion
            $ExitCode.Value = 0
            return
        }

        # 2-4.
        $options = Assert-Arguments -Raw $Raw -Contract $contract
        Write-PPNotice
        if ($null -eq $LiveResolver -and -not $options.DryRun) { $LiveResolver = Get-PPDnsResolver -TimeoutMs $contract.ResolveTimeoutMs }
        $resolver = Select-PPResolver -DryRun $options.DryRun -Live $LiveResolver
        if ($null -eq $Adapters) { $Adapters = $contract.DefaultAdapters }

        # 5. Profile path (FileSystem only), then the parser.
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Status 'Reading the profile' }
        $profileFull = Resolve-PPFileSystemPath -Path $options.ProfilePath -Code 'Profile.NotFound' -What 'profile'
        if (-not [System.IO.File]::Exists($profileFull)) {
            Invoke-PPRefusal -Code 'Profile.NotFound' -Message ("profile '{0}' was not found." -f (Get-PPSafeText -Text $options.ProfilePath))
        }
        $profileDocument = Import-PPProfile -Path $profileFull -Contract $contract

        # 6. Expansion and the pre-resolution early exit (all three parameters together).
        # The pass-1 expansion limit follows the run's effective cap.
        $expansion = Expand-PPProfile -ProfileDocument $profileDocument -Bindings $options.Bindings -AllowCidr:$options.AllowCidr `
            -EffectiveCap $options.EffectiveCap -Contract $contract
        $nPre = @($expansion.Probes | Where-Object { $null -ne $_ }).Count
        Assert-PPPreResolutionCount -Count $nPre -Cap $options.EffectiveCap -Ceiling $options.Ceiling

        $startedUtc = [datetime]::UtcNow
        $runId = [guid]::NewGuid().ToString()

        # 7. -DryRun: report and return. Nothing after this block runs under -DryRun.
        if ($options.DryRun) {
            $icmpTargets = 0
            if ($options.Icmp) { $icmpTargets = [int]$expansion.DistinctTargets }
            $total = $nPre + $icmpTargets
            if ($total -gt $options.EffectiveCap) {
                Invoke-PPRefusal -Code 'CapExceeded.PreResolution' -Message ('{0} probes exceed the cap of {1} (before name resolution; nothing was resolved or sent)' -f
                    $total.ToString([cultureinfo]::InvariantCulture), ([int]$options.EffectiveCap).ToString([cultureinfo]::InvariantCulture))
            }
            $worst = Measure-PPWorstCase -Probes @($expansion.Probes) -IcmpTargets $icmpTargets -Options $options
            $header = Get-PPRunHeader -Options $options -ProfileDocument $profileDocument -Expansion $expansion -ProbeCount $total `
                -Basis 'pre-resolution-upper-bound' -ExecutionPath 'None' -StartedUtc $startedUtc -RunId $runId -WorstCaseSeconds $worst
            Write-PPDryRunReport -Options $options -ProfileDocument $profileDocument -Expansion $expansion -Header $header
            $ExitCode.Value = 0
            return
        }

        # 8. Output preflight (Files only). Creates nothing.
        $plan = $null
        if ($options.Emit -ceq 'Files') { $plan = Test-PPOutputPreflight -Options $options }

        # 9. Resolution.
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Status 'Resolving names' }
        $resolution = Resolve-PPProbeList -Probes @($expansion.Probes) -Resolver $resolver
        $resolvedTimestamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)

        # 10. Gate -> Scheduler. The header is printed once the Gate has admitted the list.
        $executionPath = if ($PSVersionTable.PSVersion.Major -ge 7) { 'Parallel' } else { 'Runspace' }
        $ppAdmitState = @{
            Options = $options; ProfileDocument = $profileDocument; Expansion = $expansion; Resolution = $resolution
            StartedUtc = $startedUtc; RunId = $runId; ExecutionPath = $executionPath; Header = $null
        }
        $schedule = @{
            Concurrency = $options.Concurrency; MaxProbesPerSecond = $options.MaxProbesPerSecond
            JitterMs = $options.JitterMs; TimeoutMs = $options.TimeoutMs; ExecutionPath = $executionPath
        }
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Status 'Probing' }
        # -OnAdmitted is an inline scriptblock literal at the call site.
        $gateResult = Invoke-PPGate -Resolution $resolution -Cap $options.EffectiveCap -Icmp:$options.Icmp -Schedule $schedule `
            -Adapters $Adapters -Recorder $Recorder -OnAdmitted {
            param($AdmittedCount)
            $st = $ppAdmitState
            $execCount = @($st.Resolution.ExecProbes | Where-Object { $null -ne $_ }).Count
            $worstCase = Measure-PPWorstCase -Probes @($st.Resolution.ExecProbes) -IcmpTargets ([int]$AdmittedCount - $execCount) -Options $st.Options
            $st.Header = Get-PPRunHeader -Options $st.Options -ProfileDocument $st.ProfileDocument -Expansion $st.Expansion `
                -ProbeCount ([int]$AdmittedCount) -Basis 'admitted' -ExecutionPath $st.ExecutionPath -StartedUtc $st.StartedUtc `
                -RunId $st.RunId -WorstCaseSeconds $worstCase
            Write-PPRunHeader -Header $st.Header
        }

        # 11. Results, ResultSet, exit code.
        $rows = Join-PPResults -Expansion $expansion -Resolution $resolution -GateResult $gateResult -RunId $runId -ResolvedTimestamp $resolvedTimestamp
        $header = $ppAdmitState.Header
        if ($null -eq $header) {
            $header = Get-PPRunHeader -Options $options -ProfileDocument $profileDocument -Expansion $expansion `
                -ProbeCount ([int]$gateResult.AdmittedCount) -Basis 'admitted' -ExecutionPath $executionPath -StartedUtc $startedUtc -RunId $runId
        }
        $header.Flags.ExecutionPath = if ($gateResult.ExecutionPath) { [string]$gateResult.ExecutionPath } else { $executionPath }
        $summary = Get-PPSummary -Rows $rows -ElapsedMs $stopwatch.ElapsedMilliseconds
        $resultSet = [pscustomobject][ordered]@{ PSTypeName = 'PortProof.ResultSet'; Header = $header; Rows = $rows; Summary = $summary }

        # 12. Emit.
        if ($options.Emit -ceq 'Files') {
            [void][System.IO.Directory]::CreateDirectory($plan.Directory)
            $written = [System.Collections.Generic.List[string]]::new()
            foreach ($format in @($options.Formats)) {
                $path = $plan.Files[$format]
                try {
                    switch -CaseSensitive ($format) {
                        'Html' { Write-PPOutputFile -Path $path -Text (ConvertTo-PPHtml -ResultSet $resultSet) -Bom $false -Force $options.Force }
                        'Csv' { Write-PPOutputFile -Path $path -Text (ConvertTo-PPCsv -ResultSet $resultSet) -Bom $true -Force $options.Force }
                        'Json' { Write-PPOutputFile -Path $path -Text (ConvertTo-PPJson -ResultSet $resultSet) -Bom $false -Force $options.Force }
                    }
                }
                catch {
                    if ([string]$_.FullyQualifiedErrorId -clike 'PortProof.*') { throw }
                    $already = if ($written.Count -gt 0) { $written -join ', ' } else { 'none' }
                    Invoke-PPRefusal -Code 'Output.WriteFailed' -Message ("could not write '{0}': {1}; files already written: {2}" -f $path,
                        (Get-PPSafeText -Text $_.Exception.Message), $already)
                }
                $written.Add($path)
            }
        }
        elseif ($options.Emit -ceq 'Stream') {
            switch -CaseSensitive ($options.Formats[0]) {
                'Csv' { Write-Output (ConvertTo-PPCsv -ResultSet $resultSet) }
                'Json' { Write-Output (ConvertTo-PPJson -ResultSet $resultSet) }
            }
        }

        # 13. Summary and exit code.
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Completed }
        Write-PPSummary -ResultSet $resultSet
        $ExitCode.Value = [int]$summary.ExitCode
    }
    catch {
        $fqid = [string]$_.FullyQualifiedErrorId
        if ($fqid -clike 'PortProof.*') {
            Write-Error -Message $_.Exception.Message -ErrorId $fqid -Category InvalidArgument -ErrorAction Continue
        }
        else {
            $message = 'PortProof: internal error: {0}: {1}' -f $_.Exception.GetType().FullName, (Get-PPSafeText -Text $_.Exception.Message)
            Write-Error -Message $message -ErrorId 'PortProof.InternalError' -Category NotSpecified -ErrorAction Continue
        }
        $ExitCode.Value = 2
    }
}

# Entry block - the last lines of 90-Main.ps1 and so of dist/PortProof.ps1. Dot-sourcing this file
# (tests) leaves it inert.
if ($MyInvocation.InvocationName -ne '.') {
    $ppRaw = @{
        ProfilePath = $ProfilePath; Set = $Set; Out = $Out; Format = $Format; Timeout = $Timeout
        Concurrency = $Concurrency; MaxProbesPerSecond = $MaxProbesPerSecond; Jitter = $Jitter
        MaxProbes = $MaxProbes; MaxProbesGiven = $PSBoundParameters.ContainsKey('MaxProbes'); OutGiven = $PSBoundParameters.ContainsKey('Out')
        AllowLarge = [bool]$AllowLarge; AllowCidr = [bool]$AllowCidr; Icmp = [bool]$Icmp
        DryRun = [bool]$DryRun; NoOperator = [bool]$NoOperator; Force = [bool]$Force
        Quiet = [bool]$Quiet; Version = [bool]$Version
    }
    $ppExit = [ref]0
    Invoke-PortProof -Raw $ppRaw -ExitCode $ppExit
    exit $ppExit.Value
}
