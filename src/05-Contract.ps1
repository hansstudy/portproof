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
