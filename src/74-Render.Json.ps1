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
