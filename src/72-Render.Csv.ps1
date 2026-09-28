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
