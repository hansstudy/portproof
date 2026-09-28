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
