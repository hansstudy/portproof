<#
    .SYNOPSIS
        AC18 - no telemetry and no outbound calls other than the declared probes.

    .DESCRIPTION
        Scope and limits: a static token scan over our own committed source, run at build/CI time -
        not a proof against a determined insider with commit access. The backstop for anything a
        reviewed token list still misses is the independent pre-release security review.

        AC18: source scan with comments stripped, over src/ and dist/, for zero matches of
        `Invoke-WebRequest`, `Invoke-RestMethod`, `System.Net.WebClient`, `HttpClient`,
        `Start-BitsTransfer`, or any update check.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$rules = @(
    @{ Rule = 'AC18.Outbound'; Pattern = 'Invoke-WebRequest' }
    @{ Rule = 'AC18.Outbound'; Pattern = 'Invoke-RestMethod' }
    @{ Rule = 'AC18.Outbound'; Pattern = 'System\.Net\.WebClient' }
    @{ Rule = 'AC18.Outbound'; Pattern = '\bWebClient\b' }
    @{ Rule = 'AC18.Outbound'; Pattern = 'HttpClient' }
    @{ Rule = 'AC18.Outbound'; Pattern = 'Start-BitsTransfer' }
    # "any update check" heuristics - no such feature exists in this tool's design; a name in
    # this shape landing in src/ or dist/ is itself the finding.
    @{ Rule = 'AC18.UpdateCheck'; Pattern = 'CheckForUpdate' }
    @{ Rule = 'AC18.UpdateCheck'; Pattern = 'UpdateCheck' }
    @{ Rule = 'AC18.UpdateCheck'; Pattern = 'NewVersionAvailable' }
    @{ Rule = 'AC18.UpdateCheck'; Pattern = 'LatestRelease' }
)

$findings = New-Object System.Collections.Generic.List[string]

foreach ($file in Get-PPSourceFile -Root $Root -Dirs @('src', 'dist')) {
    $text = Get-PPStrippedText -Path $file
    foreach ($r in $rules) {
        $hits = [regex]::Matches($text, $r.Pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $hits) {
            $line = Get-PPLineNumber -Text $text -Offset $m.Index
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule $r.Rule -Text "matched '$($m.Value)'" -Root $Root))
        }
    }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
