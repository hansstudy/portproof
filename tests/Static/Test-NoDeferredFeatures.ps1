<#
    .SYNOPSIS
        AC28 - the implementation tokens for deferred features are absent from src/.

    .DESCRIPTION
        Scope and limits: a static token scan over our own committed source, run at build/CI time -
        not a proof against a determined insider with commit access. The backstop for anything a
        reviewed token list still misses is the independent pre-release security review.

        AC28: no `Invoke-Command`, `New-PSSession`, `TcpListener`, or `Publish-PSResource`
        in `src/`. Scoped to src/ only (not dist/, not tests/): naming listener mode in the README
        limitations section is required, not forbidden, and the test harness legitimately uses
        `TcpListener` (tests/Harness/), which this scanner never looks at.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$rules = @(
    @{ Rule = 'AC28.DeferredFeature'; Pattern = 'Invoke-Command' }
    @{ Rule = 'AC28.DeferredFeature'; Pattern = 'New-PSSession' }
    @{ Rule = 'AC28.DeferredFeature'; Pattern = 'TcpListener' }
    @{ Rule = 'AC28.DeferredFeature'; Pattern = 'Publish-PSResource' }
)

$findings = New-Object System.Collections.Generic.List[string]

foreach ($file in Get-PPSourceFile -Root $Root -Dirs @('src')) {
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
