<#
    .SYNOPSIS
        AC17 - no credential logic anywhere.

    .DESCRIPTION
        Scope and limits: a static token scan over our own committed source, run at build/CI time -
        not a proof against a determined insider with commit access. The backstop for anything a
        reviewed token list still misses is the independent pre-release security review.

        AC17: source scan with comments and comment-based help stripped, over src/ and
        dist/, for zero matches of `Get-Credential`, `PSCredential`, `ConvertTo-SecureString`, a
        `-Credential` parameter declaration, or any credential-file read. The README/help sentence
        "no -Credential parameter" is prose, not code, so it is never scanned here.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$rules = @(
    @{ Rule = 'AC17.Credential'; Pattern = 'Get-Credential' }
    @{ Rule = 'AC17.Credential'; Pattern = 'PSCredential' }
    @{ Rule = 'AC17.Credential'; Pattern = 'ConvertTo-SecureString' }
    @{ Rule = 'AC17.Credential'; Pattern = '\$Credential\b' }
    @{ Rule = 'AC17.Credential'; Pattern = '-Credential\b' }
    # Heuristic for "any credential-file read": a stored-credential file loaded back in.
    @{ Rule = 'AC17.Credential'; Pattern = 'Import-Clixml[^\n]*[Cc]red' }
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
