<#
    .SYNOPSIS
        AC38 - no unresolved template tokens.

    .DESCRIPTION
        Scope and limits: a static regex scan over the whole tree, run at build/CI time - not a
        proof against a determined insider with commit access. The backstop for anything this check
        still misses is the independent pre-release security review.

        `\{\{[A-Z_]+\}\}` over the whole tree, excluding `.git/` and exactly the two verbatim
        upstream copies `docs/RELEASE-CHECKLIST.md` and
        `.github/workflows/scripts/check-release-evidence.mjs` (they carry the token literally, by
        design, as documentation of the template mechanism itself).

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$excludedRelativePaths = @(
    'docs\RELEASE-CHECKLIST.md',
    '.github\workflows\scripts\check-release-evidence.mjs'
)

# Extensions unlikely to be text, or too large to usefully regex-scan: skipped rather than risk a
# false read of binary content as text (never a security exemption - these are asset kinds, not
# document kinds a template token could hide in).
$skipExtensions = @('.png', '.jpg', '.jpeg', '.gif', '.ico', '.zip', '.dll', '.exe', '.pdf', '.gitattributes')

$findings = New-Object System.Collections.Generic.List[string]
$rootFull = (Resolve-Path -LiteralPath $Root).ProviderPath.TrimEnd('\', '/')

Get-ChildItem -LiteralPath $Root -Recurse -File -Force | ForEach-Object {
    $full = $_.FullName
    $relative = $full.Substring($rootFull.Length).TrimStart('\', '/')

    if ($relative -match '(^|\\)\.git(\\|$)') { return }
    if ($excludedRelativePaths -icontains $relative) { return }
    if ($skipExtensions -icontains $_.Extension) { return }

    try {
        $text = [System.IO.File]::ReadAllText($full)
    } catch {
        return
    }
    if ($text.IndexOf("`0") -ge 0) { return }  # binary heuristic

    foreach ($m in [regex]::Matches($text, '\{\{[A-Z_]+\}\}')) {
        $line = Get-PPLineNumber -Text $text -Offset $m.Index
        $findings.Add((Format-PPFinding -Path $full -Line $line -Rule 'AC38.TemplateToken' -Text "unresolved token '$($m.Value)'" -Root $Root))
    }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
