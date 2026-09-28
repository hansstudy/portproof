<#
    .SYNOPSIS
        AC3 / `lint_command` - the one PSScriptAnalyzer invocation for PortProof.

    .DESCRIPTION
        Scope and limits: this runs PSScriptAnalyzer's own rule set plus two settings-hygiene
        checks, at build/CI time - it is not a proof against a determined insider with commit
        access, and it does not replace the other scanners in this folder. The backstop for
        anything it misses is the independent pre-release security review.

        Runs `Invoke-ScriptAnalyzer -Recurse -Settings settings/PSScriptAnalyzerSettings.psd1` over
        each of `src`, `build`, `tests`, and `dist` (when present). Fails (exit 1) on any Error or
        Warning diagnostic, on any `SuppressMessageAttribute` whose `Justification` is empty, or on
        any `ExcludeRules` entry in the settings file that lacks a `# reason:` comment on its line.
        In CI, installs PSScriptAnalyzer 1.25.0 first if that exact version is not already
        available. This is the exact string `release-config.yml`'s `lint_command` runs:
        `powershell -NoProfile -NonInteractive -File tests/Static/Invoke-Lint.ps1`.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'Invoke-Lint.ps1 is a console runner, not a reusable module: every Write-Host call here is deliberate user-facing progress/result output, the same pattern tests/Invoke-Tests.ps1 already uses.')]
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$requiredVersion = '1.25.0'

if ($env:CI) {
    $hasExact = [bool] (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { $_.Version -eq [version] $requiredVersion })
    if (-not $hasExact) {
        try {
            Install-Module PSScriptAnalyzer -RequiredVersion $requiredVersion -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop
        } catch {
            Write-Host "Invoke-Lint: could not install PSScriptAnalyzer $requiredVersion in CI: $($_.Exception.Message)"
        }
    }
}

Remove-Module PSScriptAnalyzer -Force -ErrorAction SilentlyContinue
try {
    Import-Module PSScriptAnalyzer -RequiredVersion $requiredVersion -ErrorAction Stop
} catch {
    Write-Host "Invoke-Lint: PSScriptAnalyzer $requiredVersion is not available: $($_.Exception.Message)"
    exit 1
}

$loadedVersion = (Get-Module PSScriptAnalyzer).Version
if ($loadedVersion -ne [version] $requiredVersion) {
    Write-Host "Invoke-Lint: loaded PSScriptAnalyzer $loadedVersion, expected exactly $requiredVersion."
    exit 1
}

$settingsPath = Join-Path $PSScriptRoot 'settings\PSScriptAnalyzerSettings.psd1'
if (-not (Test-Path -LiteralPath $settingsPath)) {
    Write-Host "Invoke-Lint: settings file not found at '$settingsPath'."
    exit 1
}

$failed = $false

# --- Every ExcludeRules entry needs a '# reason:' comment on its line. ---
$settingsLines = Get-Content -LiteralPath $settingsPath
$inExcludeRules = $false
foreach ($line in $settingsLines) {
    if ($line -match '\bExcludeRules\b') { $inExcludeRules = $true }
    if ($inExcludeRules) {
        if ($line -match '^\s*[''"]?[A-Za-z][\w-]*[''"]?\s*(,|$)' -and $line -notmatch '=') {
            if ($line -notmatch '#\s*reason:') {
                Write-Host "Invoke-Lint: ExcludeRules entry missing a '# reason:' comment: $line"
                $failed = $true
            }
        }
        if ($line -match '\)') { $inExcludeRules = $false }
    }
}

# --- Every SuppressMessage(Attribute) needs a non-empty Justification. ---
# Parsed from the AST (AttributeAst), not a regex: a regex anchored on `SuppressMessageAttribute(`
# misses the short form (`SuppressMessage(...)`, valid and honoured by PSSA - .NET attribute
# references may omit the `Attribute` suffix) and mis-captures when the Justification text itself
# contains a ')' (the capture group stops at the first one, which is not necessarily attribute's).
# A plain `foreach` (not `ForEach-Object`) throughout: a ForEach-Object scriptblock is its own
# scope, so `$failed = $true` inside one would set a local shadow copy and never reach the flag
# this script exits on.
$dirsToScan = @('src', 'build', 'tests', 'dist') | ForEach-Object { Join-Path $Root $_ } | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
foreach ($dir in $dirsToScan) {
    $codeFiles = Get-ChildItem -LiteralPath $dir -Recurse -File -Include '*.ps1', '*.psm1'
    foreach ($file in $codeFiles) {
        $astResult = Get-PPAst -Path $file.FullName
        $attributes = $astResult.Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.AttributeAst] }, $true)
        foreach ($attr in $attributes) {
            $typeName = $attr.TypeName.FullName
            if ($typeName -notmatch '(?i)(^|\.)SuppressMessage(Attribute)?$') { continue }
            $justificationArg = $attr.NamedArguments | Where-Object { $_.ArgumentName -ieq 'Justification' } | Select-Object -First 1
            $justificationValue = $null
            if ($justificationArg -and -not $justificationArg.ExpressionOmitted) {
                $justificationValue = Resolve-PPConstantString $justificationArg.Argument
            }
            if ([string]::IsNullOrWhiteSpace($justificationValue)) {
                $line = $attr.Extent.StartLineNumber
                Write-Host "Invoke-Lint: $($file.FullName):$line has a SuppressMessage(Attribute) with an empty or missing Justification."
                $failed = $true
            }
        }
    }
}

# --- The one Invoke-ScriptAnalyzer run. ---
$diagnostics = @()
foreach ($dir in $dirsToScan) {
    $diagnostics += Invoke-ScriptAnalyzer -Path $dir -Recurse -Settings $settingsPath
}

$blocking = $diagnostics | Where-Object { $_.Severity -in @('Error', 'Warning') }
if ($blocking) {
    foreach ($d in $blocking) {
        Write-Host ("Invoke-Lint: {0}:{1}: {2}: {3}" -f $d.ScriptPath, $d.Line, $d.Severity, $d.Message)
    }
    $failed = $true
}

if ($failed) { exit 1 } else { exit 0 }
