<#
    .SYNOPSIS
        PortProof test entry point. Guards the Pester version, dispatches by tag and by host
        (AC4), and computes its own exit code.

    .DESCRIPTION
        `-Suite Auto` (default) picks what a host can run: Portable-only off Windows; on Windows
        PowerShell 5.1 it runs Portable+Windows in-process, then launches `pwsh -Suite PS7` if
        `pwsh` is on PATH (else reports PS7 SKIPPED); under pwsh on Windows it runs PS7 in-process,
        then launches `powershell.exe -Suite Full` for the 5.1 suite. Explicit `-Suite` values
        (Full, Portable, PS7) never launch a second host - there is no recursion. Runner exit codes
        (0 = all run suites passed, 1 = a suite failed or a test is mistagged, 3 = the Pester guard
        failed) are the test harness's own and are unrelated to the tool's 0/1/2.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '',
    Justification = 'This is the test runner (tests/Invoke-Tests.ps1), not tool code in src/: its
    job is to print its own progress and results to the console host a verifier or CI log is
    reading, not to produce pipeline output for another command to consume. Write-Host is the
    correct cmdlet for that job by design (the information-stream contract this runner is
    deliberately outside of applies only to src/).')]
[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Full', 'Portable', 'PS7')]
    [string] $Suite = 'Auto'
)

$ErrorActionPreference = 'Stop'
$testsRoot = $PSScriptRoot

# The version the local verifier runs: pinned so a CI lane with no Pester
# preinstalled gets the exact version this tool was built and measured against.
$pinnedPester = '6.1.0'

Remove-Module Pester -Force -ErrorAction SilentlyContinue

if ($env:CI) {
    $hasV5 = [bool] (Get-Module -ListAvailable -Name Pester | Where-Object { $_.Version -ge [version] '5.0' })
    if (-not $hasV5) {
        try {
            Install-Module Pester -RequiredVersion $pinnedPester -Scope CurrentUser -Force -SkipPublisherCheck -ErrorAction Stop
        } catch {
            Write-Host "PortProof tests: could not install Pester $pinnedPester in CI: $($_.Exception.Message)"
        }
    }
}

try {
    Import-Module Pester -MinimumVersion 5.0 -ErrorAction Stop
} catch {
    Write-Host "PortProof tests need Pester 5 or later; import failed: $($_.Exception.Message)"
    exit 3
}

$pesterVersion = (Get-Module Pester).Version
if (-not $pesterVersion -or $pesterVersion -lt [version] '5.0') {
    Write-Host "PortProof tests need Pester 5 or later; found $pesterVersion"
    exit 3
}

$isDesktop = $PSVersionTable.PSEdition -eq 'Desktop'
if ($isDesktop) {
    $onWindows = $true
} else {
    $onWindows = [bool] (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue -ValueOnly)
}

function Invoke-PPTestSuite {
    <# Runs one tag set through Pester and reports pass/fail/skip counts. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string[]] $Tag,
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $Label
    )
    $config = [PesterConfiguration] @{
        Run    = @{ Path = $Path; PassThru = $true; Exit = $false }
        Filter = @{ Tag = $Tag }
        Output = @{ Verbosity = 'Normal' }
    }
    $result = Invoke-Pester -Configuration $config
    Write-Host ("PortProof tests: {0} -> {1} passed, {2} failed, {3} skipped" -f `
        $Label, $result.PassedCount, $result.FailedCount, $result.SkippedCount)
    return ($result.FailedCount -eq 0)
}

function Test-PPTagDiscipline {
    <# Discovery-only pass: every test must carry exactly one of Portable, Windows, PS7. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path)
    $config = [PesterConfiguration] @{
        Run    = @{ Path = $Path; PassThru = $true; SkipRun = $true }
        Output = @{ Verbosity = 'None' }
    }
    $discovery = Invoke-Pester -Configuration $config
    $validTags = @('Portable', 'Windows', 'PS7')
    $offenders = New-Object System.Collections.Generic.List[string]
    foreach ($test in $discovery.Tests) {
        # In discovery-only mode (Run.SkipRun) a leaf test's own .Tag is not yet resolved; the tag
        # lives on the Describe/Context block(s) that contain it, so walk the block chain and union
        # every tag found up to (not including) the synthetic Root block.
        $allTags = New-Object System.Collections.Generic.List[string]
        $block = $test.Block
        while ($block -and $block.Name -ne 'Root') {
            if ($block.Tag) { foreach ($t in $block.Tag) { $allTags.Add($t) } }
            $block = $block.Parent
        }
        $matched = @($allTags | Where-Object { $validTags -contains $_ } | Select-Object -Unique)
        if ($matched.Count -ne 1) {
            $label = $test.Name
            if ($test.ExpandedPath) { $label = $test.ExpandedPath }
            $offenders.Add($label)
        }
    }
    return $offenders.ToArray()
}

$offenders = Test-PPTagDiscipline -Path $testsRoot
if ($offenders.Count -gt 0) {
    Write-Host 'PortProof tests: every test must carry exactly one of the tags Portable, Windows, PS7. Offending tests:'
    foreach ($name in $offenders) { Write-Host "  $name" }
    exit 1
}

$overallSuccess = $true

switch ($Suite) {
    'Portable' {
        $overallSuccess = Invoke-PPTestSuite -Tag @('Portable') -Path $testsRoot -Label 'Portable'
    }
    'Full' {
        if ($env:STUDY_PS_FLOOR -eq '5.1' -and -not $isDesktop) {
            Write-Host 'PortProof tests: STUDY_PS_FLOOR=5.1 requires -Suite Full to run under Windows PowerShell 5.1 Desktop.'
            exit 3
        }
        $overallSuccess = Invoke-PPTestSuite -Tag @('Portable', 'Windows') -Path $testsRoot -Label 'Full (Portable+Windows)'
    }
    'PS7' {
        $overallSuccess = Invoke-PPTestSuite -Tag @('PS7') -Path $testsRoot -Label 'PS7'
    }
    'Auto' {
        if (-not $onWindows) {
            $overallSuccess = Invoke-PPTestSuite -Tag @('Portable') -Path $testsRoot -Label 'Auto: Portable (non-Windows host)'
        } elseif ($isDesktop) {
            $overallSuccess = Invoke-PPTestSuite -Tag @('Portable', 'Windows') -Path $testsRoot -Label 'Auto: Portable+Windows (5.1, in-process)'
            $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
            if ($pwshCmd) {
                Write-Host 'PortProof tests: launching pwsh for the PS7 suite.'
                & $pwshCmd.Source -NoProfile -NonInteractive -File $PSCommandPath -Suite PS7
                if ($LASTEXITCODE -ne 0) { $overallSuccess = $false }
            } else {
                Write-Host 'PortProof tests: PS7 group SKIPPED (pwsh not present).'
            }
        } else {
            $overallSuccess = Invoke-PPTestSuite -Tag @('PS7') -Path $testsRoot -Label 'Auto: PS7 (in-process)'
            $powershellCmd = Get-Command powershell.exe -ErrorAction SilentlyContinue
            if ($powershellCmd) {
                Write-Host 'PortProof tests: launching powershell.exe for the 5.1 (Full) suite.'
                & $powershellCmd.Source -NoProfile -NonInteractive -File $PSCommandPath -Suite Full
                if ($LASTEXITCODE -ne 0) { $overallSuccess = $false }
            } else {
                Write-Host 'PortProof tests: powershell.exe not found; cannot run the 5.1 suite.'
                $overallSuccess = $false
            }
        }
    }
}

if ($overallSuccess) { exit 0 } else { exit 1 }
