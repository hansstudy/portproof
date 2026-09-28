<#
    .SYNOPSIS
        AC30 (call-site half) - the class predicate and the Scheduler's entry point each have one
        owner.

    .DESCRIPTION
        Scope and limits: a static AST scan over our own committed source, run at build/CI time -
        not a proof against a determined insider with commit access. The backstop for anything this
        check still misses is the independent pre-release security review.

        By AST, over src/: `Test-RefusedTargetClass` is invoked only from `10-Parser.ps1` and
        `35-Gate.ps1` (its definition site, `05-Contract.ps1`, is excluded from the scan - a
        definition is not a call site); `Invoke-ProbeSchedule` is invoked only from `35-Gate.ps1`.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$rules = @(
    @{ Name = 'Test-RefusedTargetClass'; Allowed = @('10-Parser.ps1', '35-Gate.ps1'); Exclude = @('05-Contract.ps1') }
    @{ Name = 'Invoke-ProbeSchedule';    Allowed = @('35-Gate.ps1');                  Exclude = @() }
)

$findings = New-Object System.Collections.Generic.List[string]

foreach ($file in Get-PPSourceFile -Root $Root -Dirs @('src')) {
    $leaf = [System.IO.Path]::GetFileName($file)
    $result = Get-PPAst -Path $file
    $rawText = [System.IO.File]::ReadAllText($file)
    $commands = $result.Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)

    foreach ($rule in $rules) {
        if ($rule.Exclude -icontains $leaf) { continue }
        foreach ($cmd in $commands) {
            $name = $cmd.GetCommandName()
            if ($name -and $name -ieq $rule.Name -and ($rule.Allowed -inotcontains $leaf)) {
                $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
                $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC30.CallSite' `
                    -Text "'$($rule.Name)' called outside {$($rule.Allowed -join ', ')}" -Root $Root))
            }
        }
    }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
