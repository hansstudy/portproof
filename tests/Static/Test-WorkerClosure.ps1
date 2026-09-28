<#
    .SYNOPSIS
        Worker-set closure: the
        functions transported into a worker runspace call only each other, .NET, or `Start-Sleep`.

    .DESCRIPTION
        Scope and limits: a static AST scan over our own committed source, run at build/CI time -
        not a proof against a determined insider with commit access. The backstop for anything this
        check still misses is the independent pre-release security review.

        By AST, every command invoked inside `Invoke-PPTargetQueue`, `Wait-PPRateSlot`,
        `Get-PPOutcome` and the three production adapters (`Invoke-TcpProbe`, `Invoke-UdpProbe`,
        `Invoke-IcmpProbe`) must resolve to another member of that same set, or to `Start-Sleep`.
        A .NET method call is not a PowerShell command invocation and is never in scope here (the
        design's own "functions call only each other, .NET, and Start-Sleep").

        One dynamic call is permitted: inside
        `Invoke-PPTargetQueue` only, `& $x` where `$x` is a plain variable reference to one of that
        function's own declared parameters (the adapter-name parameter) - the whitelisted operand
        shape. Any other unresolvable command name (a dynamic `&`/`.` call whose operand is not
        that shape, in any worker-set function including `Invoke-PPTargetQueue`) is a finding.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$workerSetNames = @('Invoke-PPTargetQueue', 'Wait-PPRateSlot', 'Get-PPOutcome', 'Invoke-TcpProbe', 'Invoke-UdpProbe', 'Invoke-IcmpProbe')
$allowedExtra = @('Start-Sleep')
$dynamicAllowedIn = 'Invoke-PPTargetQueue'

$findings = New-Object System.Collections.Generic.List[string]

foreach ($file in Get-PPSourceFile -Root $Root -Dirs @('src')) {
    $result = Get-PPAst -Path $file
    $rawText = [System.IO.File]::ReadAllText($file)
    $ast = $result.Ast

    $funcDefs = $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        ($workerSetNames -icontains $args[0].Name)
    }, $true)

    foreach ($func in $funcDefs) {
        $isTargetQueue = $func.Name -ieq $dynamicAllowedIn
        $paramNames = @()
        if ($func.Parameters) {
            $paramNames = $func.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
        } elseif ($func.Body.ParamBlock) {
            $paramNames = $func.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath }
        }

        $commands = $func.Body.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($cmd in $commands) {
            $name = $cmd.GetCommandName()
            $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset

            if ($name) {
                if (($workerSetNames -icontains $name) -or ($allowedExtra -icontains $name)) { continue }
                $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'WorkerClosure.OutsideSet' `
                    -Text "'$name' called from '$($func.Name)' is outside the closed worker set" -Root $Root))
                continue
            }

            # Dynamic call (no resolvable literal command name): only allowed in
            # Invoke-PPTargetQueue, and only when the operand is a bare reference to one of its
            # own declared parameters.
            $isSimpleVariableOperand = $false
            $operandName = $null
            if ($cmd.CommandElements.Count -gt 0 -and
                $cmd.CommandElements[0] -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $operandName = $cmd.CommandElements[0].VariablePath.UserPath
                $isSimpleVariableOperand = $true
            }

            if ($isTargetQueue -and $isSimpleVariableOperand -and ($paramNames -icontains $operandName)) {
                continue  # the one whitelisted dynamic call
            }

            $operandText = $cmd.CommandElements[0].Extent.Text
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'WorkerClosure.UnapprovedDynamicCall' `
                -Text "dynamic call '$operandText' in '$($func.Name)' is not the whitelisted adapter-name operand" -Root $Root))
        }
    }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
