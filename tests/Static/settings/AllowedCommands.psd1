@{
    # PortProof command allowlist.
    #
    # Every CommandAst in src/ and dist/ must resolve its GetCommandName() to either (a) a function
    # defined somewhere in src/ (collected dynamically by the scanner from FunctionDefinitionAst
    # across the current tree - not listed here, since it changes as the tree grows) or (b) one of
    # the cmdlets below. Anything else is a finding. One reason per entry; this file holds data only.
    #
    # Never on this list, ever (and enforced independently of it): Set-Alias, New-Alias,
    # New-Object, Invoke-Expression, Invoke-Command, Start-Job, Get-Command, Get-Alias,
    # Get-Variable, Add-Type, Import-Module, ForEach-Object, Where-Object.
    #
    # ForEach-Object and Where-Object are never entries on THIS list (and never will be) - they are
    # governed by their own, narrower, literal-scriptblock-only rule instead
    # (Find-PPPipelineScriptBlockFinding: allowed only when every scriptblock-bearing argument -
    # -Process/-FilterScript/-Begin/-End/-Action, or the positional slot - is an inline `{ ... }`
    # literal written at the call site, never a variable).
    #
    # Get-Command has exactly one named exception, not a general allowlist entry: inside
    # `Get-PPWorkerDefinition` in `40-Scheduler.ps1`, which
    # requires `Get-Command -CommandType Function` to read the worker functions' own
    # ScriptBlock text before transporting it into a runspace. That exception is implemented as its
    # own scoped check (Test-PPIsWorkerDefinitionScope), never by adding "Get-Command" here.
    #
    # Every entry below must be a command src/ actually calls today: a
    # pre-emptive, never-called entry breaks the "every new command is a settings diff" property
    # this list exists for - a reviewer sees no diff the first time a change actually adds the call.
    # A later change that starts calling a cmdlet not yet listed adds it here, with its own reason,
    # in that change's own diff.

    'Write-Output'      = 'Success-stream emission; already used in 90-Main.ps1.'
    'Write-Error'       = 'Internal-error / PortProof.* FQID exception surface; already used in 90-Main.ps1.'
    'Write-Information' = 'Notice/header/DryRun-report/summary streams; already used in 90-Main.ps1.'
    'Write-Progress'    = 'Progress reporting unless -Quiet; already used in 90-Main.ps1.'
    'Sort-Object'       = 'ResultSet row ordering (ProfileRow, then SourceName, TargetName, Port, Protocol, ordinal compare); already used in 90-Main.ps1.'
    'Set-Item'          = 'The one function: drive write inside the -Parallel block of Invoke-ProbeSchedule. Independently restricted: allowed only with a literal function: -Path/-LiteralPath, inside that one scope; any variable:/alias:/env: target, or a non-literal function: path, is a finding regardless of this entry (Find-PPProviderDriveWriteFinding, and the existing function-write scoping). Already used in 40-Scheduler.ps1.'
    'Start-Sleep'       = 'JitterMs sleep and Wait-PPRateSlot''s bounded wait loop in the worker set (Invoke-PPTargetQueue, Wait-PPRateSlot) - already used in 40-Scheduler.ps1. Also the one non-.NET call the closed worker set may make (Test-WorkerClosure.ps1).'
    'Write-Warning'     = 'A worker failure or a missing-result count is reported via Write-Warning, never thrown (a queue failure yields ProbeError rows, never a missing row) - already used in 40-Scheduler.ps1.'
}
