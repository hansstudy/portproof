<#
    .SYNOPSIS
        AC19 - no dynamic evaluation. An allowlist, not a blocklist, layered on top of a
        construct-class posture that stays on as a second layer.

    .DESCRIPTION
        Scope and limits: this is a static allowlist check over our own committed source, run at
        build/CI time. It is not a proof against a determined insider with commit access - someone
        who can edit src/ can also edit this scanner or its settings files. What it does buy: every
        command and type src/ and dist/ can name is a short, reviewed, one-line-justified list, so
        a change that adds a new command or type is visible in review as a settings-file diff, not
        buried in a 500-line source file. The backstop for what a reviewed allowlist entry might
        still let through is the independent pre-release security review, not this scanner.

        An earlier blocklist posture (banning named dangerous
        constructs) kept finding new bypasses: `.Assembly.GetType(...)` into a variable then
        `$t::Create(...)`, `ForEach-Object -Process $blk`, `(Get-Command $n).ScriptBlock.Invoke()`,
        a non-foldable `-as [type]` from concatenated variables. Blocklists cannot be complete in
        PowerShell - there are too many ways to reach a type, a member or a command dynamically.
        Since everything in src/ and dist/ is code we wrote (never external
        input), the default is inverted. Two allowlists now gate everything else:

          A. COMMAND ALLOWLIST - every `CommandAst` must resolve `GetCommandName()` to (a) a
             function defined somewhere in src/ (collected fresh each run from every
             `FunctionDefinitionAst`, so it tracks the tree without editing this scanner as it
             grows) or (b) an entry in `settings/AllowedCommands.psd1`. `Set-Alias`, `New-Alias`,
             `New-Object`, `Invoke-Expression`, `Invoke-Command`, `Start-Job`, `Get-Command`,
             `Get-Alias`, `Get-Variable`, `Add-Type`, `Import-Module` are never on that file's list.
             `ForEach-Object`/`Where-Object` (and their aliases `%`/`?`/`where`) are allowed only
             when every scriptblock-bearing argument (`-Process`/`-FilterScript`/`-Begin`/`-End`/
             `-Action`, or positional) is an inline `{ ... }` literal - src/ already calls both this
             way today, so the narrower rule was chosen over rewriting them to `foreach`/`if` (see
             `Find-PPPipelineScriptBlockFinding` below for why). `Get-Command` has exactly one named
             exception, not a list entry: `Get-PPWorkerDefinition` in `40-Scheduler.ps1`, which
             needs it there to read a loaded function's own script text.
          B. TYPE ALLOWLIST - every `TypeExpressionAst`/`TypeConstraintAst` must name a type in
             `settings/AllowedTypes.psd1`'s General section (allowed anywhere) or its Scoped
             section (allowed only in one designated file - `TcpClient` only in
             `50-Probe.Tcp.ps1`, and so on). `scriptblock` is on neither list, so even a bare
             `param([scriptblock] $x)` constraint is now a finding, on top of the class-2 cast ban
             below.

        The construct-class bans stay on as a second, independent layer (a name could be
        allowlisted and still be reached through a banned shape), plus four more classes below:

        Banned construct classes (this scanner's authoritative list - cite this section, not the
        addenda below, when documenting the posture elsewhere):

          1. Literal banned tokens (comment-stripped, no exception anywhere): `Invoke-Expression`,
             `iex`, `[scriptblock]::Create`/`ScriptBlock]::Create`, `Add-Type`, `NewScriptBlock`.
          2. Any cast or conversion to the scriptblock type, in any namespace spelling, whether or
             not the result is ever invoked: `[scriptblock]$x`, `$x -as [scriptblock]`, a type given
             as a string (`[type]"scriptblock"`, `"...ScriptBlock" -as [type]`).
          3. Reflection: `.GetMethod(`, `.GetMember(`, `.InvokeMember(`, `.GetType()` followed by a
             further invoke, `[Reflection.*]` (any depth), `[Activator]`.
          4. A computed member name of any kind: `.$x`, `.($expr)`, `::($expr)`, and even a literal
             quoted member (`.'Create'`, `."Create"`) - the syntax itself is banned, not just the
             dynamic cases. Plain bareword access (`.Create`, `.Connect(`, `.AddressFamily`) is
             untouched.
          5. A dynamic command name for `&` and `.`: the command position must resolve to a plain
             bareword or literal string (`GetCommandName()` succeeds). The one allowance is
             `Invoke-PPTargetQueue`'s adapter-name dispatch in `40-Scheduler.ps1`:
             `& $x`/`. $x` where `$x` is literally one of that function's own parameters.
          6. `Start-Job`, `Start-ThreadJob`, `Invoke-Command` (banned outright); `Register-
             ObjectEvent`/`Register-EngineEvent` with `-Action`; and, generally, any `-ScriptBlock`/
             `-Action` parameter on any command bound to anything other than an inline scriptblock
             literal written at the call site.
          7. A `function:` drive write, literal or via a variable path, outside the two scoped
             allowances in `40-Scheduler.ps1` (exactly one `Set-Item`/`New-Item` write inside
             the `-Parallel` block, fed only from `Get-PPWorkerDefinition` via `$using:`, and
             `SessionStateFunctionEntry` for the 5.1 path).
          8. `.InvokeScript(`, `.AddScript(`, `.CreatePipeline(` on any object - the arbitrary-
             script primitives behind `[powershell]`/`[runspacefactory]`-based execution.
             `.AddCommand(` (invoking an already-loaded, named command) and `.BeginInvoke(`/
             `.EndInvoke(` are not banned: that is the shape `40-Scheduler.ps1` needs for its own
             `[PowerShell]` per queue.
          9. `Set-Alias`/`New-Alias` whose target is a banned command name (classes 1/6): aliasing
             around a literal ban is itself the finding, whether or not the alias is ever called.
         10. Splatting (`@var`) into a call whose command name resolves to a banned name (classes
             1/6): splatting does not hide the name from `GetCommandName()`, so this is already
             covered by those classes, not a separate code path - listed here so the posture is
             traceable in one place.
         11. Static member access on a non-literal (`$x::Member` - a variable holding a type
             is exactly the "type via a variable" evasion, closed structurally regardless of what
             the variable holds).
         12. `-as` with any type operand at all, not only `-as [scriptblock]` - nothing in this tool
             needs the operator anywhere, so it is closed rather than enumerated per target type.
         13. `.GetType(` unconditionally (not only when chained into a further invoke -
             assigning the result to a variable first is exactly as capable), `.Assembly`, `.Module`,
             `.InvokeReturnAsIs(`.
         14. `.Invoke(` everywhere, no exception: the Scheduler's own mechanism uses
             `BeginInvoke`/`EndInvoke`, never a synchronous `.Invoke(`, so none was carved out.
             `.ScriptBlock` is banned everywhere except `Get-PPWorkerDefinition` in
             `40-Scheduler.ps1` (the same scoped spot that needs `Get-Command` above).

        Everything above is layered on top of the constant-fold and wildcard-resolution checks this
        scanner already had (a name built from `'a' + 'b'` or resolved via `& (gcm i*x)` folds to a
        literal and is checked against classes 1/6 the same way).

        Every file-scoped allowance here (the
        `& $x` dispatch, the type allowlist's Scoped section, `[scriptblock]` on `$OnAdmitted`,
        `Get-PPWorkerDefinition`'s `Get-Command`/`.ScriptBlock` exception, `$AdapterName`'s source
        trace, `SessionStateFunctionEntry`, and the `function:` drive write) is resolved per node,
        from that node's own offset, mapped back to its original `src/` part via
        `Get-PPOwningLeaf`/`Get-PPDistPartMap` (StaticScan.ps1) - never by comparing the whole scanned
        file's own name. Every part of dist/PortProof.ps1 shares one file name (`PortProof.ps1`), so a
        whole-file check could not tell `40-Scheduler.ps1`'s own concatenated segment apart from any
        other part's, guaranteeing false positives on a legitimate construct in a real build.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$schedulerFileName = '40-Scheduler.ps1'
$bannedCommandNames = @('Invoke-Expression', 'iex', 'Add-Type', 'NewScriptBlock')
$dangerousMemberNames = @('InvokeScript', 'AddScript', 'CreatePipeline')

$findings = New-Object System.Collections.Generic.List[string]

# --- Layer 1: literal comment-stripped token scan (AC19's own wording, verbatim). ---
$literalPatterns = @(
    @{ Rule = 'AC19.LiteralToken'; Pattern = '\bInvoke-Expression\b' }
    @{ Rule = 'AC19.LiteralToken'; Pattern = '\biex\b' }
    @{ Rule = 'AC19.LiteralToken'; Pattern = '\[\s*scriptblock\s*\]\s*::\s*Create\b' }
    @{ Rule = 'AC19.LiteralToken'; Pattern = 'ScriptBlock\s*\]\s*::\s*Create\b' }
    @{ Rule = 'AC19.LiteralToken'; Pattern = '\bAdd-Type\b' }
    @{ Rule = 'AC19.LiteralToken'; Pattern = '\bNewScriptBlock\b' }
)

function Find-PPLiteralTokenFinding {
    param([string] $Path, [string] $Root)
    $local = New-Object System.Collections.Generic.List[string]
    $text = Get-PPStrippedText -Path $Path
    foreach ($p in $literalPatterns) {
        foreach ($m in [regex]::Matches($text, $p.Pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $line = Get-PPLineNumber -Text $text -Offset $m.Index
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule $p.Rule -Text "matched '$($m.Value)'" -Root $Root))
        }
    }
    $local
}

# --- Layer 2: AST. ---
function Find-PPAstDynamicEvalFinding {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'Root is used inside the nested Add-Finding function below, which closes over it; PSScriptAnalyzer does not trace usage through a nested function definition.')]
    param([string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    function Add-Finding($OffsetNode, [string] $Rule, [string] $Text) {
        $line = Get-PPLineNumber -Text $rawText -Offset $OffsetNode.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule $Rule -Text $Text -Root $Root))
    }

    # 1. Banned command names, resolved through GetCommandName() (defeats a backtick escape or a
    #    line-split bareword) and un-module-qualified (Module\Invoke-Expression -> Invoke-Expression).
    $commands = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($cmd in $commands) {
        $name = $cmd.GetCommandName()
        if (-not $name) { continue }
        $simpleName = $name -replace '^.*\\', ''
        if ($bannedCommandNames -icontains $simpleName) {
            Add-Finding $cmd 'AC19.DynamicEval' "banned command '$simpleName'"
        }
    }

    # 2. [scriptblock]::Create - direct, via a one-hop type variable (incl. [type]"scriptblock" and
    #    "...ScriptBlock" -as [type]), or via a variable holding the member name "Create".
    $staticCalls = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static
    }, $true)
    foreach ($call in $staticCalls) {
        $memberName = $null
        if ($call.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $memberName = $call.Member.Value
        } elseif ($call.Member -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $memberName = Resolve-PPVariableConstant -VarName $call.Member.VariablePath.UserPath -FileAst $ast -BeforeOffset $call.Extent.StartOffset
        }
        if ($memberName -ieq 'Create' -and (Test-PPScriptBlockTypeExpr -ExprAst $call.Expression -FileAst $ast)) {
            $via = if ($call.Expression -is [System.Management.Automation.Language.VariableExpressionAst]) { ' (via a variable)' } else { '' }
            $memberVia = if ($call.Member -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { ' (member name via a variable)' } else { '' }
            Add-Finding $call 'AC19.DynamicEval' "[scriptblock]::Create$via$memberVia"
        }
    }

    # 3. String concatenation folding to a banned literal (constant-fold only; a runtime value
    #    genuinely cannot be proven either way by static analysis).
    $binaries = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $node.Operator -eq [System.Management.Automation.Language.TokenKind]::Plus -and
        -not ($node.Parent -is [System.Management.Automation.Language.BinaryExpressionAst] -and
              $node.Parent.Operator -eq [System.Management.Automation.Language.TokenKind]::Plus)
    }, $true)
    foreach ($bin in $binaries) {
        $folded = Resolve-PPConstantString $bin
        if (Test-PPBannedNameMatch -Value $folded -BannedNames $bannedCommandNames) {
            Add-Finding $bin 'AC19.DynamicEval' "string concatenation folds to '$folded'"
        }
    }

    # 4. & (Get-Command X) / & (gcm X) resolving to a banned name, wildcards included.
    $ampCalls = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -and
        $node.CommandElements.Count -gt 0 -and
        $node.CommandElements[0] -is [System.Management.Automation.Language.ParenExpressionAst]
    }, $true)
    foreach ($amp in $ampCalls) {
        $paren = $amp.CommandElements[0]
        $inner = $paren.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
        foreach ($innerCmd in $inner) {
            $innerName = $innerCmd.GetCommandName()
            if ($innerName -and ($innerName -iin @('Get-Command', 'gcm'))) {
                $nameArg = $null
                for ($i = 1; $i -lt $innerCmd.CommandElements.Count; $i++) {
                    $el = $innerCmd.CommandElements[$i]
                    if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -ieq 'Name') {
                        if ($i + 1 -lt $innerCmd.CommandElements.Count) { $nameArg = $innerCmd.CommandElements[$i + 1] }
                    } elseif ($el -is [System.Management.Automation.Language.StringConstantExpressionAst] -and -not $nameArg) {
                        $nameArg = $el
                    }
                }
                if ($nameArg -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    (Test-PPBannedNameMatch -Value $nameArg.Value -BannedNames $bannedCommandNames)) {
                    Add-Finding $amp 'AC19.DynamicEval' "'& ($innerName ...)' resolves to banned command '$($nameArg.Value)'"
                }
            }
        }
    }

    # 5. & $var / . $var where $var's value folds to a banned name (not the closed adapter-name
    #    dispatch Test-WorkerClosure.ps1 owns: that operand is a runtime parameter, so it never
    #    folds to a constant here, and is never flagged).
    $dynamicVarCalls = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.CommandAst] -and
        ($node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -or
         $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot) -and
        $node.CommandElements.Count -gt 0 -and
        $node.CommandElements[0] -is [System.Management.Automation.Language.VariableExpressionAst]
    }, $true)
    foreach ($dyn in $dynamicVarCalls) {
        $varName = $dyn.CommandElements[0].VariablePath.UserPath
        $resolved = Resolve-PPVariableConstant -VarName $varName -FileAst $ast -BeforeOffset $dyn.Extent.StartOffset
        if (Test-PPBannedNameMatch -Value $resolved -BannedNames $bannedCommandNames) {
            Add-Finding $dyn 'AC19.DynamicEval' "call through `$$varName resolves to banned command '$resolved'"
        }
    }

    # 6. Set-Alias / New-Alias targeting a banned command.
    $aliasCalls = $commands | Where-Object { $_.GetCommandName() -iin @('Set-Alias', 'New-Alias') }
    foreach ($aliasCmd in $aliasCalls) {
        $valueArg = $null
        $namedValue = $null
        for ($i = 1; $i -lt $aliasCmd.CommandElements.Count; $i++) {
            $el = $aliasCmd.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -ieq 'Value') {
                if ($i + 1 -lt $aliasCmd.CommandElements.Count) { $namedValue = $aliasCmd.CommandElements[$i + 1] }
            }
        }
        if ($namedValue) {
            $valueArg = $namedValue
        } else {
            $positional = @($aliasCmd.CommandElements | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] })
            if ($positional.Count -ge 3) { $valueArg = $positional[2] }
        }
        if ($valueArg) {
            $resolved = if ($valueArg -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $valueArg.Value } else { Resolve-PPConstantString $valueArg }
            if (Test-PPBannedNameMatch -Value $resolved -BannedNames $bannedCommandNames) {
                Add-Finding $aliasCmd 'AC19.DynamicEval' "'$($aliasCmd.GetCommandName())' targets banned command '$resolved'"
            }
        }
    }

    # 7. $ExecutionContext.InvokeCommand - any member.
    $execCmdMembers = $ast.FindAll({
        $node = $args[0]
        ($node -is [System.Management.Automation.Language.MemberExpressionAst]) -and
        $node.Expression -is [System.Management.Automation.Language.MemberExpressionAst] -and
        $node.Expression.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Expression.Member.Value -ieq 'InvokeCommand' -and
        $node.Expression.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Expression.Expression.VariablePath.UserPath -ieq 'ExecutionContext'
    }, $true)
    foreach ($m in $execCmdMembers) {
        $memberName = if ($m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $m.Member.Value } else { '<dynamic>' }
        Add-Finding $m 'AC19.DynamicEval' "`$ExecutionContext.InvokeCommand.$memberName is a dynamic-execution primitive"
    }

    # 8. Generic dangerous members on any object: InvokeScript, AddScript, CreatePipeline.
    $dangerousMembers = $ast.FindAll({
        $node = $args[0]
        ($node -is [System.Management.Automation.Language.MemberExpressionAst]) -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        ($dangerousMemberNames -icontains $node.Member.Value)
    }, $true)
    foreach ($m in $dangerousMembers) {
        Add-Finding $m 'AC19.DynamicEval' ".$($m.Member.Value)( is a dynamic-execution primitive"
    }

    $local
}

# --- function: drive writes (literal, and via a variable path), merged into one offset list. ---
function Find-PPFunctionDriveWriteOffset {
    param($Ast, [string] $Text)

    $offsets = New-Object System.Collections.Generic.List[int]

    $literalPattern = '(Set-Item|New-Item)\b[^\r\n]*?[''"]?function:|\$\{?function:\w'
    foreach ($m in [regex]::Matches($Text, $literalPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $offsets.Add($m.Index)
    }

    $pathWrites = $Ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.CommandAst] -and
        ($node.GetCommandName() -iin @('Set-Item', 'New-Item'))
    }, $true)
    foreach ($cmd in $pathWrites) {
        $pathArg = $null
        for ($i = 1; $i -lt $cmd.CommandElements.Count; $i++) {
            $el = $cmd.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and
                ($el.ParameterName -iin @('Path', 'LiteralPath'))) {
                if ($i + 1 -lt $cmd.CommandElements.Count) { $pathArg = $cmd.CommandElements[$i + 1] }
                break
            }
        }
        if (-not $pathArg) {
            $positional = @($cmd.CommandElements | Where-Object { $_ -isnot [System.Management.Automation.Language.CommandParameterAst] })
            if ($positional.Count -ge 2) { $pathArg = $positional[1] }
        }
        if ($pathArg -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $resolved = Resolve-PPVariableConstant -VarName $pathArg.VariablePath.UserPath -FileAst $Ast -BeforeOffset $cmd.Extent.StartOffset
            if ($resolved -and $resolved.Trim() -match '(?i)^function:') {
                $offsets.Add($cmd.Extent.StartOffset)
            }
        }
    }

    ($offsets | Sort-Object -Unique)
}

function Find-PPPipelineScriptBlockFinding {
    <#
        ForEach-Object/Where-Object (and their aliases %/?/where) are allowed only when every
        scriptblock-bearing argument is an inline literal `{ ... }` written at the call site -
        `-Process`/`-FilterScript`/`-Begin`/`-End`, or the positional slot when no such parameter
        name is present. src/ already calls both this way today (every existing use is a literal
        block), so this narrower rule was chosen over rewriting to foreach/if.
    #>
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $pipelineNames = @('ForEach-Object', '%', 'Where-Object', '?', 'where')
    $scriptParamNames = @('Process', 'FilterScript', 'Begin', 'End', 'Action')

    $commands = $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.CommandAst] -and
        ($pipelineNames -icontains $args[0].GetCommandName())
    }, $true)

    foreach ($cmd in $commands) {
        $scriptArgs = New-Object System.Collections.Generic.List[object]
        $skipNext = $false
        for ($i = 1; $i -lt $cmd.CommandElements.Count; $i++) {
            $el = $cmd.CommandElements[$i]
            if ($skipNext) { $skipNext = $false; continue }
            if ($el -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($scriptParamNames -icontains $el.ParameterName) {
                    if ($i + 1 -lt $cmd.CommandElements.Count) { $scriptArgs.Add($cmd.CommandElements[$i + 1]) }
                }
                $skipNext = $true
                continue
            }
            $scriptArgs.Add($el)
        }
        foreach ($sa in $scriptArgs) {
            if ($sa -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
                $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.PipelineScriptBlock' `
                    -Text "'$($cmd.GetCommandName())' argument '$($sa.Extent.Text)' is not an inline scriptblock literal" -Root $Root))
            }
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

$allFiles = Get-PPSourceFile -Root $Root -Dirs @('src', 'dist')
$definedFunctionNames = Get-PPDefinedFunctionName -Root $Root
# Union with settings/DeclaredFunctions.psd1 so a forward reference to a function declared but not
# yet defined in this file is not a false "not on the allowlist" finding.
foreach ($n in (Get-PPDeclaredFunctionName)) { [void] $definedFunctionNames.Add($n) }
$allowedCommandNames = Get-PPAllowedCommandSet
$allowedTypeData = Get-PPAllowedTypeData

foreach ($file in $allFiles) {
    foreach ($f in (Find-PPLiteralTokenFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPAstDynamicEvalFinding -Path $file -Root $Root)) { $findings.Add($f) }
    # Posture bans (classes 2-6, 8, 11-14 above; shared with Test-ResolverIsolation.ps1 for classes
    # 3, 4, 11, 12).
    foreach ($f in (Find-PPScriptBlockConversionFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPComputedMemberFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPReflectionFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPDynamicCommandFinding -Path $file -Root $Root -SchedulerFileName $schedulerFileName)) { $findings.Add($f) }
    foreach ($f in (Find-PPScriptBlockParameterFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPPipelineScriptBlockFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPStaticMemberOnVariableFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPAsTypeCastFinding -Path $file -Root $Root)) { $findings.Add($f) }
    # Allowlists (command and type, items A and B above).
    foreach ($f in (Find-PPCommandAllowlistFinding -Path $file -Root $Root -DefinedFunctionNames $definedFunctionNames -AllowedCommandNames $allowedCommandNames)) { $findings.Add($f) }
    foreach ($f in (Find-PPTypeAllowlistFinding -Path $file -Root $Root -TypeData $allowedTypeData)) { $findings.Add($f) }
    foreach ($f in (Find-PPAdapterNameAssignmentFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPProviderDriveWriteFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPComparisonCastFinding -Path $file -Root $Root)) { $findings.Add($f) }
}

# --- The two scoped allowances ---

# SessionStateFunctionEntry: allowed only in 40-Scheduler.ps1. Checked per
# match, from that match's own offset via Get-PPOwningLeaf, not once for the whole file - in
# dist/PortProof.ps1 every part shares the one file name PortProof.ps1, so a whole-file check could
# not tell 40-Scheduler.ps1's own concatenated segment apart from any other part's.
foreach ($file in $allFiles) {
    $text = Get-PPStrippedText -Path $file
    $hits = [regex]::Matches($text, 'SessionStateFunctionEntry')
    foreach ($m in $hits) {
        if ((Get-PPOwningLeaf -Path $file -Offset $m.Index) -ine $schedulerFileName) {
            $line = Get-PPLineNumber -Text $text -Offset $m.Index
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC19.FunctionEntryScope' `
                -Text 'SessionStateFunctionEntry appears outside 40-Scheduler.ps1' -Root $Root))
        }
    }

    if ((Split-Path -Leaf (Split-Path -Parent $file)) -ieq 'dist' -and [System.IO.Path]::GetFileName($file) -ieq 'PortProof.ps1') {
        foreach ($f in (Get-PPDistPartMapMissingFinding -Path $file -Root $Root)) { $findings.Add($f) }
    }
}

# function: drive writes: allowed only in 40-Scheduler.ps1, exactly one, inside -Parallel, fed
# only from a variable assigned only by Get-PPWorkerDefinition. Each write
# offset's OWN owning leaf (Get-PPOwningLeaf) decides which bucket it falls in - never a single
# whole-file leaf check - for the same dist/PortProof.ps1 reason as the SessionStateFunctionEntry
# check above.
foreach ($file in $allFiles) {
    $text = Get-PPStrippedText -Path $file
    $result = Get-PPAst -Path $file
    $ast = $result.Ast
    $allOffsets = Find-PPFunctionDriveWriteOffset -Ast $ast -Text $text
    $outsideOffsets = @($allOffsets | Where-Object { (Get-PPOwningLeaf -Path $file -Offset $_) -ine $schedulerFileName })
    $offsets = @($allOffsets | Where-Object { (Get-PPOwningLeaf -Path $file -Offset $_) -ieq $schedulerFileName })

    foreach ($offset in $outsideOffsets) {
        $line = Get-PPLineNumber -Text $text -Offset $offset
        $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC19.FunctionWriteScope' `
            -Text 'function: drive write outside 40-Scheduler.ps1' -Root $Root))
    }

    if ($offsets.Count -eq 0) { continue }
    if ($offsets.Count -gt 1) {
        $line = Get-PPLineNumber -Text $text -Offset $offsets[0]
        $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC19.FunctionWriteCount' `
            -Text "expected exactly one function: write in 40-Scheduler.ps1, found $($offsets.Count)" -Root $Root))
    }

    $parallelBlocks = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.CommandAst] -and
        ($node.GetCommandName() -in @('ForEach-Object', '%')) -and
        ($node.CommandElements | Where-Object {
            $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ieq 'Parallel'
        })
    }, $true)

    $parallelExtents = foreach ($p in $parallelBlocks) {
        $p.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.ScriptBlockExpressionAst] } |
            ForEach-Object { $_.Extent }
    }

    foreach ($absOffset in $offsets) {
        $insideParallel = $false
        foreach ($ext in $parallelExtents) {
            if ($absOffset -ge $ext.StartOffset -and $absOffset -lt $ext.EndOffset) { $insideParallel = $true; break }
        }
        if (-not $insideParallel) {
            $line = Get-PPLineNumber -Text $text -Offset $absOffset
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC19.FunctionWriteLocation' `
                -Text 'function: write is not inside the -Parallel scriptblock' -Root $Root))
        }

        # The value must trace to $using:<var>; the $using: reference need not be on the same
        # source line as the write itself (the idiom loops `foreach ($d in $using:defs...)` around
        # the write), so search the whole enclosing -Parallel block.
        $enclosingParallel = $parallelExtents | Where-Object { $absOffset -ge $_.StartOffset -and $absOffset -lt $_.EndOffset } | Select-Object -First 1
        $usingVars = @()
        if ($enclosingParallel) {
            $usingMatches = [regex]::Matches($text.Substring($enclosingParallel.StartOffset, $enclosingParallel.EndOffset - $enclosingParallel.StartOffset), '\$using:(\w+)')
            $usingVars = $usingMatches | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        }
        if ($usingVars.Count -eq 0) {
            $line = Get-PPLineNumber -Text $text -Offset $absOffset
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC19.FunctionWriteSource' `
                -Text 'function: write value does not trace to a $using: reference' -Root $Root))
        } else {
            foreach ($varName in $usingVars) {
                $assignments = $ast.FindAll({
                    $node = $args[0]
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $node.Left.VariablePath.UserPath -ieq $varName
                }, $true)
                if ($assignments.Count -eq 0) {
                    $findings.Add((Format-PPFinding -Path $file -Line 1 -Rule 'AC19.FunctionWriteSource' `
                        -Text "`$$varName is never assigned in this file (expected: only from Get-PPWorkerDefinition)" -Root $Root))
                }
                foreach ($a in $assignments) {
                    if ($a.Right -is [System.Management.Automation.Language.CommandExpressionAst]) {
                        $inner = $a.Right.Expression
                    } else { $inner = $a.Right }
                    $rhsCommands = @($inner)
                    if ($inner -isnot [System.Management.Automation.Language.CommandAst]) {
                        $rhsCommands = $a.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
                    }
                    $ok = $false
                    foreach ($rc in $rhsCommands) {
                        if ($rc.GetCommandName() -ieq 'Get-PPWorkerDefinition') { $ok = $true }
                    }
                    if (-not $ok) {
                        $line = Get-PPLineNumber -Text $text -Offset $a.Extent.StartOffset
                        $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC19.FunctionWriteSource' `
                            -Text "`$$varName assigned from something other than Get-PPWorkerDefinition" -Root $Root))
                    }
                }
            }
        }
    }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
