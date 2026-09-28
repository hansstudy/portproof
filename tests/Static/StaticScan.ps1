# PortProof static-scan shared helpers.
#
# Dot-sourced by every scanner in this folder. Defines functions only; no top-level side effects.
# Every scanner is standalone (`param([string] $Root)`, exit 0 clean / 1 findings, one finding per
# line `path:line: rule: text`) and also runnable in-process from Static.Tests.ps1.

function Get-PPStaticRepoRoot {
    <# Two levels up from tests/Static: the repo root (system/portproof). #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
}

function Get-PPAst {
    <# Parses one file and returns its Ast, full Tokens (including comments) and ParseErrors. #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Path)

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref] $tokens, [ref] $errors)
    [pscustomobject]@{
        PSTypeName = 'PortProof.Static.AstResult'
        Ast        = $ast
        Tokens     = $tokens
        Errors     = $errors
    }
}

function Get-PPCodeTokens {
    <#
        The tokenizer with comments removed - including comment-based help, since a block comment
        or a line comment is a single Comment-kind token regardless of what it contains. String
        contents are kept (a token's textual content, not its meaning, is what every scanner in
        this folder cares about).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Name kept fixed on purpose; renaming it would break the documented contract every scanner in this folder relies on.')]
    [CmdletBinding()]
    [OutputType([System.Management.Automation.Language.Token[]])]
    param([Parameter(Mandatory)] [string] $Path)

    $result = Get-PPAst -Path $Path
    @($result.Tokens | Where-Object { $_.Kind -ne [System.Management.Automation.Language.TokenKind]::Comment })
}

function Get-PPStrippedText {
    <#
        Raw file text with every comment token's span blanked out (spaces; newlines kept), so a
        line-numbered regex match against the result still points at the right source line, and a
        token that appears only inside a comment (or comment-based help) cannot match. String
        literal content is untouched, so a token inside a string still matches where a rule wants
        that (several ACs are explicit that help text describing an absent feature is not a
        finding, but do not exempt string content in general).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)

    $text = [System.IO.File]::ReadAllText($Path)
    if ($text.Length -eq 0) { return $text }
    $result = Get-PPAst -Path $Path
    $chars = $text.ToCharArray()
    foreach ($tok in $result.Tokens) {
        if ($tok.Kind -eq [System.Management.Automation.Language.TokenKind]::Comment) {
            $start = $tok.Extent.StartOffset
            $end = [Math]::Min($tok.Extent.EndOffset, $chars.Length)
            for ($i = $start; $i -lt $end; $i++) {
                if ($chars[$i] -ne "`n" -and $chars[$i] -ne "`r") { $chars[$i] = ' ' }
            }
        }
    }
    -join $chars
}

function Get-PPSourceFile {
    <# Every file with one of $Extensions under each of $Dirs (relative to $Root) that exists. #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [string[]] $Dirs = @('src', 'dist'),
        [string[]] $Extensions = @('.ps1', '.psm1')
    )

    $files = New-Object System.Collections.Generic.List[string]
    foreach ($d in $Dirs) {
        $full = Join-Path $Root $d
        if (Test-Path -LiteralPath $full -PathType Container) {
            Get-ChildItem -LiteralPath $full -Recurse -File |
                Where-Object { $Extensions -contains $_.Extension } |
                Sort-Object FullName |
                ForEach-Object { $files.Add($_.FullName) }
        }
    }
    $files.ToArray()
}

function Format-PPFinding {
    <# `path:line: rule: text`, path relative to $Root when possible (readable output, stable
       across machines). #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [int] $Line,
        [Parameter(Mandatory)] [string] $Rule,
        [Parameter(Mandatory)] [string] $Text,
        [string] $Root
    )

    $shown = $Path
    if ($Root) {
        try {
            $rootFull = (Resolve-Path -LiteralPath $Root -ErrorAction Stop).ProviderPath.TrimEnd('\', '/')
            if ($Path.StartsWith($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
                $shown = $Path.Substring($rootFull.Length).TrimStart('\', '/')
            }
        } catch {
            $null = $_
        }
    }
    '{0}:{1}: {2}: {3}' -f $shown, $Line, $Rule, $Text
}

function Get-PPLineNumber {
    <# 1-based line number of a character offset into $Text. #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Offset)

    $capped = [Math]::Min($Offset, $Text.Length)
    $slice = $Text.Substring(0, $capped)
    ($slice.ToCharArray() | Where-Object { $_ -eq "`n" } | Measure-Object).Count + 1
}

function Get-PPDistPartMap {
    <#
        dist/PortProof.ps1 is one file concatenated by
        build/Build-PortProof.ps1 from the parts build/parts.txt lists, in order. Build-PortProof.ps1
        emits a banner line '# ---- <src/part.ps1 path> ----' before every part after the first (its
        own join loop: `[void]$builder.Append('# ---- ' + $parts[$i] + " ----`n")` when `$i -gt 0`) -
        never before the first part. That banner is the one reliable, build-guaranteed marker this
        scanner can use to map a dist/ line back to its original src/ file; build/parts.txt's own
        first listed entry (read fresh here, never hardcoded) names the un-bannered leading segment.

        Returns an ordered array of @{ StartOffset; EndOffset; SourceLeaf } segments (character
        offsets into the file's own raw text, EndOffset exclusive) covering the whole file, or $null
        when $Path is not a dist/PortProof.ps1, when build/parts.txt cannot be found or names no
        part, or when the file's raw text carries no banner at all (a single-part build, or a build
        tool that stopped emitting them - the "no reliable marker" case is reported explicitly
        rather than guessed through). Callers must treat $null as "fall back to whole-file scoping by
        the dist leaf itself" (which denies every scoped allowance, since 'PortProof.ps1' matches no
        scoped file name) - never as "everything is allowed".

        Always reads the file's own raw bytes itself (never a caller's comment-stripped text): the
        banner is itself a '#' comment, so a caller's own Get-PPStrippedText result would blank it
        out and make it unfindable. Cached per $Path for the life of the process - the map for a
        given built file cannot change mid-scan.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path)

    $leaf = [System.IO.Path]::GetFileName($Path)
    $parentDir = Split-Path -Leaf (Split-Path -Parent $Path)
    if ($leaf -ine 'PortProof.ps1' -or $parentDir -ine 'dist') { return $null }

    if ($null -eq $script:PPDistPartMapCache) { $script:PPDistPartMapCache = @{} }
    if ($script:PPDistPartMapCache.ContainsKey($Path)) { return $script:PPDistPartMapCache[$Path] }

    $mapResult = $null
    for ($once = 0; $once -lt 1; $once++) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { break }
        # dist/PortProof.ps1's own parent's parent is the repo root (the mirror image of
        # Get-PPStaticRepoRoot's "two levels up from tests/Static").
        $root = Split-Path -Parent (Split-Path -Parent $Path)
        $partsPath = Join-Path $root 'build\parts.txt'
        if (-not (Test-Path -LiteralPath $partsPath -PathType Leaf)) { break }

        $partNames = New-Object System.Collections.Generic.List[string]
        foreach ($line in ([System.IO.File]::ReadAllText($partsPath) -split "`r?`n")) {
            $entry = $line.Trim()
            if ($entry.Length -eq 0 -or $entry.StartsWith('#', [System.StringComparison]::Ordinal)) { continue }
            if ($entry -match '^src/(.+\.ps1)$') { [void] $partNames.Add($Matches[1]) }
        }
        if ($partNames.Count -eq 0) { break }

        $rawText = [System.IO.File]::ReadAllText($Path)
        $bannerRegex = [regex] '(?m)^# ---- src/([A-Za-z0-9._-]+\.ps1) ----\r?$'
        $bannerMatches = @($bannerRegex.Matches($rawText))
        if ($bannerMatches.Count -eq 0) { break }

        $segments = New-Object System.Collections.Generic.List[hashtable]
        [void] $segments.Add(@{ StartOffset = 0; EndOffset = $bannerMatches[0].Index; SourceLeaf = $partNames[0] })
        for ($i = 0; $i -lt $bannerMatches.Count; $i++) {
            $start = $bannerMatches[$i].Index
            $end = if ($i + 1 -lt $bannerMatches.Count) { $bannerMatches[$i + 1].Index } else { $rawText.Length }
            [void] $segments.Add(@{ StartOffset = $start; EndOffset = $end; SourceLeaf = $bannerMatches[$i].Groups[1].Value })
        }
        $mapResult = $segments.ToArray()
    }

    $script:PPDistPartMapCache[$Path] = $mapResult
    $mapResult
}

function Get-PPOwningLeaf {
    <#
        The file leaf that "owns" $Offset in $Path, for every file-scoped allowance in this folder:
        $Path's own leaf normally, or the original src/ part leaf when
        $Path is the concatenated dist/PortProof.ps1, resolved through Get-PPDistPartMap. Falls back
        to $Path's own leaf ('PortProof.ps1', which matches no scoped file name, so every scoped
        allowance is correctly denied rather than guessed at) when no part map is available. $Offset
        is valid whether taken from the file's raw text or from Get-PPStrippedText's result (comment
        spans are blanked, not removed, so offsets are identical between the two).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [int] $Offset)

    $leaf = [System.IO.Path]::GetFileName($Path)
    $parentDir = Split-Path -Leaf (Split-Path -Parent $Path)
    if ($leaf -ine 'PortProof.ps1' -or $parentDir -ine 'dist') { return $leaf }

    $map = Get-PPDistPartMap -Path $Path
    if (-not $map) { return $leaf }
    foreach ($seg in $map) {
        if ($Offset -ge $seg.StartOffset -and $Offset -lt $seg.EndOffset) { return $seg.SourceLeaf }
    }
    $leaf
}

function Get-PPDistPartMapMissingFinding {
    <#
        "If no reliable marker exists, stop and report" - one visible
        finding when $Path is dist/PortProof.ps1 and Get-PPDistPartMap could not build a part map
        for it (build/parts.txt missing/empty, or no banner found in the file). Every file-scoped
        allowance already falls back to denied in that case (Get-PPOwningLeaf), so this is a
        visibility flag on top of that fallback, not a second gate - without it, a broken build
        marker would just look like a wall of ordinary posture findings, not a distinct build defect.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $leaf = [System.IO.Path]::GetFileName($Path)
    $parentDir = Split-Path -Leaf (Split-Path -Parent $Path)
    if ($leaf -ine 'PortProof.ps1' -or $parentDir -ine 'dist') { return @() }
    if (Get-PPDistPartMap -Path $Path) { return @() }
    @((Format-PPFinding -Path $Path -Line 1 -Rule 'Static.DistPartMapMissing' `
        -Text 'no build/parts.txt, or no src/<part>.ps1 banner found in dist/PortProof.ps1 - every file-scoped allowance denies by default for this build' -Root $Root))
}

function Resolve-PPConstantString {
    <#
        Best-effort compile-time fold of a chain of string-literal concatenations (`'a' + 'b'`,
        including through a paren expression). Returns $null the moment any operand is not itself
        foldable, so a variable, a function call or an expandable string with a variable inside it
        stops the fold rather than guessing.
    #>
    [CmdletBinding()]
    param($ExprAst)

    if ($null -eq $ExprAst) { return $null }
    if ($ExprAst -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
        return $ExprAst.Value
    }
    if ($ExprAst -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and
        $ExprAst.NestedExpressions.Count -eq 0) {
        return $ExprAst.Value
    }
    if ($ExprAst -is [System.Management.Automation.Language.ParenExpressionAst]) {
        $elements = @($ExprAst.Pipeline.PipelineElements)
        if ($elements.Count -eq 1 -and $elements[0] -is [System.Management.Automation.Language.CommandExpressionAst]) {
            return Resolve-PPConstantString $elements[0].Expression
        }
        return $null
    }
    if ($ExprAst -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $ExprAst.Operator -eq [System.Management.Automation.Language.TokenKind]::Plus) {
        $left = Resolve-PPConstantString $ExprAst.Left
        if ($null -eq $left) { return $null }
        $right = Resolve-PPConstantString $ExprAst.Right
        if ($null -eq $right) { return $null }
        return $left + $right
    }
    if ($ExprAst -is [System.Management.Automation.Language.CommandExpressionAst]) {
        # An AssignmentStatementAst's .Right (and a few other RHS positions) wrap the real
        # expression in a CommandExpressionAst; unwrap it so a plain `$x = 'Add-Type'` folds too.
        return Resolve-PPConstantString $ExprAst.Expression
    }
    return $null
}

function Resolve-PPVariableConstant {
    <#
        Best-effort: the nearest assignment to $VarName in $FileAst that starts before
        $BeforeOffset, folded via Resolve-PPConstantString. Returns $null when no such assignment
        exists or its value is not foldable (a parameter, a runtime value, or a non-literal source
        - in every one of those cases there is nothing for a static scanner to prove, so no finding
        is raised; that is the same "stop rather than guess" rule Resolve-PPConstantString follows).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'VarName and BeforeOffset are both used inside the closure passed to Ast.FindAll(...); PSScriptAnalyzer does not trace variable capture through a scriptblock argument to a .NET method call.')]
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $VarName, [Parameter(Mandatory)] $FileAst, [Parameter(Mandatory)] [int] $BeforeOffset)

    $assignments = $FileAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $args[0].Left.VariablePath.UserPath -ieq $VarName -and
        $args[0].Extent.StartOffset -lt $BeforeOffset
    }, $true)
    if ($assignments.Count -eq 0) { return $null }
    $last = $assignments | Sort-Object { $_.Extent.StartOffset } | Select-Object -Last 1
    Resolve-PPConstantString $last.Right
}

function Test-PPBannedNameMatch {
    <#
        True when $Value (a resolved argument, itself possibly a wildcard pattern such as
        `Get-Command`'s `-Name`) denotes one of $BannedNames - either exactly, or because $Value
        used as a wildcard pattern matches a banned name (`'i*x' -like 'iex'`-shaped test, giving
        `& (gcm i*x)` the same reach the design's literal-name ban has).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([string] $Value, [Parameter(Mandatory)] [string[]] $BannedNames)

    if ([string]::IsNullOrEmpty($Value)) { return $false }
    foreach ($b in $BannedNames) {
        if ($Value -ieq $b) { return $true }
        if ($b -like $Value) { return $true }
    }
    return $false
}

function Get-PPEnclosingFunction {
    <# The innermost FunctionDefinitionAst in $FileAst whose extent contains $Node, or $null at
       file scope. #>
    [CmdletBinding()]
    param($Node, $FileAst)

    $funcs = $FileAst.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    $funcs |
        Where-Object { $_.Extent.StartOffset -le $Node.Extent.StartOffset -and $_.Extent.EndOffset -ge $Node.Extent.EndOffset } |
        Sort-Object { $_.Extent.EndOffset - $_.Extent.StartOffset } |
        Select-Object -First 1
}

function Get-PPParameterTypeName {
    <# The declared type constraint's full name for parameter $VarName of function $Func (either
       calling form, `function f($x)` or `function f { param($x) }`), or $null when the parameter
       has no type constraint or does not exist - a plain, unproven variable. #>
    [CmdletBinding()]
    [OutputType([string])]
    param($Func, [Parameter(Mandatory)] [string] $VarName)

    if (-not $Func) { return $null }
    $parameters = if ($Func.Parameters) { $Func.Parameters } elseif ($Func.Body.ParamBlock) { $Func.Body.ParamBlock.Parameters } else { @() }
    $p = $parameters | Where-Object { $_.Name.VariablePath.UserPath -ieq $VarName } | Select-Object -First 1
    if (-not $p) { return $null }
    $typeAttr = $p.Attributes | Where-Object { $_ -is [System.Management.Automation.Language.TypeConstraintAst] } | Select-Object -First 1
    if ($typeAttr) { return $typeAttr.TypeName.FullName }
    return $null
}

function Test-PPScriptBlockTypeExpr {
    <#
        True when $ExprAst denotes the [scriptblock] type, directly (a TypeExpressionAst) or one
        indirect hop through a variable assigned that type earlier in the same file (`$t =
        [scriptblock]; ... $t::Create(...)` - the "via a variable" evasion).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($ExprAst, $FileAst)

    if ($null -eq $ExprAst) { return $false }
    if ($ExprAst -is [System.Management.Automation.Language.CommandExpressionAst]) {
        return Test-PPScriptBlockTypeExpr -ExprAst $ExprAst.Expression -FileAst $FileAst
    }
    if ($ExprAst -is [System.Management.Automation.Language.TypeExpressionAst]) {
        $name = $ExprAst.TypeName.FullName
        return ($name -match '(?i)(^|\.)scriptblock$')
    }
    if ($ExprAst -is [System.Management.Automation.Language.ConvertExpressionAst] -and
        $ExprAst.Type.TypeName.Name -ieq 'type') {
        # `[type]"scriptblock"` - a type-by-string cast; the [type] shell around it is itself
        # inert, what matters is whether the folded child string names scriptblock.
        $childName = Resolve-PPConstantString $ExprAst.Child
        return ($null -ne $childName -and $childName -match '(?i)(^|\.)scriptblock$')
    }
    if ($ExprAst -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $ExprAst.Operator -eq [System.Management.Automation.Language.TokenKind]::As -and
        $ExprAst.Right -is [System.Management.Automation.Language.TypeExpressionAst] -and
        $ExprAst.Right.TypeName.Name -ieq 'type') {
        # `"...ScriptBlock" -as [type]` - same idea, the other syntax for it.
        $leftName = Resolve-PPConstantString $ExprAst.Left
        return ($null -ne $leftName -and $leftName -match '(?i)(^|\.)scriptblock$')
    }
    if ($ExprAst -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $varName = $ExprAst.VariablePath.UserPath
        $assignments = $FileAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $args[0].Left.VariablePath.UserPath -ieq $varName -and
            $args[0].Extent.StartOffset -lt $ExprAst.Extent.StartOffset
        }, $true)
        foreach ($a in $assignments) {
            if (Test-PPScriptBlockTypeExpr -ExprAst $a.Right -FileAst $FileAst) { return $true }
        }
    }
    return $false
}

# --- Posture-based bans: whole construct classes banned in src/ and
# dist/, each with only the narrow, named allowances this tool requires. Shared between
# Test-NoDynamicEval.ps1 (AC19) and Test-ResolverIsolation.ps1 (AC11), since a dynamically-named
# member or a reflection call defeats both isolation guarantees the same way. See each scanner's
# own header comment for the exact banned-construct-class list it owns.

function Find-PPComputedMemberFinding {
    <#
        Bans every member access whose member name is not a plain bareword: `.$x` (variable),
        `.($expr)` / `::($expr)` (parenthesized/computed), and `.'literal'` / `."literal"`
        (quoted-string member access) - even a literal quoted name is banned, because the point is
        the *syntax*, not whether this particular occurrence happens to be provably static. Ordinary
        `.Create`, `.Connect(`, `.AddressFamily` (bareword) are untouched.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $members = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.MemberExpressionAst] -or
        $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]
    }, $true)
    foreach ($m in $members) {
        $isBareword = $m.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $m.Member.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::BareWord
        if (-not $isBareword) {
            $line = Get-PPLineNumber -Text $rawText -Offset $m.Extent.StartOffset
            $shape = $m.Member.GetType().Name
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.ComputedMember' `
                -Text "computed or quoted member access '$($m.Extent.Text)' ($shape)" -Root $Root))
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Test-PPIsWorkerDefinitionScope {
    <#
        True when $Node sits inside `Get-PPWorkerDefinition` in `40-Scheduler.ps1` - the one place
        that reads worker definitions only through `Get-Command -CommandType Function` and the
        `.ScriptBlock` property it returns. Both call sites get this same exception, and only this
        one.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] $Node,
        [Parameter(Mandatory)] $FileAst,
        [Parameter(Mandatory)] [string] $Path,
        [string] $SchedulerFileName = '40-Scheduler.ps1',
        [string] $WorkerDefinitionFunctionName = 'Get-PPWorkerDefinition'
    )
    if ((Get-PPOwningLeaf -Path $Path -Offset $Node.Extent.StartOffset) -ine $SchedulerFileName) { return $false }
    $enclosing = Get-PPEnclosingFunction -Node $Node -FileAst $FileAst
    return ($enclosing -and $enclosing.Name -ieq $WorkerDefinitionFunctionName)
}

function Test-PPIsInsideCatchOrTrap {
    <# True when $Node's extent is contained in some CatchClauseAst or TrapStatementAst in
       $FileAst. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Node, [Parameter(Mandatory)] $FileAst)
    $blocks = $FileAst.FindAll({
        $args[0] -is [System.Management.Automation.Language.CatchClauseAst] -or
        $args[0] -is [System.Management.Automation.Language.TrapStatementAst]
    }, $true)
    foreach ($b in $blocks) {
        if ($Node.Extent.StartOffset -ge $b.Extent.StartOffset -and $Node.Extent.EndOffset -le $b.Extent.EndOffset) { return $true }
    }
    return $false
}

function Test-PPIsAllowedGetTypeNameRead {
    <#
        `.GetType().Name`/`.GetType().FullName` is allowed only as a
        terminal property read (nothing chained after `.Name`/`.FullName`), on a receiver of `$_`,
        `$_.Exception`, `$PSItem`, or `$PSItem.Exception`, inside a catch block or trap, and only in
        `90-Main.ps1`. Modelled the same way as the `& $AdapterName` and Get-PPWorkerDefinition
        allowances: a structural, narrowly-scoped exception, not a general permission.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $GetTypeCall, [Parameter(Mandatory)] $FileAst, [Parameter(Mandatory)] [string] $Path)

    if ((Get-PPOwningLeaf -Path $Path -Offset $GetTypeCall.Extent.StartOffset) -ine '90-Main.ps1') { return $false }

    $outer = $GetTypeCall.Parent
    if ($outer -isnot [System.Management.Automation.Language.MemberExpressionAst] -or
        $outer -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) { return $false }
    if (-not ($outer.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
              ($outer.Member.Value -ieq 'Name' -or $outer.Member.Value -ieq 'FullName'))) { return $false }
    if (-not [object]::ReferenceEquals($outer.Expression, $GetTypeCall)) { return $false }

    # Terminal: nothing chained after .Name/.FullName (its result must not itself be the receiver
    # of a further member/invoke).
    $grandparent = $outer.Parent
    if ($grandparent -is [System.Management.Automation.Language.MemberExpressionAst] -and
        [object]::ReferenceEquals($grandparent.Expression, $outer)) { return $false }

    $receiver = $GetTypeCall.Expression
    $isSelf = $receiver -is [System.Management.Automation.Language.VariableExpressionAst] -and
        ($receiver.VariablePath.UserPath -ieq '_' -or $receiver.VariablePath.UserPath -ieq 'PSItem')
    $isExceptionOfSelf = $receiver -is [System.Management.Automation.Language.MemberExpressionAst] -and
        $receiver -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $receiver.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $receiver.Member.Value -ieq 'Exception' -and
        $receiver.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
        ($receiver.Expression.VariablePath.UserPath -ieq '_' -or $receiver.Expression.VariablePath.UserPath -ieq 'PSItem')
    if (-not ($isSelf -or $isExceptionOfSelf)) { return $false }

    Test-PPIsInsideCatchOrTrap -Node $GetTypeCall -FileAst $FileAst
}

function Find-PPReflectionFinding {
    <#
        Bans reflection and the other type/member-introspection primitives outright:
        `.GetMethod(`, `.GetMember(`, `.InvokeMember(`, `.GetType(` (unconditional - not only when
        chained into a further call: reading `.GetType().Name` is exactly as easy a route to
        `.GetType().GetMethod(...)` as writing the chain in one expression, so both are banned the
        same way, except the one allowance below), `.Assembly`, `.Module`, `.InvokeReturnAsIs(`;
        `[Reflection.*]` (any namespace depth) and `[Activator]`/`[System.Activator]`. `.ScriptBlock`
        is banned everywhere except `Get-PPWorkerDefinition` in `40-Scheduler.ps1`
        (Test-PPIsWorkerDefinitionScope), the one place that reads a loaded function's
        own script text back out of a `Get-Command` result. `.Invoke(` is banned with no exception:
        the Scheduler's own mechanism uses `BeginInvoke`/`EndInvoke`, never a synchronous
        `.Invoke(`.

        Allowance: `.GetType().Name`/`.GetType().FullName` is allowed as a terminal read on
        `$_`/`$_.Exception`/`$PSItem`/`$PSItem.Exception`, inside a catch block or trap, only in
        `90-Main.ps1` (Test-PPIsAllowedGetTypeNameRead) - the internal-error message format
        needs exactly this. Any other `.GetType(` use, including that same shape outside a catch/
        trap or outside 90-Main.ps1, or with anything chained after `.Name`/`.FullName`, stays
        banned.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $bannedCallMemberNames = @('GetMethod', 'GetMember', 'InvokeMember', 'InvokeReturnAsIs', 'Invoke')
    $calls = $ast.FindAll({
        $node = $args[0]
        ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        ($bannedCallMemberNames -icontains $node.Member.Value)
    }, $true)
    foreach ($m in $calls) {
        $line = Get-PPLineNumber -Text $rawText -Offset $m.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.Reflection' -Text ".$($m.Member.Value)( is banned (reflection/introspection)" -Root $Root))
    }

    $getTypeCalls = $ast.FindAll({
        $node = $args[0]
        ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Member.Value -ieq 'GetType'
    }, $true)
    foreach ($m in $getTypeCalls) {
        if (Test-PPIsAllowedGetTypeNameRead -GetTypeCall $m -FileAst $ast -Path $Path) { continue }
        $line = Get-PPLineNumber -Text $rawText -Offset $m.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.Reflection' -Text '.GetType( is banned (reflection/introspection)' -Root $Root))
    }

    $bannedPropertyNames = @('Assembly', 'Module')
    $properties = $ast.FindAll({
        $node = $args[0]
        ($node -is [System.Management.Automation.Language.MemberExpressionAst]) -and
        -not ($node -is [System.Management.Automation.Language.InvokeMemberExpressionAst]) -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        ($bannedPropertyNames -icontains $node.Member.Value)
    }, $true)
    foreach ($m in $properties) {
        $line = Get-PPLineNumber -Text $rawText -Offset $m.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.Reflection' -Text ".$($m.Member.Value) is banned (reflection/introspection)" -Root $Root))
    }

    $scriptBlockMembers = $ast.FindAll({
        $node = $args[0]
        ($node -is [System.Management.Automation.Language.MemberExpressionAst]) -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Member.Value -ieq 'ScriptBlock'
    }, $true)
    foreach ($m in $scriptBlockMembers) {
        if (Test-PPIsWorkerDefinitionScope -Node $m -FileAst $ast -Path $Path) { continue }
        $line = Get-PPLineNumber -Text $rawText -Offset $m.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.Reflection' -Text '.ScriptBlock is banned outside Get-PPWorkerDefinition in 40-Scheduler.ps1' -Root $Root))
    }

    $types = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.TypeExpressionAst] }, $true)
    foreach ($t in $types) {
        $full = $t.TypeName.FullName
        if ($full -match '(?i)(^|\.)Reflection\.' -or $full -match '(?i)(^|\.)Activator$') {
            $line = Get-PPLineNumber -Text $rawText -Offset $t.Extent.StartOffset
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.Reflection' -Text "type '$full' is reflection" -Root $Root))
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Find-PPStaticMemberOnVariableFinding {
    <#
        Static member access (`$x::Member`) is banned when the receiver is not a literal
        type expression - `[Type]::Member` (Expression is TypeExpressionAst) is the only allowed
        shape; a variable holding a type (`$t::Create`) is exactly the "type via a variable"
        evasion this closes structurally, on top of Test-PPScriptBlockTypeExpr's narrower
        scriptblock-specific trace.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $staticMembers = $ast.FindAll({
        $node = $args[0]
        ($node -is [System.Management.Automation.Language.MemberExpressionAst]) -and
        $node.Static -and
        $node.Expression -isnot [System.Management.Automation.Language.TypeExpressionAst]
    }, $true)
    foreach ($m in $staticMembers) {
        $line = Get-PPLineNumber -Text $rawText -Offset $m.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.StaticMemberOnVariable' -Text "static member access on a non-literal: '$($m.Extent.Text)'" -Root $Root))
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Find-PPAsTypeCastFinding {
    <#
        `-as [AnyType]` is banned outright, not only `-as [scriptblock]`
        (Find-PPScriptBlockConversionFinding already bans that spelling specifically). `-as` is a
        general type-conversion operator with no legitimate call site anywhere in this tool (every
        real conversion this tool needs is a direct `[Type]$x` cast or a `::Parse`/
        `::TryParse` call), so the operator itself is closed rather than enumerated per target type.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $asBinaries = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $node.Operator -eq [System.Management.Automation.Language.TokenKind]::As -and
        $node.Right -is [System.Management.Automation.Language.TypeExpressionAst]
    }, $true)
    foreach ($b in $asBinaries) {
        $line = Get-PPLineNumber -Text $rawText -Offset $b.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.AsTypeCast' -Text "-as is banned: '$($b.Extent.Text)'" -Root $Root))
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Find-PPScriptBlockConversionFinding {
    <#
        Bans every cast or conversion to the scriptblock type, in any namespace spelling, whether
        or not the result is ever invoked: `[scriptblock]$x`, `$x -as [scriptblock]`,
        `[type]"scriptblock"`, `"...ScriptBlock" -as [type]`. The narrower "via a one-hop variable"
        evasion of `[scriptblock]::Create` (`$t = [scriptblock]; $t::Create(...)`, not a cast at
        all) is Test-PPScriptBlockTypeExpr's job and is unaffected by this function.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)
    $sbPattern = '(?i)(^|\.)scriptblock$'

    $converts = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.ConvertExpressionAst] -and
        $node.Type.TypeName.FullName -match '(?i)(^|\.)scriptblock$'
    }, $true)
    foreach ($c in $converts) {
        $line = Get-PPLineNumber -Text $rawText -Offset $c.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.ScriptBlockConversion' -Text "cast to scriptblock: '$($c.Extent.Text)'" -Root $Root))
    }

    $asBinaries = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $node.Operator -eq [System.Management.Automation.Language.TokenKind]::As -and
        $node.Right -is [System.Management.Automation.Language.TypeExpressionAst] -and
        $node.Right.TypeName.FullName -match '(?i)(^|\.)scriptblock$'
    }, $true)
    foreach ($b in $asBinaries) {
        $line = Get-PPLineNumber -Text $rawText -Offset $b.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.ScriptBlockConversion' -Text "-as [scriptblock]: '$($b.Extent.Text)'" -Root $Root))
    }

    $typeByStringConverts = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.ConvertExpressionAst] -and
        $node.Type.TypeName.Name -ieq 'type'
    }, $true)
    foreach ($c in $typeByStringConverts) {
        $folded = Resolve-PPConstantString $c.Child
        if ($folded -and ($folded -match $sbPattern)) {
            $line = Get-PPLineNumber -Text $rawText -Offset $c.Extent.StartOffset
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.ScriptBlockConversion' -Text "type given as a string: '$($c.Extent.Text)'" -Root $Root))
        }
    }

    $typeByStringAs = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.BinaryExpressionAst] -and
        $node.Operator -eq [System.Management.Automation.Language.TokenKind]::As -and
        $node.Right -is [System.Management.Automation.Language.TypeExpressionAst] -and
        $node.Right.TypeName.Name -ieq 'type'
    }, $true)
    foreach ($b in $typeByStringAs) {
        $folded = Resolve-PPConstantString $b.Left
        if ($folded -and ($folded -match $sbPattern)) {
            $line = Get-PPLineNumber -Text $rawText -Offset $b.Extent.StartOffset
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.ScriptBlockConversion' -Text "type given as a string: '$($b.Extent.Text)'" -Root $Root))
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Test-PPCommandOperandIsOwnParameter {
    <# True when $OperandAst is a plain VariableExpressionAst naming one of $EnclosingFunc's own
       declared parameters. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($OperandAst, $EnclosingFunc)
    if ($OperandAst -isnot [System.Management.Automation.Language.VariableExpressionAst]) { return $false }
    if (-not $EnclosingFunc) { return $false }
    $paramNames = @()
    if ($EnclosingFunc.Parameters) { $paramNames = $EnclosingFunc.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } }
    elseif ($EnclosingFunc.Body.ParamBlock) { $paramNames = $EnclosingFunc.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } }
    $paramNames -icontains $OperandAst.VariablePath.UserPath
}

function Find-PPDynamicCommandFinding {
    <#
        AC19: the command position of an `&`/`.` invocation must be a bareword or a literal string
        (GetCommandName() resolves it); anything else - a variable, a member access, an
        interpolated string, a parenthesized expression - is a dynamic command name and is banned
        outright. Three named allowances exist, each modelled the same way (a specific function, in
        a specific file, dispatching only its own declared parameter) - no other dynamic command
        position is ever permitted:
          1. `40-Scheduler.ps1`, inside `Invoke-PPTargetQueue`, `& $x`/`. $x` where
             `$x` is literally one of that function's own parameters (the adapter name).
          2. `30-Resolver.ps1`, inside `Resolve-PPProbeList`, `& $Resolver.Resolve <arg>`
             where `$Resolver` is that function's own parameter and the member accessed is
             literally, statically `.Resolve` (a bareword, not computed - Find-PPComputedMemberFinding
             already bans any other member-access shape here regardless).
          3. `35-Gate.ps1`, inside `Invoke-PPGate`, `& $OnAdmitted <arg>` where
             `$OnAdmitted` is that function's own parameter.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Root,
        [string] $SchedulerFileName = '40-Scheduler.ps1',
        [string] $SchedulerFunctionName = 'Invoke-PPTargetQueue',
        [string] $ResolverFileName = '30-Resolver.ps1',
        [string] $ResolverFunctionName = 'Resolve-PPProbeList',
        [string] $ResolverParameterName = 'Resolver',
        [string] $GateFileName = '35-Gate.ps1',
        [string] $GateFunctionName = 'Invoke-PPGate'
    )

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $dynCalls = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.CommandAst] -and
        ($node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Ampersand -or
         $node.InvocationOperator -eq [System.Management.Automation.Language.TokenKind]::Dot) -and
        (-not $node.GetCommandName())
    }, $true)

    foreach ($cmd in $dynCalls) {
        $allowed = $false
        $operand = if ($cmd.CommandElements.Count -gt 0) { $cmd.CommandElements[0] } else { $null }
        $enclosing = Get-PPEnclosingFunction -Node $cmd -FileAst $ast
        # The owning leaf is resolved per call, from its own offset, not
        # once for the whole file - in dist/PortProof.ps1 different lines own to different src/
        # parts (Get-PPOwningLeaf/Get-PPDistPartMap).
        $leaf = Get-PPOwningLeaf -Path $Path -Offset $cmd.Extent.StartOffset

        if ($leaf -ieq $SchedulerFileName -and $enclosing -and $enclosing.Name -ieq $SchedulerFunctionName) {
            if (Test-PPCommandOperandIsOwnParameter -OperandAst $operand -EnclosingFunc $enclosing) { $allowed = $true }
        }
        elseif ($leaf -ieq $ResolverFileName -and $enclosing -and $enclosing.Name -ieq $ResolverFunctionName) {
            if ($operand -is [System.Management.Automation.Language.MemberExpressionAst] -and
                $operand -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                $operand.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                $operand.Member.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::BareWord -and
                $operand.Member.Value -ieq 'Resolve' -and
                (Test-PPCommandOperandIsOwnParameter -OperandAst $operand.Expression -EnclosingFunc $enclosing) -and
                $operand.Expression.VariablePath.UserPath -ieq $ResolverParameterName) {
                $allowed = $true
            }
        }
        elseif ($leaf -ieq $GateFileName -and $enclosing -and $enclosing.Name -ieq $GateFunctionName) {
            if (Test-PPCommandOperandIsOwnParameter -OperandAst $operand -EnclosingFunc $enclosing) { $allowed = $true }
        }

        if (-not $allowed) {
            $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.DynamicCommand' -Text "dynamic command position: '$($cmd.Extent.Text)'" -Root $Root))
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Find-PPScriptBlockParameterFinding {
    <#
        AC19: `Start-Job`, `Start-ThreadJob` and `Invoke-Command` are banned outright (no
        legitimate use in a synchronous, single-process tool); `Register-ObjectEvent`/
        `Register-EngineEvent` are banned when called with `-Action`; and, generally, any
        `-ScriptBlock`/`-Action` parameter on any command is banned unless its argument is an
        inline scriptblock literal (`{ ... }`) written at the call site - a variable, however it
        was built, is not.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $outrightBanned = @('Start-Job', 'Start-ThreadJob', 'Invoke-Command')
    $commands = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($cmd in $commands) {
        $name = $cmd.GetCommandName()
        if ($name -and ($outrightBanned -icontains $name)) {
            $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.BackgroundExecution' -Text "banned command '$name'" -Root $Root))
        }

        $hasAction = $cmd.CommandElements | Where-Object {
            $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -ieq 'Action'
        }
        if ($name -and ($name -iin @('Register-ObjectEvent', 'Register-EngineEvent')) -and $hasAction) {
            $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.BackgroundExecution' -Text "'$name' with -Action" -Root $Root))
        }

        for ($i = 1; $i -lt $cmd.CommandElements.Count; $i++) {
            $el = $cmd.CommandElements[$i]
            if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and
                ($el.ParameterName -iin @('ScriptBlock', 'Action'))) {
                $valueArg = if ($i + 1 -lt $cmd.CommandElements.Count) { $cmd.CommandElements[$i + 1] } else { $null }
                if ($valueArg -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                    $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
                    $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.BackgroundExecution' `
                        -Text "-$($el.ParameterName) not bound to an inline scriptblock literal" -Root $Root))
                }
            }
            # Call-site rule: every call to Invoke-PPGate must pass -OnAdmitted as an
            # inline scriptblock literal, or omit it entirely.
            if ($name -ieq 'Invoke-PPGate' -and $el -is [System.Management.Automation.Language.CommandParameterAst] -and
                $el.ParameterName -ieq 'OnAdmitted') {
                $valueArg = if ($i + 1 -lt $cmd.CommandElements.Count) { $cmd.CommandElements[$i + 1] } else { $null }
                if ($valueArg -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst]) {
                    $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
                    $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.BackgroundExecution' `
                        -Text '-OnAdmitted on Invoke-PPGate not bound to an inline scriptblock literal' -Root $Root))
                }
            }
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Get-PPAllowedCommandSet {
    <# Loads settings/AllowedCommands.psd1 into a case-insensitive set of cmdlet names. #>
    [CmdletBinding()]
    param([string] $SettingsPath)
    if (-not $SettingsPath) { $SettingsPath = Join-Path $PSScriptRoot 'settings\AllowedCommands.psd1' }
    $data = Import-PowerShellDataFile -LiteralPath $SettingsPath
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $data.Keys) { [void] $set.Add($k) }
    Write-Output -InputObject $set -NoEnumerate
}

function Get-PPDefinedFunctionName {
    <#
        Every function name defined anywhere in $Root's src/ and dist/. Computed fresh each run -
        the whole point of allowlisting "a function defined in src/" instead of a static name list
        is that it tracks the real, current tree without needing to be hand-edited as it grows.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Root)
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($file in (Get-PPSourceFile -Root $Root -Dirs @('src', 'dist'))) {
        $result = Get-PPAst -Path $file
        $funcs = $result.Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
        foreach ($f in $funcs) { [void] $names.Add($f.Name) }
    }
    Write-Output -InputObject $names -NoEnumerate
}

function Get-PPDeclaredFunctionName {
    <#
        settings/DeclaredFunctions.psd1's keys - functions named for a file that has not landed
        yet. Callers union this with
        Get-PPDefinedFunctionName's real, current result to build the command allowlist's "defined
        function" set, so a forward reference to a not-yet-defined function is not a false finding.
    #>
    [CmdletBinding()]
    param([string] $SettingsPath)
    if (-not $SettingsPath) { $SettingsPath = Join-Path $PSScriptRoot 'settings\DeclaredFunctions.psd1' }
    $data = Import-PowerShellDataFile -LiteralPath $SettingsPath
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $data.Keys) { [void] $set.Add($k) }
    Write-Output -InputObject $set -NoEnumerate
}

function Find-PPCommandAllowlistFinding {
    <#
        Command allowlist: every statically-resolvable command name in src/+dist/ must be
        either a function defined somewhere in src/ ($DefinedFunctionNames) or on the fixed cmdlet
        list ($AllowedCommandNames). A name that does not resolve at all (a dynamic `&`/`.`
        invocation) is not re-reported here - Find-PPDynamicCommandFinding already owns that
        finding, with the one scoped-dispatch exception; this function only judges names that did
        resolve. Get-Command's own narrow exception (Test-PPIsWorkerDefinitionScope) is checked
        here too, since Get-Command is deliberately never on the fixed list. ForEach-Object/
        Where-Object and their aliases (%, ?, where) are exempt from this list check entirely - they
        are governed by their own, stricter, literal-scriptblock-only rule
        (Find-PPPipelineScriptBlockFinding), not by "is the name on the list".
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Root,
        [Parameter(Mandatory)] $DefinedFunctionNames,
        [Parameter(Mandatory)] $AllowedCommandNames
    )

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)
    $pipelineExempt = @('ForEach-Object', '%', 'Where-Object', '?', 'where')

    $commands = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($cmd in $commands) {
        $name = $cmd.GetCommandName()
        if (-not $name) { continue }
        if ($pipelineExempt -icontains $name) { continue }
        if ($DefinedFunctionNames.Contains($name)) { continue }
        if ($AllowedCommandNames.Contains($name)) { continue }
        if ($name -ieq 'Get-Command' -and (Test-PPIsWorkerDefinitionScope -Node $cmd -FileAst $ast -Path $Path)) { continue }
        $line = Get-PPLineNumber -Text $rawText -Offset $cmd.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.CommandAllowlist' -Text "'$name' is not a src/-defined function or an allowlisted cmdlet" -Root $Root))
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Get-PPAllowedTypeData {
    <# Loads settings/AllowedTypes.psd1 (a hashtable with General and Scoped keys). #>
    [CmdletBinding()]
    param([string] $SettingsPath)
    if (-not $SettingsPath) { $SettingsPath = Join-Path $PSScriptRoot 'settings\AllowedTypes.psd1' }
    Import-PowerShellDataFile -LiteralPath $SettingsPath
}

function Get-PPTypeBaseName {
    <# Strips generic arguments (List[string] -> List) and one array suffix (string[] -> string)
       so a TypeName's FullName can be looked up in the allowlist by its base name. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $FullName)
    $name = $FullName
    if ($name.EndsWith('[]')) { $name = $name.Substring(0, $name.Length - 2) }
    $bracket = $name.IndexOf('[')
    if ($bracket -ge 0) { $name = $name.Substring(0, $bracket) }
    $name
}

function Get-PPShortTypeName {
    <# The part of a (base, already generic/array-stripped) type name after its last '.'. #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $BaseName)
    $lastDot = $BaseName.LastIndexOf('.')
    if ($lastDot -ge 0) { $BaseName.Substring($lastDot + 1) } else { $BaseName }
}

function Test-PPTypeNameMatchesKey {
    <# True when a source type's (base, shortName) matches an allowlist $Key by either spelling -
       the allowlist key can be written fully-qualified or short, and so can the source. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Key, [Parameter(Mandatory)] [string] $Base, [Parameter(Mandatory)] [string] $ShortName)
    $keyShort = Get-PPShortTypeName -BaseName $Key
    ($Key -ieq $Base) -or ($Key -ieq $ShortName) -or ($keyShort -ieq $Base) -or ($keyShort -ieq $ShortName)
}

function Find-PPTypeAllowedEntry {
    <#
        Returns @{ Allowed = [bool]; ScopedEntry = <hashtable or $null> } for one type FullName at
        one AST node. $Offset (the node's own StartOffset) is required so a Scoped entry's File is
        checked against that node's owning leaf (Get-PPOwningLeaf), not $Path's own whole-file leaf -
        in dist/PortProof.ps1 a type used in its legitimate src/ part must
        still be recognized as scoped-allowed there, and a type used in the WRONG part must still be
        flagged, neither of which a whole-file "is this dist/PortProof.ps1" check can tell apart.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $FullName, [Parameter(Mandatory)] $TypeData, [Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [int] $Offset)
    $base = Get-PPTypeBaseName -FullName $FullName
    $shortName = Get-PPShortTypeName -BaseName $base

    foreach ($key in $TypeData.General.Keys) {
        if (Test-PPTypeNameMatchesKey -Key $key -Base $base -ShortName $shortName) { return @{ Allowed = $true; ScopedEntry = $null } }
    }
    foreach ($key in $TypeData.Scoped.Keys) {
        if (Test-PPTypeNameMatchesKey -Key $key -Base $base -ShortName $shortName) {
            $entry = $TypeData.Scoped[$key]
            $allowed = ((Get-PPOwningLeaf -Path $Path -Offset $Offset) -ieq $entry.File)
            return @{ Allowed = $allowed; ScopedEntry = $entry }
        }
    }
    return @{ Allowed = $false; ScopedEntry = $null }
}

function Test-PPIsAllowedScriptBlockParameterConstraint {
    <#
        `[scriptblock]` may appear only as the TypeConstraintAst on `Invoke-PPGate`'s
        own `$OnAdmitted` parameter, in `35-Gate.ps1` - never as a cast (`[scriptblock]$x`) or with
        `-as` (both produce a ConvertExpressionAst/BinaryExpressionAst wrapping a TypeExpressionAst,
        never a TypeConstraintAst, so requiring TypeConstraintAst here already excludes them; they
        stay banned everywhere anyway via Find-PPScriptBlockConversionFinding/
        Find-PPAsTypeCastFinding regardless of this function). PowerShell does not convert a string
        argument to a scriptblock-typed parameter (verified empirically), so this narrow constraint
        cannot be used to smuggle a string into becoming code.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] $TypeNode,
        [Parameter(Mandatory)] $FileAst,
        [Parameter(Mandatory)] [string] $Path,
        [string] $GateFileName = '35-Gate.ps1',
        [string] $GateFunctionName = 'Invoke-PPGate',
        [string] $ParameterName = 'OnAdmitted'
    )
    if ($TypeNode -isnot [System.Management.Automation.Language.TypeConstraintAst]) { return $false }
    if ((Get-PPOwningLeaf -Path $Path -Offset $TypeNode.Extent.StartOffset) -ine $GateFileName) { return $false }
    if ($TypeNode.Parent -isnot [System.Management.Automation.Language.ParameterAst]) { return $false }
    if ($TypeNode.Parent.Name.VariablePath.UserPath -ine $ParameterName) { return $false }
    $enclosing = Get-PPEnclosingFunction -Node $TypeNode -FileAst $FileAst
    return ($enclosing -and $enclosing.Name -ieq $GateFunctionName)
}

function Find-PPTypeAllowlistFinding {
    <#
        Type allowlist: every TypeExpressionAst/TypeConstraintAst in src/+dist/ must name a
        type in $TypeData.General (allowed anywhere) or $TypeData.Scoped (allowed only in that
        type's one named file - e.g. TcpClient only in 50-Probe.Tcp.ps1). A network class named in
        Scoped but used in the wrong file, or a type on neither list at all (Socket, anything
        unreviewed), is a finding. `scriptblock` has its own dedicated, parameter-shaped allowance
        (Test-PPIsAllowedScriptBlockParameterConstraint) checked before the general
        list, since it is never simply "allowed in file X" - it is allowed only as one specific
        parameter's type constraint.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root, [Parameter(Mandatory)] $TypeData)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $typeNodes = $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.TypeExpressionAst] -or
        $args[0] -is [System.Management.Automation.Language.TypeConstraintAst]
    }, $true)
    foreach ($t in $typeNodes) {
        $full = $t.TypeName.FullName
        if ($full -match '(?i)(^|\.)scriptblock$' -and (Test-PPIsAllowedScriptBlockParameterConstraint -TypeNode $t -FileAst $ast -Path $Path)) { continue }
        $verdict = Find-PPTypeAllowedEntry -FullName $full -TypeData $TypeData -Path $Path -Offset $t.Extent.StartOffset
        if ($verdict.Allowed) { continue }
        $line = Get-PPLineNumber -Text $rawText -Offset $t.Extent.StartOffset
        if ($verdict.ScopedEntry) {
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.TypeAllowlist' -Text "type '$full' is allowed only in $($verdict.ScopedEntry.File)" -Root $Root))
        } else {
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.TypeAllowlist' -Text "type '$full' is not on the allowlist" -Root $Root))
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Find-PPAdapterNameAssignmentFinding {
    <#
        Tightens the adapter dispatch allowance: the real
        `Invoke-PPTargetQueue` reassigns `$AdapterName` once per queue item
        (`$AdapterName = [string]$item.AdapterName`). Every assignment to `$AdapterName` inside that
        function, in `40-Scheduler.ps1`, must have a right-hand side that traces to trusted adapter
        data - either of two shapes:
          1. An index/property access into the function's own
             `$Adapters` parameter (`$Adapters[...]` or `$Adapters.<literal>`), if that function ever
             declares one.
          2. The shape actually used: `$item.AdapterName` (a bareword property read),
             where `$item` is the loop variable of an enclosing `foreach` whose collection is,
             itself, the function's own `$Queue` parameter - per-item adapter names the CALLER
             (`Invoke-ProbeSchedule`) precomputed from its own `$Adapters` parameter (the header
             comment above `Invoke-PPTargetQueue` says exactly this: "its value is always a name the
             caller took from the -Adapters map").
        A `[cast]` wrapping either shape is unwrapped first. Any other source - a literal, a
        parameter, an unrelated variable - is a finding.

        `$FunctionName` definitions are found across the whole file, then
        filtered to only the ones whose own offset maps (Get-PPOwningLeaf) to `$SchedulerFileName` -
        never by a single whole-file leaf check up front. In dist/PortProof.ps1 the function lives
        inside its own src/ part's concatenated segment; a whole-file check cannot tell that segment
        apart from any other part's.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
        Justification = 'FunctionName is used inside the closure passed to Ast.FindAll(...); PSScriptAnalyzer does not trace variable capture through a scriptblock argument to a .NET method call.')]
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Root,
        [string] $SchedulerFileName = '40-Scheduler.ps1',
        [string] $FunctionName = 'Invoke-PPTargetQueue',
        [string] $VariableName = 'AdapterName'
    )

    $local = New-Object System.Collections.Generic.List[string]

    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    # Find every $FunctionName definition in the file, then keep only the
    # ones whose OWN offset maps (Get-PPOwningLeaf) to $SchedulerFileName - never a whole-file check.
    # In dist/PortProof.ps1 the function lives inside its own src/ part's segment; a whole-file
    # "is this dist/PortProof.ps1" check cannot tell that segment apart from any other.
    $funcs = @($ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].Name -ieq $FunctionName
    }, $true) | Where-Object { (Get-PPOwningLeaf -Path $Path -Offset $_.Extent.StartOffset) -ieq $SchedulerFileName })
    if ($funcs.Count -eq 0) { Write-Output -InputObject $local.ToArray() -NoEnumerate; return }

    $assignments = New-Object System.Collections.Generic.List[object]
    foreach ($func in $funcs) {
        $paramNames = @()
        if ($func.Parameters) { $paramNames = $func.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } }
        elseif ($func.Body.ParamBlock) { $paramNames = $func.Body.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath } }

        foreach ($a in $func.FindAll({
            $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $args[0].Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $args[0].Left.VariablePath.UserPath -ieq $VariableName
        }, $true)) {
            [void] $assignments.Add(@{ Assignment = $a; ParamNames = $paramNames; Func = $func })
        }
    }

    foreach ($entry in $assignments) {
        $a = $entry.Assignment
        $paramNames = $entry.ParamNames
        $func = $entry.Func
        $rhs = $a.Right
        if ($rhs -is [System.Management.Automation.Language.CommandExpressionAst]) { $rhs = $rhs.Expression }
        if ($rhs -is [System.Management.Automation.Language.ConvertExpressionAst]) { $rhs = $rhs.Child }

        $ok = $false

        # Shape 1: $Adapters[...] / $Adapters.<literal>, $Adapters being this function's own param.
        if (($rhs -is [System.Management.Automation.Language.IndexExpressionAst]) -or
            ($rhs -is [System.Management.Automation.Language.MemberExpressionAst] -and
             $rhs -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
             $rhs.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
             $rhs.Member.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::BareWord)) {
            if ($rhs.Target -is [System.Management.Automation.Language.VariableExpressionAst]) { $base = $rhs.Target }
            elseif ($rhs.Expression -is [System.Management.Automation.Language.VariableExpressionAst]) { $base = $rhs.Expression }
            else { $base = $null }
            if ($base -and $base.VariablePath.UserPath -ieq 'Adapters' -and ($paramNames -icontains 'Adapters')) { $ok = $true }
        }

        # Shape 2: $item.AdapterName, $item bound by an enclosing foreach over this function's own
        # parameter (Queue, in the shape actually used - checked generically as "any of this
        # function's own parameters" so the check does not need to hardcode the parameter name).
        if (-not $ok -and
            $rhs -is [System.Management.Automation.Language.MemberExpressionAst] -and
            $rhs -isnot [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
            $rhs.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $rhs.Member.StringConstantType -eq [System.Management.Automation.Language.StringConstantType]::BareWord -and
            $rhs.Member.Value -ieq $VariableName -and
            $rhs.Expression -is [System.Management.Automation.Language.VariableExpressionAst]) {

            $loopVarName = $rhs.Expression.VariablePath.UserPath
            $enclosingLoop = $func.FindAll({
                $args[0] -is [System.Management.Automation.Language.ForEachStatementAst] -and
                $args[0].Variable -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $args[0].Variable.VariablePath.UserPath -ieq $loopVarName -and
                $args[0].Extent.StartOffset -le $a.Extent.StartOffset -and
                $args[0].Extent.EndOffset -ge $a.Extent.EndOffset
            }, $true) | Sort-Object { $_.Extent.EndOffset - $_.Extent.StartOffset } | Select-Object -First 1

            if ($enclosingLoop -and $enclosingLoop.Condition -is [System.Management.Automation.Language.PipelineAst]) {
                $elements = @($enclosingLoop.Condition.PipelineElements)
                if ($elements.Count -eq 1 -and $elements[0] -is [System.Management.Automation.Language.CommandExpressionAst] -and
                    $elements[0].Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    ($paramNames -icontains $elements[0].Expression.VariablePath.UserPath)) {
                    $ok = $true
                }
            }
        }

        if (-not $ok) {
            $line = Get-PPLineNumber -Text $rawText -Offset $a.Extent.StartOffset
            $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.AdapterNameSource' -Text "`$$VariableName assignment does not trace to trusted adapter data: '$($a.Extent.Text)'" -Root $Root))
        }
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Find-PPProviderDriveWriteFinding {
    <#
        Provider-drive write tightening: `Set-Item`/`New-Item` may target the `variable:`, `alias:` or
        `env:` drive nowhere in src/ or dist/ - none has a legitimate use anywhere in this tool, and
        each is its own well-known evasion (defining a variable/alias to redirect a later call, or
        setting an environment variable another process trusts). This is independent of, and in
        addition to, the existing `function:`-drive scoping (Find-PPFunctionDriveWriteOffset in
        Test-NoDynamicEval.ps1): that logic only ever looks for the literal text `function:`, so it
        would not previously have noticed a `variable:`/`alias:`/`env:` write at all.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $text = Get-PPStrippedText -Path $Path
    $pattern = '(Set-Item|New-Item)\b[^\r\n]*?[''"]?(variable|alias|env):'
    foreach ($m in [regex]::Matches($text, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $line = Get-PPLineNumber -Text $text -Offset $m.Index
        $driveName = $m.Groups[2].Value
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.ProviderDriveWrite' -Text "write to the ${driveName}: drive: matched '$($m.Value)'" -Root $Root))
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}

function Find-PPComparisonCastFinding {
    <#
        A `[System.Comparison[...]]` cast is allowed only when its operand
        is an inline `ScriptBlockExpressionAst` literal (`[System.Comparison[object]] { ... }`, the
        shape 90-Main.ps1 already uses for `List.Sort(...)`, its own normative row ordering). Casting a
        variable or any other expression to a Comparison delegate is a finding: nothing stops that
        variable from holding a dynamically-built scriptblock reached some other way, and there is
        no legitimate reason to build the comparer anywhere but inline at the call site.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $Path, [string] $Root)

    $local = New-Object System.Collections.Generic.List[string]
    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $casts = $ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.ConvertExpressionAst] -and
        (Get-PPTypeBaseName -FullName $args[0].Type.TypeName.FullName) -match '(?i)(^|\.)Comparison$'
    }, $true)
    foreach ($c in $casts) {
        if ($c.Child -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { continue }
        $line = Get-PPLineNumber -Text $rawText -Offset $c.Extent.StartOffset
        $local.Add((Format-PPFinding -Path $Path -Line $line -Rule 'Posture.ComparisonCast' -Text "System.Comparison cast operand is not an inline scriptblock literal: '$($c.Extent.Text)'" -Root $Root))
    }
    Write-Output -InputObject $local.ToArray() -NoEnumerate
}
