<#
    .SYNOPSIS
        AC11 (4) - the Resolver seam is the only door to name resolution or a string-host network
        call. An allowlist, not a blocklist, layered on top of a construct-class posture that stays
        on as a second layer.

    .DESCRIPTION
        Scope and limits: this is a static allowlist check over our own committed source, run at
        build/CI time. It is not a proof against a determined insider with commit access - someone
        who can edit src/ can also edit this scanner or its settings files. What it does buy: every
        command and type src/ and dist/ can name is a short, reviewed, one-line-justified list, so
        a change that adds a new command or type is visible in review as a settings-file diff, not
        buried in a 500-line source file. The backstop for what a reviewed allowlist entry might
        still let through is the independent pre-release security review, not this scanner.

        An earlier blocklist posture kept finding new bypasses: a
        hashtable-splatted `New-Object @p`, a dynamic `-TypeName` variable, `'...TcpClient' -as
        [type]` then `$t::new(...)`, `.Assembly.GetType('...TcpClient')` then the same. Blocklists
        cannot be complete in PowerShell. Shared with Test-NoDynamicEval.ps1:
        since everything in src/ and dist/ is code we wrote, the default is inverted with two
        allowlists (see that scanner's header for the full rationale and the exact file format):

          A. COMMAND ALLOWLIST (`settings/AllowedCommands.psd1`) - every command name must be a
             function defined in src/ or on the fixed cmdlet list. `New-Object` is never on that
             list (class 2 below is now enforced twice: as an outright ban, and structurally, by
             its absence from the one list that would let it resolve at all).
          B. TYPE ALLOWLIST (`settings/AllowedTypes.psd1`) - every type reference must be in
             General (anywhere) or Scoped (one named file) - `TcpClient` only in
             `50-Probe.Tcp.ps1`, `UdpClient` only in `55-Probe.Udp.ps1`, `Socket` on neither list at
             all (this tool never constructs one, so it has no allowed file - this scanner's own
             class-3 rule below already enforces the same restriction independently for
             `::new(...)` specifically; the type allowlist closes it for every other reference
             shape too, e.g. a bare `[Socket]` type-expression with no construction at all).

        The construct-class bans stay on as a second, independent layer, plus two more classes
        below (shared with Test-NoDynamicEval.ps1 - see that scanner for the exact rule):

        Banned construct classes (this scanner's authoritative list - cite this section, not the
        addenda below, when documenting the posture elsewhere):

          1. Resolving tokens (comment-stripped): `System.Net.Dns`, `[Net.Dns]`, `GetHostEntry`,
             `GetHostAddresses`, `GetHostByName`, `BeginGetHostAddresses`, `Resolve-DnsName`,
             `Test-Connection`, `Test-NetConnection` - only in `30-Resolver.ps1`. The count of each
             in `dist/PortProof.ps1` must equal its count in `30-Resolver.ps1` (a build cannot
             duplicate or drop resolving code on the way in).
          2. `New-Object`, in every shape (positional, `-ArgumentList`, splatted, dynamic
             `-TypeName`) - banned entirely, everywhere in src/ and dist/. The one constructor idiom
             this tool uses is `[Type]::new(...)`; `New-Object` has no legitimate call site at all,
             so nothing narrower than an outright ban survives a splatted argument list or a
             `-TypeName` held in a variable (both defeat any check that inspects `New-Object`'s own
             arguments instead of banning the command).
          3. Construction of `TcpClient`/`UdpClient`/`Socket` via `[Type]::new(...)` - allowed only
             in the one designated file for each class (`TcpClient` in `50-Probe.Tcp.ps1`, `UdpClient`
             in `55-Probe.Udp.ps1`; `Socket` is never constructed anywhere, so it
             has no allowed file) - and only with provably typed arguments: an `AddressFamily`-shaped
             expression, a numeric literal, or a provable `[IPAddress]`/`[IPEndPoint]` expression.
          4. `.Connect(`, `.ConnectAsync(`, `.BeginConnect(`, `.Send(`, `.SendAsync(`,
             `.SendPingAsync(` outside `30-Resolver.ps1` - every argument must be provably typed the
             same way (checked per-argument, not by a fixed position: `Send`/`SendAsync` have a
             2-argument already-connected form with no host at all, and 3-/4-argument forms whose
             host sits at a different position depending on receiver class - `Ping.Send(address,
             timeout, buffer)` puts it first, `UdpClient.Send(buffer, size, host, port)` puts it
             third).
          5. A computed member name of any kind (`.$x`, `.($expr)`, `::($expr)`, a quoted member) -
             shared with Test-NoDynamicEval.ps1's Find-PPComputedMemberFinding: `$client.$methodName`
             dispatch is exactly as much a resolver-isolation hole as it is a dynamic-eval one.
          6. Reflection (`.GetMethod(`, `.GetMember(`, `.InvokeMember(`, `.GetType(` unconditionally,
             `.Assembly`, `.Module`, `.InvokeReturnAsIs(`, `[Reflection.*]`, `[Activator]`) - shared
             with Test-NoDynamicEval.ps1's Find-PPReflectionFinding: `.Assembly.GetType('...
             TcpClient')` then `$t::new(...)` reaches a network constructor without ever writing a
             literal `[System.Net.Sockets.TcpClient]`.
          7. Static member access on a non-literal (`$x::Member`) and `-as` with any type
             operand - `'...TcpClient' -as [type]` then `$t::new($h,80)` is exactly this shape.

        Class 3's file-scoped construction check and class
        4's 30-Resolver.ps1 exemption are both resolved per call, from that call's own offset, mapped
        back to its original `src/` part via `Get-PPOwningLeaf`/`Get-PPDistPartMap` (StaticScan.ps1) -
        not by comparing the whole scanned file's own name. In dist/PortProof.ps1 every part shares
        one file name (`PortProof.ps1`), so a whole-file check could not tell `50-Probe.Tcp.ps1`'s own
        concatenated segment apart from any other part's, nor 30-Resolver.ps1's own segment apart from
        the rest - guaranteeing false positives (a TcpClient built in its own legitimate segment) or
        false exemptions (every other part's Connect/Send calls silently exempted too) whichever way
        the old whole-file check happened to fall. `Find-PPTypeAllowedEntry`, the two allowlist scans,
        and every scoped allowance in Test-NoDynamicEval.ps1 share the same fix.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$resolverFileName = '30-Resolver.ps1'
$definedFunctionNames = Get-PPDefinedFunctionName -Root $Root
# Union with settings/DeclaredFunctions.psd1 so a forward reference to a function declared but not
# yet defined in this file is not a false "not on the allowlist" finding.
foreach ($n in (Get-PPDeclaredFunctionName)) { [void] $definedFunctionNames.Add($n) }
$allowedCommandNames = Get-PPAllowedCommandSet
$allowedTypeData = Get-PPAllowedTypeData

$tokenRules = @(
    'System\.Net\.Dns',
    '\[\s*Net\.Dns\s*\]',
    'GetHostEntry',
    'GetHostAddresses',
    'GetHostByName',
    'BeginGetHostAddresses',
    'Resolve-DnsName',
    'Test-Connection',
    'Test-NetConnection'
)

$methodNames = @('Connect', 'ConnectAsync', 'BeginConnect', 'Send', 'SendAsync', 'SendPingAsync')

# Class name -> the one file it is allowed to be constructed in ($null = never allowed anywhere).
$constructorAllowedFile = [ordered]@{
    'TcpClient' = '50-Probe.Tcp.ps1'
    'UdpClient' = '55-Probe.Udp.ps1'
    'Socket'    = $null
}

function Get-PPTokenCount {
    param([string] $Text, [string] $Pattern)
    ([regex]::Matches($Text, $Pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
}

function Test-PPApprovedNetworkArgument {
    <#
        True for a provably safe argument to a host-touching constructor or method: a numeric
        literal, $null, a [byte[]] buffer expression, a direct IPAddress/IPEndPoint constructing or
        casting expression, an AddressFamily-shaped expression (the constructors' one legitimate
        argument), a scriptblock (a BeginConnect callback), or a variable whose declared parameter
        type is IPAddress/IPEndPoint/AddressFamily/Int32/byte[]. Anything else - a string literal,
        or a variable with no provable type - is not approved: never a string literal or any other
        unprovable variable.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param($ArgAst, $EnclosingFunc)

    if ($null -eq $ArgAst) { return $true }
    if ($ArgAst -is [System.Management.Automation.Language.ConstantExpressionAst] -and
        $ArgAst -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) {
        return $true   # a numeric (or boolean) literal - a port, a timeout, never a host
    }
    if ($ArgAst -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { return $true }

    $text = $ArgAst.Extent.Text.Trim()
    if ($text -eq '$null') { return $true }
    if ($text -match '^\[byte\[\]\]') { return $true }
    if ($text -match '^\[\s*(System\.Net\.)?IPAddress\s*\]\s*::\s*(new|Parse|TryParse)\s*\(') { return $true }
    if ($text -match '^\[\s*(System\.Net\.)?IPEndPoint\s*\]\s*::\s*new\s*\(') { return $true }
    if ($text -match '^\[\s*(System\.Net\.)?IPAddress\s*\]') { return $true }     # cast
    if ($text -match '^\[\s*(System\.Net\.)?IPEndPoint\s*\]') { return $true }    # cast
    if ($text -match '^\[\s*(System\.Net\.Sockets\.)?AddressFamily\s*\]\s*::') { return $true }

    if ($ArgAst -is [System.Management.Automation.Language.MemberExpressionAst] -and
        $ArgAst.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $ArgAst.Member.Value -ieq 'AddressFamily') {
        return $true
    }

    if ($ArgAst -is [System.Management.Automation.Language.VariableExpressionAst]) {
        $typeName = Get-PPParameterTypeName -Func $EnclosingFunc -VarName $ArgAst.VariablePath.UserPath
        if ($typeName -and $typeName -match '(?i)(^|\.)(IPAddress|IPEndPoint|AddressFamily|Int32|Int|Byte\[\])$') { return $true }
        return $false
    }

    return $false
}

function Get-PPCallArgument {
    <# The argument expressions of a `::new(...)`/`.Method(...)` InvokeMemberExpressionAst call, in
       order. New-Object is banned outright (below), so this no longer needs to understand its
       -ArgumentList/positional shapes. #>
    [CmdletBinding()]
    param($Node)
    @($Node.Arguments)
}

$findings = New-Object System.Collections.Generic.List[string]

# --- 1. Token scan over src/, resolver tokens confined to 30-Resolver.ps1 ---
$srcFiles = Get-PPSourceFile -Root $Root -Dirs @('src')
$resolverPath = $srcFiles | Where-Object { [System.IO.Path]::GetFileName($_) -ieq $resolverFileName } | Select-Object -First 1

foreach ($file in $srcFiles) {
    if ([System.IO.Path]::GetFileName($file) -ieq $resolverFileName) { continue }
    $text = Get-PPStrippedText -Path $file
    foreach ($pattern in $tokenRules) {
        foreach ($m in [regex]::Matches($text, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $line = Get-PPLineNumber -Text $text -Offset $m.Index
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC11.ResolverIsolation' `
                -Text "resolving token '$($m.Value)' outside $resolverFileName" -Root $Root))
        }
    }
}

# --- 1b. dist/ count parity with 30-Resolver.ps1 ---
$distFile = Join-Path $Root 'dist\PortProof.ps1'
if ((Test-Path -LiteralPath $distFile) -and $resolverPath) {
    $resolverText = Get-PPStrippedText -Path $resolverPath
    $distText = Get-PPStrippedText -Path $distFile
    foreach ($pattern in $tokenRules) {
        $resolverCount = Get-PPTokenCount -Text $resolverText -Pattern $pattern
        $distCount = Get-PPTokenCount -Text $distText -Pattern $pattern
        if ($distCount -ne $resolverCount) {
            $findings.Add((Format-PPFinding -Path $distFile -Line 1 -Rule 'AC11.DistCountMismatch' `
                -Text "pattern '$pattern' count $distCount in dist vs $resolverCount in $resolverFileName" -Root $Root))
        }
    }
}

# --- 2. New-Object: banned outright, everywhere in src/ and dist/ (no exception, not even in
#    30-Resolver.ps1 - the resolver has no more legitimate use for it than any other file). ---
$allScanFiles = Get-PPSourceFile -Root $Root -Dirs @('src', 'dist')
foreach ($file in $allScanFiles) {
    $result = Get-PPAst -Path $file
    $rawText = [System.IO.File]::ReadAllText($file)
    $newObjectCalls = $result.Ast.FindAll({
        $args[0] -is [System.Management.Automation.Language.CommandAst] -and $args[0].GetCommandName() -ieq 'New-Object'
    }, $true)
    foreach ($call in $newObjectCalls) {
        $line = Get-PPLineNumber -Text $rawText -Offset $call.Extent.StartOffset
        $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'Posture.NewObjectBanned' `
            -Text "New-Object is banned; use [Type]::new(...): '$($call.Extent.Text)'" -Root $Root))
    }

    # 5, 6, 7 (shared with Test-NoDynamicEval.ps1): computed member names, reflection, static
    # member on a non-literal, and -as with any type operand - everywhere.
    foreach ($f in (Find-PPComputedMemberFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPReflectionFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPStaticMemberOnVariableFinding -Path $file -Root $Root)) { $findings.Add($f) }
    foreach ($f in (Find-PPAsTypeCastFinding -Path $file -Root $Root)) { $findings.Add($f) }

    # Allowlists (command and type, items A and B above).
    foreach ($f in (Find-PPCommandAllowlistFinding -Path $file -Root $Root -DefinedFunctionNames $definedFunctionNames -AllowedCommandNames $allowedCommandNames)) { $findings.Add($f) }
    foreach ($f in (Find-PPTypeAllowlistFinding -Path $file -Root $Root -TypeData $allowedTypeData)) { $findings.Add($f) }

    if ((Split-Path -Leaf (Split-Path -Parent $file)) -ieq 'dist' -and [System.IO.Path]::GetFileName($file) -ieq 'PortProof.ps1') {
        foreach ($f in (Get-PPDistPartMapMissingFinding -Path $file -Root $Root)) { $findings.Add($f) }
    }
}

# --- 3 & 4. AST scan over src/ + dist/. 30-Resolver.ps1's exemption from
# section 4 (unrestricted argument shapes - the resolver's own seam) is checked per call, from
# that call's own offset via Get-PPOwningLeaf, not by excluding a whole file from $allScanFiles up
# front - in dist/PortProof.ps1 the resolver's own legitimate calls sit in the same file as every
# other part's, so a whole-file exclusion would either exempt everything or nothing.
foreach ($file in $allScanFiles) {
    $result = Get-PPAst -Path $file
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($file)

    # 3. Constructor calls: ::new( only (New-Object is banned above regardless of what it builds).
    $ctorCalls = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $node.Static -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $node.Member.Value -ieq 'new' -and
        $node.Expression -is [System.Management.Automation.Language.TypeExpressionAst] -and
        ($constructorAllowedFile.Keys | Where-Object { $node.Expression.TypeName.Name -match "(?i)(^|\.)$_`$" })
    }, $true)

    foreach ($call in $ctorCalls) {
        $className = $constructorAllowedFile.Keys | Where-Object { $call.Expression.TypeName.Name -match "(?i)(^|\.)$_`$" } | Select-Object -First 1
        $allowedFile = $constructorAllowedFile[$className]
        $line = Get-PPLineNumber -Text $rawText -Offset $call.Extent.StartOffset
        $owningLeaf = Get-PPOwningLeaf -Path $file -Offset $call.Extent.StartOffset

        if (-not $allowedFile -or $owningLeaf -ine $allowedFile) {
            $where = if ($allowedFile) { "outside $allowedFile" } else { 'nowhere; this class is never constructed' }
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'Posture.ConstructionFileScope' `
                -Text "$className construction is allowed $where" -Root $Root))
            continue
        }

        $enclosingFunc = Get-PPEnclosingFunction -Node $call -FileAst $ast
        $callArgs = Get-PPCallArgument -Node $call
        $bad = @($callArgs | Where-Object { -not (Test-PPApprovedNetworkArgument -ArgAst $_ -EnclosingFunc $enclosingFunc) })
        if ($bad.Count -gt 0) {
            $argsText = ($callArgs | ForEach-Object { $_.Extent.Text }) -join ', '
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC11.StringHostConstructor' `
                -Text "$className construction with an unapproved argument ($argsText)" -Root $Root))
        }
    }

    # 4. .Connect(/.ConnectAsync(/.BeginConnect(/.Send(/.SendAsync(/.SendPingAsync( - every argument
    #    checked by its own provable type/shape, not by a fixed position (Send's host position
    #    differs by overload and by receiver class). Exempt only the calls whose own owning leaf is
    #    30-Resolver.ps1 (the resolver's own seam), not the whole file.
    $methodCalls = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        ($methodNames -icontains $node.Member.Value)
    }, $true)
    foreach ($call in $methodCalls) {
        if ((Get-PPOwningLeaf -Path $file -Offset $call.Extent.StartOffset) -ieq $resolverFileName) { continue }
        $enclosingFunc = Get-PPEnclosingFunction -Node $call -FileAst $ast
        $callArgs = Get-PPCallArgument -Node $call
        if ($callArgs.Count -eq 0) { continue }
        $bad = @($callArgs | Where-Object { -not (Test-PPApprovedNetworkArgument -ArgAst $_ -EnclosingFunc $enclosingFunc) })
        if ($bad.Count -gt 0) {
            $badText = ($bad | ForEach-Object { $_.Extent.Text.Trim() }) -join ', '
            $line = Get-PPLineNumber -Text $rawText -Offset $call.Extent.StartOffset
            $findings.Add((Format-PPFinding -Path $file -Line $line -Rule 'AC11.UnapprovedHostArgument' `
                -Text "$($call.Member.Value)( has an unapproved argument outside ${resolverFileName}: $badText" -Root $Root))
        }
    }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
