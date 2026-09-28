<#
    .SYNOPSIS
        AC16 - no SYN scanning, no raw sockets, no local source-port binding, no TCP banner grab.

    .DESCRIPTION
        Scope and limits: a static token/AST scan over our own committed source, run at build/CI
        time - not a proof against a determined insider with commit access, who could edit this
        scanner too. It catches the named prohibited constructs by name and shape; the backstop for
        anything a reviewed check still misses is the independent pre-release security review.

        Per-file, comment-stripped scan over src/ and dist/ (AC16).

        Everywhere: raw-socket construction (`SocketType]::Raw`, `ProtocolType]::Raw` /
        `ProtocolType]::Icmp`), `IPHeaderIncluded`, local source-port binding (`.Bind(`,
        `ExclusiveAddressUse`, `SetSocketOption`), and any use of `LingerState` (this tool has no
        legitimate reason to force a RST-on-close).

        In every file except `55-Probe.Udp.ps1` (and `dist/PortProof.ps1`, see below): `GetStream(`,
        `NetworkStream`, `.Receive(`, `ReceiveFrom`, `BeginReceive`, `BeginRead`, `EndRead` - the TCP
        adapter and the scheduler never read from a socket.

        `.Read(` is banned the same way, with one named exception: a FileStream-typed
        receiver inside `10-Parser.ps1` (or its copy in `dist/PortProof.ps1`) - the one bounded
        profile read requires. A `.Read(` on anything else -
        untyped, differently typed, or in any other file - stays banned; `.Read(`/`.BeginRead(`/
        `.EndRead(` on a `TcpClient`/`UdpClient`/`NetworkStream` receiver is banned everywhere, with
        no exception anywhere (checked structurally here, not only through the general type
        allowlist the other two scanners own).

        In `55-Probe.Udp.ps1` (the one file the UDP contract requires to receive): the blanket
        receive prohibition does not apply, but every `.Receive(` call must be preceded, in the
        same function, by an assignment to `.ReceiveTimeout` - an unbounded UDP receive would hang
        the whole scheduler queue for that target. The same guard is checked in `dist/PortProof.ps1`.

        `dist/PortProof.ps1` is the concatenation of every `src/` part, so it always carries
        `55-Probe.Udp.ps1`'s own legitimate `.Receive(` call too; applying the blanket non-UDP ban to
        the built artifact would make AC16 fail on every release build. Instead, for each of the
        non-UDP-file tokens, `dist/PortProof.ps1`'s count must equal `55-Probe.Udp.ps1`'s count (the
        same count-parity check `Test-ResolverIsolation.ps1` already uses for `30-Resolver.ps1`) -
        a build cannot introduce a banner-grab token beyond what the guarded UDP file already has.

        The `.Read(`/10-Parser.ps1 exception above is
        resolved per call, from that call's own line, mapped back to its original `src/` part via
        `Get-PPOwningLeaf`/`Get-PPDistPartMap` (StaticScan.ps1) - which reads the `# ---- <part>
        ----` banner `build/Build-PortProof.ps1` writes before every part after the first, plus
        `build/parts.txt`'s own first entry for the un-bannered leading part. A `.Read(` planted in
        dist/PortProof.ps1 outside 10-Parser.ps1's own concatenated segment is still denied, even
        though the whole file's name is `PortProof.ps1`. If no banner/parts.txt is found at all,
        `Get-PPDistPartMapMissingFinding` reports it once rather than silently falling back.

    .PARAMETER Root
        Repo root (system/portproof). Defaults to two levels up from this script.
#>
[CmdletBinding()]
param([string] $Root)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not $Root) { $Root = Get-PPStaticRepoRoot }

$udpFileName = '55-Probe.Udp.ps1'

# Everywhere (src/ + dist/), no exception.
$everywhereRules = @(
    @{ Rule = 'AC16.RawSocket';    Pattern = 'SocketType\s*\]\s*::\s*Raw' }
    @{ Rule = 'AC16.RawSocket';    Pattern = 'ProtocolType\s*\]\s*::\s*(Raw|Icmp)\b' }
    @{ Rule = 'AC16.RawSocket';    Pattern = 'IPHeaderIncluded' }
    @{ Rule = 'AC16.SourcePort';   Pattern = '\.Bind\s*\(' }
    @{ Rule = 'AC16.SourcePort';   Pattern = 'ExclusiveAddressUse' }
    @{ Rule = 'AC16.SourcePort';   Pattern = 'SetSocketOption' }
    @{ Rule = 'AC16.Linger';       Pattern = 'LingerState' }
)

# Everywhere except the UDP adapter. `.Read(` is handled separately below
# (Find-PPReadReceiverFinding), since it alone gets the FileStream/10-Parser.ps1 exception.
$nonUdpRules = @(
    @{ Rule = 'AC16.BannerGrab'; Pattern = 'GetStream\s*\(' }
    @{ Rule = 'AC16.BannerGrab'; Pattern = 'NetworkStream' }
    @{ Rule = 'AC16.BannerGrab'; Pattern = '\.Receive\s*\(' }
    @{ Rule = 'AC16.BannerGrab'; Pattern = 'ReceiveFrom' }
    @{ Rule = 'AC16.BannerGrab'; Pattern = 'BeginReceive' }
    @{ Rule = 'AC16.BannerGrab'; Pattern = 'BeginRead' }
    @{ Rule = 'AC16.BannerGrab'; Pattern = 'EndRead' }
)

function Get-PPMatchesWithLine {
    <# Always an array, even for zero matches. PS 5.1 unrolls a function's output onto the success
       stream one element at a time regardless of an internal @()-wrap, so a zero-element result
       still collapses to $null at the call site (`$x = Get-Foo` with zero emitted objects) unless
       the array itself is written with -NoEnumerate, which is what makes the count-parity check's
       `.Count` reliable at zero. #>
    [OutputType([object[]])]
    param([string] $Text, [string] $Pattern)
    $items = @([regex]::Matches($Text, $Pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase) |
        ForEach-Object {
            [pscustomobject]@{ Line = Get-PPLineNumber -Text $Text -Offset $_.Index; Value = $_.Value }
        })
    Write-Output -InputObject $items -NoEnumerate
}

function Test-PPUdpReceiveGuarded {
    <# For 55-Probe.Udp.ps1: every .Receive( call must have a preceding .ReceiveTimeout
       assignment in the same function body (by token offset, not just anywhere in the file). #>
    param([string] $Path, [string] $Root)

    $findings = New-Object System.Collections.Generic.List[string]
    $astResult = Get-PPAst -Path $Path
    $functions = $astResult.Ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    # A .Receive( at file scope (no enclosing function) is checked against the whole file, via the
    # $scopeAst fallback below.

    $receiveCalls = $astResult.Ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Member.Value -ieq 'Receive'
    }, $true)

    foreach ($call in $receiveCalls) {
        $enclosing = $functions | Where-Object {
            $_.Extent.StartOffset -le $call.Extent.StartOffset -and $_.Extent.EndOffset -ge $call.Extent.EndOffset
        } | Sort-Object { $_.Extent.EndOffset - $_.Extent.StartOffset } | Select-Object -First 1
        $scopeAst = if ($enclosing) { $enclosing } else { $astResult.Ast }

        $guarded = $scopeAst.FindAll({
            $node = $args[0]
            $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left -is [System.Management.Automation.Language.MemberExpressionAst] -and
            $node.Left.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
            $node.Left.Member.Value -ieq 'ReceiveTimeout' -and
            $node.Extent.StartOffset -lt $call.Extent.StartOffset
        }, $true).Count -gt 0

        if (-not $guarded) {
            $line = Get-PPLineNumber -Text ([System.IO.File]::ReadAllText($Path)) -Offset $call.Extent.StartOffset
            $findings.Add((Format-PPFinding -Path $Path -Line $line -Rule 'AC16.UdpReceiveUnbounded' `
                -Text '.Receive( has no preceding .ReceiveTimeout assignment in the same function' -Root $Root))
        }
    }
    $findings
}

function Find-PPReadReceiverFinding {
    <#
        `.Read(` is AC16.BannerGrab everywhere, with one named exception - a
        FileStream-typed receiver, inside `10-Parser.ps1` (or its copy in `dist/PortProof.ps1`) -
        the one bounded profile read requires. The receiver's
        type is proven the same way the resolver-isolation scanner proves adapter argument types:
        traced to a declared parameter's type constraint (Get-PPParameterTypeName), never assumed.
        A `.Read(` on an untyped variable, a differently-typed one, or in any other file, is still a
        finding - this narrows the old blanket ban for this one token, it does not remove it.

        The exception is checked per call, from that call's own offset via
        Get-PPOwningLeaf, not once for the whole file. The old whole-file `$isDistFile` shortcut
        allowed a FileStream `.Read(` ANYWHERE in dist/PortProof.ps1 - too permissive, since dist/ is
        every part concatenated, not just 10-Parser.ps1's; a `.Read(` planted in a different part's
        segment, even one on a FileStream-typed variable, must still be denied there.
    #>
    param([string] $Path, [string] $Root, [string] $ParserFileName = '10-Parser.ps1')

    $findings = New-Object System.Collections.Generic.List[string]

    $result = Get-PPAst -Path $Path
    $ast = $result.Ast
    $rawText = [System.IO.File]::ReadAllText($Path)

    $reads = $ast.FindAll({
        $node = $args[0]
        $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
        $node.Member -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $node.Member.Value -ieq 'Read'
    }, $true)

    foreach ($call in $reads) {
        $allowed = $false
        $owningLeaf = Get-PPOwningLeaf -Path $Path -Offset $call.Extent.StartOffset
        if (($owningLeaf -ieq $ParserFileName) -and $call.Expression -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $enclosing = Get-PPEnclosingFunction -Node $call -FileAst $ast
            $typeName = Get-PPParameterTypeName -Func $enclosing -VarName $call.Expression.VariablePath.UserPath
            if ($typeName -and $typeName -match '(?i)(^|\.)FileStream$') { $allowed = $true }
        }
        if (-not $allowed) {
            $line = Get-PPLineNumber -Text $rawText -Offset $call.Extent.StartOffset
            $findings.Add((Format-PPFinding -Path $Path -Line $line -Rule 'AC16.BannerGrab' -Text "matched '.Read('" -Root $Root))
        }
    }
    $findings
}

$findings = New-Object System.Collections.Generic.List[string]

$allFiles = Get-PPSourceFile -Root $Root -Dirs @('src', 'dist')
$udpPath = $allFiles | Where-Object { [System.IO.Path]::GetFileName($_) -ieq $udpFileName } | Select-Object -First 1
$udpText = if ($udpPath) { Get-PPStrippedText -Path $udpPath } else { $null }

foreach ($file in $allFiles) {
    $text = Get-PPStrippedText -Path $file
    $leaf = [System.IO.Path]::GetFileName($file)
    $isUdpFile = $leaf -ieq $udpFileName
    $isDistFile = $leaf -ieq 'PortProof.ps1' -and (Split-Path -Leaf (Split-Path -Parent $file)) -ieq 'dist'

    if ($isDistFile) {
        # Report (not silently fall back) when dist/PortProof.ps1 carries
        # no recognizable src/-part banner - every file-scoped allowance below denies by default in
        # that case, which would otherwise look like a wall of ordinary findings, not a build defect.
        foreach ($f in (Get-PPDistPartMapMissingFinding -Path $file -Root $Root)) { $findings.Add($f) }
    }

    foreach ($r in $everywhereRules) {
        foreach ($m in (Get-PPMatchesWithLine -Text $text -Pattern $r.Pattern)) {
            $findings.Add((Format-PPFinding -Path $file -Line $m.Line -Rule $r.Rule -Text "matched '$($m.Value)'" -Root $Root))
        }
    }

    if ($isDistFile -and $udpText) {
        # Count parity with 55-Probe.Udp.ps1 instead of a blanket ban: dist/ always carries that
        # file's own legitimate .Receive(, so the same finding format ResolverIsolation uses for
        # 30-Resolver.ps1 applies here too.
        foreach ($r in $nonUdpRules) {
            $distCount = (Get-PPMatchesWithLine -Text $text -Pattern $r.Pattern).Count
            $udpCount = (Get-PPMatchesWithLine -Text $udpText -Pattern $r.Pattern).Count
            if ($distCount -ne $udpCount) {
                $findings.Add((Format-PPFinding -Path $file -Line 1 -Rule 'AC16.DistCountMismatch' `
                    -Text "pattern '$($r.Pattern)' count $distCount in dist vs $udpCount in $udpFileName" -Root $Root))
            }
        }
        foreach ($f in (Test-PPUdpReceiveGuarded -Path $file -Root $Root)) { $findings.Add($f) }
    } elseif ($isDistFile -and -not $udpText) {
        # No src/55-Probe.Udp.ps1 to compare against yet: fall back to the blanket ban rather than
        # silently skipping the check.
        foreach ($r in $nonUdpRules) {
            foreach ($m in (Get-PPMatchesWithLine -Text $text -Pattern $r.Pattern)) {
                $findings.Add((Format-PPFinding -Path $file -Line $m.Line -Rule $r.Rule -Text "matched '$($m.Value)'" -Root $Root))
            }
        }
    } elseif (-not $isUdpFile) {
        foreach ($r in $nonUdpRules) {
            foreach ($m in (Get-PPMatchesWithLine -Text $text -Pattern $r.Pattern)) {
                $findings.Add((Format-PPFinding -Path $file -Line $m.Line -Rule $r.Rule -Text "matched '$($m.Value)'" -Root $Root))
            }
        }
    } else {
        foreach ($f in (Test-PPUdpReceiveGuarded -Path $file -Root $Root)) { $findings.Add($f) }
    }

    # .Read( is checked independently of the UDP/dist-count-parity branching above, in every file:
    # it alone carries the FileStream/10-Parser.ps1 exception.
    foreach ($f in (Find-PPReadReceiverFinding -Path $file -Root $Root)) { $findings.Add($f) }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
