# Contract tests. Dot-sources 05-Contract.ps1 and 90-Main.ps1 (the
# entry guard keeps 90 inert) and builds a contract-only artifact (parts 00, 05, 90) in $TestDrive
# for the process-level cases, exercising only the contract layer directly. Nothing here opens a
# socket or resolves a name: the parser/expander/resolver functions Main calls are replaced by
# in-test stubs.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:HeaderPath = Join-Path $script:Root 'src/00-Header.ps1'
    $script:ContractPath = Join-Path $script:Root 'src/05-Contract.ps1'
    $script:MainPath = Join-Path $script:Root 'src/90-Main.ps1'
    $script:BuildScript = Join-Path $script:Root 'build/Build-PortProof.ps1'
    . $script:ContractPath
    . $script:MainPath

    function Get-Raw {
        param([hashtable] $Overrides = @{})
        $raw = @{
            ProfilePath = 'p.csv'; Set = $null; Out = ''; Format = $null; Timeout = 2000; Concurrency = 16
            MaxProbesPerSecond = 50; Jitter = 250; MaxProbes = 0; MaxProbesGiven = $false; AllowLarge = $false
            AllowCidr = $false; Icmp = $false; DryRun = $false; NoOperator = $false; Force = $false; Quiet = $true
            Version = $false
        }
        foreach ($key in $Overrides.Keys) { $raw[$key] = $Overrides[$key] }
        if ($Overrides.ContainsKey('MaxProbes') -and -not $Overrides.ContainsKey('MaxProbesGiven')) { $raw['MaxProbesGiven'] = $true }
        $raw
    }

    function Get-Refusal {
        param([scriptblock] $Action)
        try { & $Action; return $null } catch { return $_ }
    }

    function Invoke-MainEntry {
        param([hashtable] $Raw, $LiveResolver)
        $exitCode = [ref]99
        $all = @(Invoke-PortProof -Raw $Raw -ExitCode $exitCode -LiveResolver $LiveResolver *>&1)
        [pscustomobject]@{
            ExitCode = $exitCode.Value
            Success  = @($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] -and $_ -isnot [System.Management.Automation.InformationRecord] -and $_ -isnot [System.Management.Automation.WarningRecord] -and $_ -isnot [System.Management.Automation.VerboseRecord] -and $_ -isnot [System.Management.Automation.DebugRecord] })
            Info     = @($all | Where-Object { $_ -is [System.Management.Automation.InformationRecord] })
            Errors   = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        }
    }

    function Get-ContractArtifact {
        # Builds 00+05+90 into $TestDrive once; returns the artifact path.
        if ($script:Artifact -and (Test-Path -LiteralPath $script:Artifact)) { return $script:Artifact }
        $co = Join-Path $TestDrive 'contract-only'
        $null = [System.IO.Directory]::CreateDirectory((Join-Path $co 'src'))
        $null = [System.IO.Directory]::CreateDirectory((Join-Path $co 'build'))
        foreach ($name in '00-Header.ps1', '05-Contract.ps1', '90-Main.ps1') {
            Copy-Item -LiteralPath (Join-Path $script:Root "src/$name") -Destination (Join-Path $co "src/$name")
        }
        [System.IO.File]::WriteAllText((Join-Path $co 'build/parts.txt'), "src/00-Header.ps1`nsrc/05-Contract.ps1`nsrc/90-Main.ps1`n")
        $null = & $script:BuildScript -Root $co -OutFile 'dist/PortProof.ps1'
        if ($LASTEXITCODE -ne 0) { throw "contract-only build failed ($LASTEXITCODE)" }
        $script:Artifact = Join-Path $co 'dist/PortProof.ps1'
        $script:Artifact
    }

    function Invoke-ProcessEntry {
        # Runs the host executable of this session (powershell.exe under 5.1) with -File or -Command.
        param([string] $Artifact, [string[]] $Arguments, [ValidateSet('File', 'Command')] [string] $Entry)
        $exe = (Get-Process -Id $PID).Path
        if ($Entry -eq 'File') {
            $quoted = @($Arguments | ForEach-Object { if ($_ -ceq '') { '""' } elseif ($_ -cmatch '[\s"]') { '"' + $_.Replace('"', '\"') + '"' } else { $_ } })
            $argText = '-NoProfile -NonInteractive -File "{0}" {1}' -f $Artifact, ($quoted -join ' ')
        }
        else {
            $inner = @($Arguments | ForEach-Object { if ($_ -match '^-') { $_ } else { "'" + $_.Replace("'", "''") + "'" } })
            $argText = '-NoProfile -NonInteractive -Command "& ''{0}'' {1}; exit $LASTEXITCODE"' -f $Artifact, ($inner -join ' ')
        }
        $psi = [System.Diagnostics.ProcessStartInfo]::new($exe, $argText)
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $psi.WorkingDirectory = $TestDrive
        $process = [System.Diagnostics.Process]::Start($psi)
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        [pscustomobject]@{ ExitCode = $process.ExitCode; StdOut = $stdout.Result; StdErr = $stderr.Result }
    }
}

Describe 'Contract constants and clause' -Tag 'Portable' {
    It 'returns a new hashtable per call' {
        $a = Get-PPContract
        $a.DefaultCeiling = 1
        (Get-PPContract).DefaultCeiling | Should -Be 1024
    }

    It 'fixes the version, ceilings and closed vocabularies' {
        $c = Get-PPContract
        $c.ToolVersion | Should -BeExactly '1.0.0'
        $c.AbsoluteProbeCeiling | Should -Be 8192
        ($c.Formats -join ',') | Should -BeExactly 'Html,Csv,Json'
        ($c.Outcomes -join ',') | Should -BeExactly 'Pass,Fail,Inconclusive'
        ($c.States.UDP -join ',') | Should -BeExactly 'Open,Closed,Open|Filtered'
        ($c.Errors -join ',') | Should -BeExactly 'None,ConnectionRefused,Timeout,IcmpUnreachable,NoResponse,DnsFailure,HostUnreachable,ProbeError,LocalPolicy'
        $c.CidrSupported | Should -BeTrue
        $c.ExpansionFactor | Should -Be 8
        $c.OutputFileNames.Csv | Should -BeExactly 'portproof-results.csv'
    }

    It 'carries the 235-character working clause within the manifest pattern' {
        $clause = (Get-PPContract).AuthorizedUseClause
        $clause.Length | Should -Be 235
        $clause | Should -Match '^.{40,400}$'
        $clause | Should -Not -Match '\{\{'
    }

    It 'marks every clause copy in src with AUTHORIZED-USE-NOTICE' {
        $contractLines = [System.IO.File]::ReadAllLines($script:ContractPath)
        $at = [array]::FindIndex($contractLines, [Predicate[string]] { param($l) $l -match "AuthorizedUseClause\s*=" })
        $at | Should -BeGreaterThan 0
        $contractLines[$at - 1] | Should -Match '^\s*# AUTHORIZED-USE-NOTICE: keep this text byte-identical'
        $headerText = [System.IO.File]::ReadAllText($script:HeaderPath)
        $endOfHelp = $headerText.IndexOf('#>')
        $marker = $headerText.IndexOf('# AUTHORIZED-USE-NOTICE')
        $marker | Should -BeGreaterThan $endOfHelp
    }

    It 'has the clause in 00-Header.ps1 as one physical line byte-identical to the constant' {
        $clause = (Get-PPContract).AuthorizedUseClause
        @([System.IO.File]::ReadAllLines($script:HeaderPath) | Where-Object { $_ -ceq $clause }).Count | Should -Be 1
    }

    It 'returns the three notice lines in order' {
        $c = Get-PPContract
        $notice = @(Get-PPAuthorizedUseNotice)
        $notice.Count | Should -Be 3
        $notice[0] | Should -BeExactly $c.NoticeLine1
        $notice[1] | Should -BeExactly $c.AuthorizedUseClause
        $notice[2] | Should -BeExactly $c.NoticeLine3
    }

    It 'returns shape field orders' {
        $rr = @(Get-PPShapeFields -Shape 'ResultRow')
        $rr.Count | Should -Be 19
        ($rr[0..15] -join ',') | Should -BeExactly 'RunId,Timestamp,SourceName,SourceIp,TargetName,TargetIp,ResolvedAddresses,Port,Protocol,Service,Required,Outcome,State,LatencyMs,Error,ProfileRow'
        (@(Get-PPShapeFields -Shape 'RunHeader')[0..12] -join ',') | Should -BeExactly 'ToolVersion,ProfileName,ProfileVersion,ProfileSha256,RunId,StartedUtc,StartedLocal,OperatorUser,OperatorHost,ProbeCount,Flags,IgnoredColumns,AuthorizedUseNotice'
        @(Get-PPShapeFields -Shape 'Flags')[-1] | Should -BeExactly 'ExecutionPath'
        (@(Get-PPShapeFields -Shape 'AdapterResult') -join ',') | Should -BeExactly 'State,ErrorName,LatencyMs'
    }

    It 'Get-PPSafeText replaces control characters including ESC and truncates' {
        $esc = [char]27
        Get-PPSafeText -Text ("a{0}[31mb`n{1}" -f $esc, [char]0x85) | Should -BeExactly 'a?[31mb??'
        (Get-PPSafeText -Text ('x' * 300)).Length | Should -Be 200
        Get-PPSafeText -Text '' | Should -BeExactly ''
    }

    It 'Invoke-PPRefusal throws PortProof.<Code> with a sanitised message and a target object' {
        $err = Get-Refusal { Invoke-PPRefusal -Code 'Profile.Domain' -Message ("bad{0}value" -f [char]27) -Row 7 }
        $err.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.Domain'
        $err.Exception.Message | Should -BeExactly 'PortProof: bad?value'
        $err.CategoryInfo.Category | Should -Be 'InvalidArgument'
        $err.TargetObject.Row | Should -Be 7
        $err.TargetObject.Code | Should -BeExactly 'Profile.Domain'
    }
}

Describe 'Refused-class predicate (AC15 literal half)' -Tag 'Portable' {
    It '<Addr> -> <Class>' -ForEach @(
        @{ Addr = '0.0.0.0'; Class = 'this-network' }
        @{ Addr = '0.1.2.3'; Class = 'this-network' }
        @{ Addr = '0.255.255.255'; Class = 'this-network' }
        @{ Addr = '1.0.0.0'; Class = '' }
        @{ Addr = '223.255.255.255'; Class = '' }
        @{ Addr = '240.0.0.1'; Class = '' }
        @{ Addr = '255.255.255.254'; Class = '' }
        @{ Addr = '255.255.255.255'; Class = 'limited-broadcast' }
        @{ Addr = '::ffff:255.255.255.255'; Class = 'limited-broadcast' }
        @{ Addr = '224.0.0.0'; Class = 'multicast' }
        @{ Addr = '224.0.0.1'; Class = 'multicast' }
        @{ Addr = '239.255.255.250'; Class = 'multicast' }
        @{ Addr = '::ffff:224.0.0.1'; Class = 'multicast' }
        @{ Addr = '169.253.255.255'; Class = '' }
        @{ Addr = '169.255.0.0'; Class = '' }
        @{ Addr = '169.254.0.0'; Class = 'link-local' }
        @{ Addr = '169.254.1.1'; Class = 'link-local' }
        @{ Addr = '::ffff:169.254.1.1'; Class = 'link-local' }
        @{ Addr = '::'; Class = 'unspecified' }
        @{ Addr = '::1'; Class = '' }
        @{ Addr = '127.0.0.1'; Class = '' }
        @{ Addr = '127.0.0.3'; Class = '' }
        @{ Addr = '::ffff:127.0.0.1'; Class = '' }
        @{ Addr = '::ffff:0.0.0.1'; Class = 'this-network' }
        @{ Addr = 'ff02::1'; Class = 'multicast' }
        @{ Addr = 'ff00::'; Class = 'multicast' }
        @{ Addr = 'ffff::1'; Class = 'multicast' }
        @{ Addr = 'fe80::1'; Class = 'link-local' }
        @{ Addr = 'febf:ffff::1'; Class = 'link-local' }
        @{ Addr = 'fec0::1'; Class = '' }
        @{ Addr = 'fe7f::1'; Class = '' }
    ) {
        $verdict = Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse($Addr))
        $verdict.Class | Should -BeExactly $Class
        $verdict.Refused | Should -Be ($Class -ne '')
        if ($Class -ne '') { $verdict.ClassLabel | Should -Not -BeNullOrEmpty } else { $verdict.ClassLabel | Should -BeExactly '' }
    }

    It 'canonicalises IPv4-mapped addresses' {
        (Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse('::ffff:255.255.255.255'))).Canonical.ToString() | Should -BeExactly '255.255.255.255'
        (Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse('::ffff:127.0.0.1'))).Canonical.ToString() | Should -BeExactly '127.0.0.1'
        (ConvertTo-CanonicalAddress -Address ([System.Net.IPAddress]::Parse('::1'))).ToString() | Should -BeExactly '::1'
    }

    It 'refuses an embedded refused IPv4 (<Form>): <Addr> -> <Class> via <Embedded>' -ForEach @(
        # Every measured form, plus each embedding for each IPv4 class.
        @{ Form = 'IPv4-compatible'; Addr = '::224.0.0.1'; Class = 'multicast'; Embedded = '224.0.0.1' }
        @{ Form = 'IPv4-compatible'; Addr = '::255.255.255.255'; Class = 'limited-broadcast'; Embedded = '255.255.255.255' }
        @{ Form = 'IPv4-compatible'; Addr = '::169.254.1.1'; Class = 'link-local'; Embedded = '169.254.1.1' }
        @{ Form = 'IPv4-compatible'; Addr = '::0.0.0.2'; Class = 'this-network'; Embedded = '0.0.0.2' }
        @{ Form = 'IPv4-translated'; Addr = '::ffff:0:224.0.0.1'; Class = 'multicast'; Embedded = '224.0.0.1' }
        @{ Form = 'IPv4-translated'; Addr = '::ffff:0:e000:1'; Class = 'multicast'; Embedded = '224.0.0.1' }
        @{ Form = 'IPv4-translated'; Addr = '::ffff:0:255.255.255.255'; Class = 'limited-broadcast'; Embedded = '255.255.255.255' }
        @{ Form = 'NAT64'; Addr = '64:ff9b::224.0.0.1'; Class = 'multicast'; Embedded = '224.0.0.1' }
        @{ Form = 'NAT64'; Addr = '64:ff9b::e000:1'; Class = 'multicast'; Embedded = '224.0.0.1' }
        @{ Form = 'NAT64'; Addr = '64:ff9b::a9fe:101'; Class = 'link-local'; Embedded = '169.254.1.1' }
        @{ Form = 'NAT64'; Addr = '64:ff9b::0.1.2.3'; Class = 'this-network'; Embedded = '0.1.2.3' }
        @{ Form = '6to4'; Addr = '2002:e000:1::1'; Class = 'multicast'; Embedded = '224.0.0.1' }
        @{ Form = '6to4'; Addr = '2002:ffff:ffff::1'; Class = 'limited-broadcast'; Embedded = '255.255.255.255' }
        @{ Form = '6to4'; Addr = '2002:a9fe:101:5::9'; Class = 'link-local'; Embedded = '169.254.1.1' }
        @{ Form = '6to4'; Addr = '2002:0:1::'; Class = 'this-network'; Embedded = '0.0.0.1' }
        @{ Form = 'Teredo'; Addr = '2001:0:4136:e378:8000:63bf:1fff:fffe'; Class = 'multicast'; Embedded = '224.0.0.1' }
        @{ Form = 'Teredo'; Addr = '2001:0:4136:e378:8000:63bf::'; Class = 'limited-broadcast'; Embedded = '255.255.255.255' }
        @{ Form = 'Teredo'; Addr = '2001::5601:fefe'; Class = 'link-local'; Embedded = '169.254.1.1' }
    ) {
        $verdict = Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse($Addr))
        $verdict.Refused | Should -BeTrue
        $verdict.Class | Should -BeExactly $Class
        $canonical = [System.Net.IPAddress]::Parse($Addr).ToString()
        $verdict.ClassLabel | Should -BeLike ('*embedded as {0} in {1} (*' -f $Embedded, $canonical)
        $verdict.Canonical.ToString() | Should -BeExactly $canonical
        $kind = Get-PPTargetKind -Text $Addr
        $kind.Kind | Should -BeExactly 'IPv6'
        (Test-RefusedTargetClass -Address $kind.Address).Refused | Should -BeTrue
    }

    It 'admits an embedded IPv4 that is not in a refused class: <Addr>' -ForEach @(
        @{ Addr = '::ffff:0:8.8.8.8' }, @{ Addr = '::8.8.8.8' }, @{ Addr = '64:ff9b::8.8.8.8' }, @{ Addr = '2002:808:808::1' }
        @{ Addr = '2001:0:4136:e378:8000:63bf:f7f7:f7f7' }, @{ Addr = '::127.0.0.1' }, @{ Addr = '::1' }, @{ Addr = '::0.0.0.1' }
        @{ Addr = '2001:db8::1' }, @{ Addr = '2001:1::e000:1' }, @{ Addr = '2003:e000:1::1' }, @{ Addr = '64:ff9b:1::e000:1' }
    ) {
        (Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse($Addr))).Refused | Should -BeFalse
    }

    It 'still refuses :: as unspecified' {
        (Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse('::'))).Class | Should -BeExactly 'unspecified'
    }
}

Describe 'Target grammar' -Tag 'Portable' {
    It '<Label> -> <Kind> (refused class: <Class>)' -ForEach @(
        @{ Label = '0x0'; Text = '0x0'; Kind = 'NonCanonicalLiteral'; Addr = '0.0.0.0'; Class = 'this-network' }
        @{ Label = '0xffffffff'; Text = '0xffffffff'; Kind = 'NonCanonicalLiteral'; Addr = '255.255.255.255'; Class = 'limited-broadcast' }
        @{ Label = '0xe0000001'; Text = '0xe0000001'; Kind = 'NonCanonicalLiteral'; Addr = '224.0.0.1'; Class = 'multicast' }
        @{ Label = '0xa9fe0101'; Text = '0xa9fe0101'; Kind = 'NonCanonicalLiteral'; Addr = '169.254.1.1'; Class = 'link-local' }
        @{ Label = '0xff.0xff.0xff.0xff'; Text = '0xff.0xff.0xff.0xff'; Kind = 'NonCanonicalLiteral'; Addr = '255.255.255.255'; Class = 'limited-broadcast' }
        @{ Label = '0X7F000001'; Text = '0X7F000001'; Kind = 'NonCanonicalLiteral'; Addr = '127.0.0.1'; Class = '' }
        @{ Label = '0x7f.1'; Text = '0x7f.1'; Kind = 'NonCanonicalLiteral'; Addr = '127.0.0.1'; Class = '' }
        @{ Label = '10.1'; Text = '10.1'; Kind = 'NonCanonicalLiteral'; Addr = '10.0.0.1'; Class = '' }
        @{ Label = '3232235777'; Text = '3232235777'; Kind = 'NonCanonicalLiteral'; Addr = '192.168.1.1'; Class = '' }
        @{ Label = '010.0.0.1'; Text = '010.0.0.1'; Kind = 'NonCanonicalLiteral'; Addr = '8.0.0.1'; Class = '' }
        @{ Label = '1.2.3'; Text = '1.2.3'; Kind = 'NonCanonicalLiteral'; Addr = '1.2.0.3'; Class = '' }
        @{ Label = '[::1]'; Text = '[::1]'; Kind = 'NonCanonicalLiteral'; Addr = '::1'; Class = '' }
        @{ Label = 'fe80::1%12'; Text = 'fe80::1%12'; Kind = 'NonCanonicalLiteral'; Addr = 'fe80::1%12'; Class = 'link-local' }
        @{ Label = '10.0.0.1<LF>'; Text = "10.0.0.1`n"; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = 'evil.test<LF>'; Text = "evil.test`n"; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = '<SP>10.0.0.1'; Text = ' 10.0.0.1'; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = 'a<ESC>[31m.test'; Text = ('a{0}[31m.test' -f [char]27); Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = '0xg.test'; Text = '0xg.test'; Kind = 'Hostname'; Addr = ''; Class = '' }
        @{ Label = '00x1.test'; Text = '00x1.test'; Kind = 'Hostname'; Addr = ''; Class = '' }
        @{ Label = 'cafe.be'; Text = 'cafe.be'; Kind = 'Hostname'; Addr = ''; Class = '' }
        @{ Label = 'dc01.corp.example'; Text = 'dc01.corp.example'; Kind = 'Hostname'; Addr = ''; Class = '' }
        @{ Label = '0x1f.example'; Text = '0x1f.example'; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = '10.0.0.1'; Text = '10.0.0.1'; Kind = 'IPv4'; Addr = '10.0.0.1'; Class = '' }
        @{ Label = '::1'; Text = '::1'; Kind = 'IPv6'; Addr = '::1'; Class = '' }
        @{ Label = '::ffff:127.0.0.1'; Text = '::ffff:127.0.0.1'; Kind = 'IPv6'; Addr = '::ffff:127.0.0.1'; Class = '' }
        @{ Label = 'ff02--1.ipv6-literal.net'; Text = 'ff02--1.ipv6-literal.net'; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = '1.2.3.4.5'; Text = '1.2.3.4.5'; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = 'host.123'; Text = 'host.123'; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = 'a%b'; Text = 'a%b'; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = '<empty>'; Text = ''; Kind = 'Invalid'; Addr = ''; Class = '' }
        @{ Label = 'under_score.test'; Text = 'under_score.test'; Kind = 'Invalid'; Addr = ''; Class = '' }
    ) {
        $k = Get-PPTargetKind -Text $Text
        $k.Kind | Should -BeExactly $Kind
        if ($Addr -ne '') {
            $k.Address.ToString() | Should -BeExactly $Addr
            (Test-RefusedTargetClass -Address $k.Address).Class | Should -BeExactly $Class
        }
        else {
            $k.Address | Should -BeNullOrEmpty
        }
        if ($Kind -eq 'Invalid' -or $Kind -eq 'NonCanonicalLiteral') { $k.Reason | Should -Not -BeNullOrEmpty }
    }

    It 'normalises groups to upper case and host names to lower case without the trailing dot' {
        $g = Get-PPTargetKind -Text '%client_1%'
        $g.Kind | Should -BeExactly 'Group'
        $g.Text | Should -BeExactly 'CLIENT_1'
        $h = Get-PPTargetKind -Text 'DC01.Corp.Example.'
        $h.Kind | Should -BeExactly 'Hostname'
        $h.Text | Should -BeExactly 'dc01.corp.example'
        (Get-PPTargetKind -Text 'FE80::1').Kind | Should -BeExactly 'IPv6'
        (Get-PPTargetKind -Text '%A%x').Kind | Should -BeExactly 'Invalid'
    }

    It 'never throws on hostile input' {
        foreach ($t in @(('a' * 300), '....', '.', '%', '%%', "`0", (('x.' * 130) + 'com'), [string][char]0x2028)) {
            { Get-PPTargetKind -Text $t } | Should -Not -Throw
            (Get-PPTargetKind -Text $t).Kind | Should -BeExactly 'Invalid'
        }
    }
}

Describe 'Outcome table and exit code (AC10 logic)' -Tag 'Portable' {
    It '<Protocol> <State>/<ErrorName> -> <Outcome>' -ForEach @(
        @{ Protocol = 'TCP'; State = 'Open'; ErrorName = 'None'; Outcome = 'Pass' }
        @{ Protocol = 'UDP'; State = 'Open'; ErrorName = 'None'; Outcome = 'Pass' }
        @{ Protocol = 'ICMP'; State = 'Reply'; ErrorName = 'None'; Outcome = 'Pass' }
        @{ Protocol = 'TCP'; State = 'Closed'; ErrorName = 'ConnectionRefused'; Outcome = 'Fail' }
        @{ Protocol = 'TCP'; State = 'Unreachable'; ErrorName = 'Timeout'; Outcome = 'Fail' }
        @{ Protocol = 'TCP'; State = 'Unreachable'; ErrorName = 'HostUnreachable'; Outcome = 'Fail' }
        @{ Protocol = 'UDP'; State = 'Closed'; ErrorName = 'IcmpUnreachable'; Outcome = 'Fail' }
        @{ Protocol = 'UDP'; State = 'Closed'; ErrorName = 'HostUnreachable'; Outcome = 'Fail' }
        @{ Protocol = 'UDP'; State = 'Open|Filtered'; ErrorName = 'NoResponse'; Outcome = 'Inconclusive' }
        @{ Protocol = 'ICMP'; State = 'NoReply'; ErrorName = 'Timeout'; Outcome = 'Fail' }
        @{ Protocol = 'ICMP'; State = 'NoReply'; ErrorName = 'HostUnreachable'; Outcome = 'Fail' }
        @{ Protocol = 'ICMP'; State = 'NoReply'; ErrorName = 'ProbeError'; Outcome = 'Inconclusive' }
        @{ Protocol = 'TCP'; State = ''; ErrorName = 'DnsFailure'; Outcome = 'Fail' }
        @{ Protocol = 'UDP'; State = ''; ErrorName = 'DnsFailure'; Outcome = 'Fail' }
        @{ Protocol = 'TCP'; State = ''; ErrorName = 'ProbeError'; Outcome = 'Inconclusive' }
        @{ Protocol = 'TCP'; State = ''; ErrorName = 'LocalPolicy'; Outcome = 'Inconclusive' }
        @{ Protocol = 'UDP'; State = ''; ErrorName = 'LocalPolicy'; Outcome = 'Inconclusive' }
        @{ Protocol = 'ICMP'; State = ''; ErrorName = 'LocalPolicy'; Outcome = 'Inconclusive' }
        @{ Protocol = 'UDP'; State = 'Unreachable'; ErrorName = 'Timeout'; Outcome = 'Inconclusive' }
    ) {
        Get-PPOutcome -Protocol $Protocol -State $State -ErrorName $ErrorName | Should -BeExactly $Outcome
    }

    It 'exit code is 0 only when every required row passed' {
        Get-PPExitCode -Rows @() | Should -Be 0
        Get-PPExitCode -Rows @([pscustomobject]@{ Required = 'yes'; Outcome = 'Pass' }, [pscustomobject]@{ Required = 'no'; Outcome = 'Fail' }) | Should -Be 0
        Get-PPExitCode -Rows @([pscustomobject]@{ Required = 'yes'; Outcome = 'Pass' }, [pscustomobject]@{ Required = 'yes'; Outcome = 'Fail' }) | Should -Be 1
        Get-PPExitCode -Rows @([pscustomobject]@{ Required = 'yes'; Outcome = 'Inconclusive' }) | Should -Be 1
    }

    It 'a required LocalPolicy row fails the gate and is carried into the result row unchanged' {
        $outcome = Get-PPOutcome -Protocol 'TCP' -State '' -ErrorName 'LocalPolicy'
        $outcome | Should -BeExactly 'Inconclusive'
        Get-PPExitCode -Rows @([pscustomobject]@{ Required = 'yes'; Outcome = $outcome }) | Should -Be 1
        $expansion = [pscustomobject]@{ Rows = @([pscustomobject]@{ Row = 2; SourceName = 's'; SourceGroup = ''; SourceIp = ''; TargetName = '127.0.0.2'
                    TargetGroup = ''; TargetKind = 'IPv4'; Port = 53; Protocol = 'TCP'; Service = 'dns'; Required = 'yes'; Notes = ''; ProbeKey = '127.0.0.2|53|TCP' }) }
        $resolution = [pscustomobject]@{ Entries = @{ '127.0.0.2|53|TCP' = @{ TargetIp = [System.Net.IPAddress]::Parse('127.0.0.2'); ResolvedAddresses = [string[]]@('127.0.0.2'); Failed = $false } } }
        $gate = [pscustomobject]@{ Results = @([pscustomobject]@{ ExecKey = '127.0.0.2|53|TCP'; TargetIp = '127.0.0.2'; Port = 53; Protocol = 'TCP'; State = ''
                    ErrorName = 'LocalPolicy'; Outcome = $outcome; LatencyMs = 0; Timestamp = '2026-01-01T00:00:00.000Z' }) }
        $rows = @(Join-PPResults -Expansion $expansion -Resolution $resolution -GateResult $gate -RunId 'r')
        $rows[0].Error | Should -BeExactly 'LocalPolicy'
        $rows[0].State | Should -BeExactly ''
        $rows[0].Outcome | Should -BeExactly 'Inconclusive'
    }
}

Describe 'Assert-Arguments (AC8 argument half, AC10)' -Tag 'Portable' {
    It 'refuses <Label> with <Id>' -ForEach @(
        @{ Label = 'no -Profile'; Over = @{ ProfilePath = '' }; Id = 'Argument.Missing'; Text = '-Profile is required.' }
        @{ Label = 'blank -Profile'; Over = @{ ProfilePath = '   ' }; Id = 'Argument.Missing'; Text = '-Profile is required.' }
        @{ Label = '-Profile p.txt'; Over = @{ ProfilePath = 'p.txt' }; Id = 'Argument.Set'; Text = "-Profile 'p.txt' must be a .csv or .json file." }
        @{ Label = '-Format Pdf'; Over = @{ Format = @('Pdf') }; Id = 'Argument.Set'; Text = "-Format 'Pdf' is not one of Html, Csv, Json." }
        @{ Label = '-Format Html,'; Over = @{ Format = @('Html,'); Out = 'o' }; Id = 'Argument.Set'; Text = "-Format '' is not one of Html, Csv, Json." }
        @{ Label = '-Timeout 50'; Over = @{ Timeout = 50 }; Id = 'Argument.Range'; Text = '-Timeout 50 is out of range; permitted 100..30000 (ms).' }
        @{ Label = '-Timeout 30001'; Over = @{ Timeout = 30001 }; Id = 'Argument.Range'; Text = 'permitted 100..30000' }
        @{ Label = '-Concurrency 0'; Over = @{ Concurrency = 0 }; Id = 'Argument.Range'; Text = '-Concurrency 0 is out of range; permitted 1..64' }
        @{ Label = '-Concurrency 65'; Over = @{ Concurrency = 65 }; Id = 'Argument.Range'; Text = 'permitted 1..64' }
        @{ Label = '-MaxProbesPerSecond 0'; Over = @{ MaxProbesPerSecond = 0 }; Id = 'Argument.Range'; Text = '-MaxProbesPerSecond 0 is out of range; permitted 1..500' }
        @{ Label = '-MaxProbesPerSecond 501'; Over = @{ MaxProbesPerSecond = 501 }; Id = 'Argument.Range'; Text = 'permitted 1..500' }
        @{ Label = '-Jitter 9999'; Over = @{ Jitter = 9999 }; Id = 'Argument.Range'; Text = '-Jitter 9999 is out of range; permitted 0..5000 (ms).' }
        @{ Label = '-Jitter -1'; Over = @{ Jitter = -1 }; Id = 'Argument.Range'; Text = 'permitted 0..5000' }
        @{ Label = '-MaxProbes 200000'; Over = @{ MaxProbes = 200000 }; Id = 'Argument.Cap'; Text = '-MaxProbes 200000 exceeds the ceiling in force (8192); no parameter raises it.' }
        @{ Label = '-MaxProbes 200000 -AllowLarge'; Over = @{ MaxProbes = 200000; AllowLarge = $true }; Id = 'Argument.Cap'; Text = '(8192); no parameter raises it.' }
        @{ Label = '-MaxProbes 3000'; Over = @{ MaxProbes = 3000 }; Id = 'Argument.Cap'; Text = '-MaxProbes 3000 exceeds the ceiling in force (1024); -AllowLarge raises the ceiling to 8192.' }
        @{ Label = '-MaxProbes 0'; Over = @{ MaxProbes = 0 }; Id = 'Argument.Cap'; Text = 'permitted 1..1024' }
        @{ Label = '-MaxProbes -5 -AllowLarge'; Over = @{ MaxProbes = -5; AllowLarge = $true }; Id = 'Argument.Cap'; Text = 'permitted 1..8192' }
        @{ Label = '-Set bad'; Over = @{ Set = @('bad') }; Id = 'Argument.SetSyntax'; Text = "-Set 'bad' is not NAME=VALUE." }
        @{ Label = '-Set 1A=x'; Over = @{ Set = @('1A=x') }; Id = 'Argument.SetSyntax'; Text = 'is not NAME=VALUE' }
        @{ Label = '-Set A='; Over = @{ Set = @('A=') }; Id = 'Argument.SetSyntax'; Text = 'is not NAME=VALUE' }
        @{ Label = '-Set A=1<LF>'; Over = @{ Set = @("A=1`n") }; Id = 'Argument.SetSyntax'; Text = 'is not NAME=VALUE' }
        @{ Label = '-Set A=1;a=2'; Over = @{ Set = @('A=1;a=2') }; Id = 'Argument.SetSyntax'; Text = '-Set binds A twice.' }
        @{ Label = '-Set A=1 and a=2 as two elements'; Over = @{ Set = @('A=1', 'a=2') }; Id = 'Argument.SetSyntax'; Text = 'binds A twice' }
        @{ Label = '-Format Html without -Out'; Over = @{ Format = @('Html') }; Id = 'Output.NeedsOut'; Text = 'Html and multi-format output need -Out.' }
        @{ Label = '-Format Csv,Json without -Out'; Over = @{ Format = @('Csv,Json') }; Id = 'Output.NeedsOut'; Text = 'need -Out' }
        @{ Label = 'blank -Out'; Over = @{ Out = '  ' }; Id = 'Argument.Missing'; Text = '-Out is empty.' }
        @{ Label = "-Out '' -Format Html (bound, finding 10)"; Over = @{ Out = ''; OutGiven = $true; Format = @('Html') }; Id = 'Argument.Missing'; Text = '-Out is empty.' }
        @{ Label = "-Out '' -Format Csv (bound, finding 10)"; Over = @{ Out = ''; OutGiven = $true; Format = @('Csv') }; Id = 'Argument.Missing'; Text = '-Out is empty.' }
    ) {
        $err = Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides $Over) -Contract (Get-PPContract) }
        $err | Should -Not -BeNullOrEmpty
        $err.FullyQualifiedErrorId | Should -BeExactly ('PortProof.' + $Id)
        $err.Exception.Message.StartsWith('PortProof: ') | Should -BeTrue
        $err.Exception.Message.Contains($Text) | Should -BeTrue -Because $err.Exception.Message
    }

    It 'applies the defaults' {
        $o = Assert-Arguments -Raw (Get-Raw) -Contract (Get-PPContract)
        $o.PSObject.TypeNames[0] | Should -BeExactly 'PortProof.RunOptions'
        $o.TimeoutMs | Should -Be 2000
        $o.Concurrency | Should -Be 16
        $o.MaxProbesPerSecond | Should -Be 50
        $o.JitterMs | Should -Be 250
        $o.Ceiling | Should -Be 1024
        $o.EffectiveCap | Should -Be 1024
        $o.Emit | Should -BeExactly 'None'
        @($o.Formats).Count | Should -Be 0
        $o.Out | Should -BeNullOrEmpty
        ($o.PSObject.Properties.Name -join ',') | Should -BeExactly 'ProfilePath,Bindings,Out,Formats,Emit,TimeoutMs,Concurrency,MaxProbesPerSecond,JitterMs,Ceiling,EffectiveCap,AllowLarge,AllowCidr,Icmp,DryRun,NoOperator,Force,Quiet'
    }

    It 'fills a missing range key from the contract defaults' {
        $raw = Get-Raw
        $raw.Remove('Timeout')
        (Assert-Arguments -Raw $raw -Contract (Get-PPContract)).TimeoutMs | Should -Be 2000
    }

    It 'computes the ceiling and the effective cap' -ForEach @(
        @{ Over = @{ MaxProbes = 3000; AllowLarge = $true }; Ceiling = 8192; Cap = 3000 }
        @{ Over = @{ MaxProbes = 100; AllowLarge = $true }; Ceiling = 8192; Cap = 100 }
        @{ Over = @{ AllowLarge = $true }; Ceiling = 8192; Cap = 8192 }
        @{ Over = @{ MaxProbes = 1024 }; Ceiling = 1024; Cap = 1024 }
        @{ Over = @{ MaxProbes = 8192; AllowLarge = $true }; Ceiling = 8192; Cap = 8192 }
        @{ Over = @{ MaxProbes = 1 }; Ceiling = 1024; Cap = 1 }
    ) {
        $o = Assert-Arguments -Raw (Get-Raw -Overrides $Over) -Contract (Get-PPContract)
        $o.Ceiling | Should -Be $Ceiling
        $o.EffectiveCap | Should -Be $Cap
    }

    It 'accepts the range boundaries' {
        $o = Assert-Arguments -Raw (Get-Raw -Overrides @{ Timeout = 100; Concurrency = 64; MaxProbesPerSecond = 500; Jitter = 0 }) -Contract (Get-PPContract)
        $o.TimeoutMs | Should -Be 100
        $o.JitterMs | Should -Be 0
        $o = Assert-Arguments -Raw (Get-Raw -Overrides @{ Timeout = 30000; Concurrency = 1; MaxProbesPerSecond = 1; Jitter = 5000 }) -Contract (Get-PPContract)
        $o.TimeoutMs | Should -Be 30000
    }

    It 'normalises -Format (<Label>)' -ForEach @(
        @{ Label = 'comma list, mixed case, duplicates'; Over = @{ Format = @('json,CSV,json'); Out = 'o' }; Formats = 'Csv,Json'; Emit = 'Files' }
        @{ Label = 'array form'; Over = @{ Format = @('Html', 'Csv'); Out = 'o' }; Formats = 'Html,Csv'; Emit = 'Files' }
        @{ Label = '-Out without -Format'; Over = @{ Out = 'o' }; Formats = 'Html,Csv,Json'; Emit = 'Files' }
        @{ Label = 'Json to the success stream'; Over = @{ Format = @('Json') }; Formats = 'Json'; Emit = 'Stream' }
        @{ Label = 'Csv to the success stream'; Over = @{ Format = @(' csv ') }; Formats = 'Csv'; Emit = 'Stream' }
        @{ Label = 'Html under -DryRun without -Out'; Over = @{ Format = @('Html'); DryRun = $true }; Formats = 'Html'; Emit = 'None' }
    ) {
        $o = Assert-Arguments -Raw (Get-Raw -Overrides $Over) -Contract (Get-PPContract)
        (@($o.Formats) -join ',') | Should -BeExactly $Formats
        $o.Emit | Should -BeExactly $Emit
    }

    It 'splits -Set on semicolons and keeps the pieces as written' {
        $o = Assert-Arguments -Raw (Get-Raw -Overrides @{ Set = @('CLIENT=10.0.0.5;;DC=dc01.corp.example,10.0.0.9', 'X_1=%y%') }) -Contract (Get-PPContract)
        (@($o.Bindings) -join '|') | Should -BeExactly 'CLIENT=10.0.0.5|DC=dc01.corp.example,10.0.0.9|X_1=%y%'
    }
}

Describe 'Entry block and parameter block (AST)' -Tag 'Portable' {
    BeforeAll {
        $tokens = $null; $errors = $null
        $script:HeaderAst = [System.Management.Automation.Language.Parser]::ParseFile($script:HeaderPath, [ref]$tokens, [ref]$errors)
        $script:HeaderErrors = $errors
        $script:MainAst = [System.Management.Automation.Language.Parser]::ParseFile($script:MainPath, [ref]$tokens, [ref]$errors)
        $script:MainErrors = $errors
    }

    It 'parses cleanly' {
        @($script:HeaderErrors).Count | Should -Be 0
        @($script:MainErrors).Count | Should -Be 0
    }

    It 'declares [CmdletBinding(PositionalBinding = $false)] and #requires 5.1' {
        $cb = @($script:HeaderAst.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' })
        $cb.Count | Should -Be 1
        $cb[0].NamedArguments[0].ArgumentName | Should -BeExactly 'PositionalBinding'
        $cb[0].NamedArguments[0].Argument.Extent.Text | Should -BeExactly '$false'
        $script:HeaderAst.ScriptRequirements.RequiredPSVersion.ToString() | Should -BeExactly '5.1'
    }

    It 'carries no validation attribute and no [Parameter] on any parameter' {
        foreach ($p in $script:HeaderAst.ParamBlock.Parameters) {
            foreach ($a in @($p.Attributes | Where-Object { $_ -is [System.Management.Automation.Language.AttributeAst] })) {
                $a.TypeName.Name | Should -BeIn @('Alias') -Because ('parameter ' + $p.Name.VariablePath.UserPath)
            }
        }
    }

    It 'passes every header parameter to Invoke-PortProof through $ppRaw' {
        $names = @($script:HeaderAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $names.Count | Should -Be 17
        $assign = $script:MainAst.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$ppRaw' }, $true)
        $assign | Should -Not -BeNullOrEmpty
        $hash = $assign.Right.Find({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
        $keys = @($hash.KeyValuePairs | ForEach-Object { $_.Item1.Extent.Text })
        foreach ($name in $names) { $keys | Should -Contain $name }
        $keys | Should -Contain 'MaxProbesGiven'
        $keys | Should -Contain 'OutGiven'
    }

    It 'makes the guarded entry block the last statement of 90-Main.ps1' {
        $last = $script:MainAst.EndBlock.Statements[-1]
        $last | Should -BeOfType ([System.Management.Automation.Language.IfStatementAst])
        $last.Clauses[0].Item1.Extent.Text | Should -BeExactly '$MyInvocation.InvocationName -ne ''.'''
    }

    It 'dot-sourcing 90-Main.ps1 did not run the entry block' {
        Get-Variable -Name 'ppRaw' -Scope Script -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        Get-Variable -Name 'ppExit' -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'passes -Count, -Cap and -Ceiling to Assert-PPPreResolutionCount (addendum 10)' {
        $call = $script:MainAst.Find({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Assert-PPPreResolutionCount' }, $true)
        $params = @($call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } | ForEach-Object { $_.ParameterName })
        ($params -join ',') | Should -BeExactly 'Count,Cap,Ceiling'
    }

    It 'uses no dynamic evaluation in the contract-only artifact (AC19)' {
        foreach ($path in $script:HeaderPath, $script:ContractPath, $script:MainPath) {
            $tokens = $null; $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
            $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' }) | ForEach-Object { $_.Text }) -join ' '
            $code | Should -Not -Match '(?i)Invoke-Expression|\biex\b|ScriptBlock\]::Create|NewScriptBlock|Add-Type'
        }
    }
}

Describe 'Resolver seam under -DryRun (AC11-2)' -Tag 'Portable' {
    It 'Select-PPResolver -DryRun $true returns the refusing stub whatever -Live is' {
        $live = [pscustomobject]@{ PSTypeName = 'PortProof.Resolver'; Kind = 'Fixture'; Invocations = 0; Resolve = { throw 'must not run' } }
        $r = Select-PPResolver -DryRun $true -Live $live
        $r.Kind | Should -BeExactly 'Refusing'
        $r.PSObject.TypeNames[0] | Should -BeExactly 'PortProof.Resolver'
        { & $r.Resolve 'dc01.corp.example' } | Should -Throw -ErrorId 'PortProof.DryRunResolutionAttempted'
        (Select-PPResolver -DryRun $false -Live $live).Kind | Should -BeExactly 'Fixture'
    }
}

Describe 'Main flow with stubbed parser/expander/resolver functions (no sockets, no resolution)' -Tag 'Portable' {
    BeforeAll {
        $script:ProfileFile = Join-Path $TestDrive 'p.csv'
        [System.IO.File]::WriteAllText($script:ProfileFile, "Source,Target,Port,Protocol,Required`n")

        function Import-PPProfile {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()]
            param([string] $Path, [hashtable] $Contract)
            $script:Stub.ImportedPath = $Path
            [pscustomobject]@{ PSTypeName = 'PortProof.Profile'; Path = $Path; FileName = 'p.csv'; Format = 'Csv'; Sha256 = 'ab'; Name = 'stub'
                Version = ''; Groups = [ordered]@{}; IgnoredColumns = [string[]]@(); Rows = @(); Warnings = [string[]]@() }
        }
        function Expand-PPProfile {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()]
            param($ProfileDocument, [string[]] $Bindings, [switch] $AllowCidr, [long] $EffectiveCap, [hashtable] $Contract)
            $script:Stub.ExpandCap = $EffectiveCap
            $script:Stub.Expansion
        }
        function Assert-PPPreResolutionCount {
            param([Parameter(Mandatory)] [int] $Count, [Parameter(Mandatory)] [int] $Cap, [Parameter(Mandatory)] [int] $Ceiling)
            $script:Stub.PreCall = @{ Count = $Count; Cap = $Cap; Ceiling = $Ceiling }
        }
        function Resolve-PPProbeList {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()]
            param($Probes, $Resolver)
            $script:Stub.ResolveCalls++
            $entries = @{
                '127.0.0.2|80|TCP'   = @{ TargetIp = [System.Net.IPAddress]::Parse('127.0.0.2'); ResolvedAddresses = [string[]]@('127.0.0.2'); Failed = $false; TargetName = '127.0.0.2'; Rows = @(2) }
                'dc01.test|443|TCP' = @{ TargetIp = $null; ResolvedAddresses = [string[]]@(); Failed = $true; TargetName = 'dc01.test'; Rows = @(3) }
            }
            $exec = [pscustomobject]@{ ExecKey = '127.0.0.2|80|TCP'; TargetIp = [System.Net.IPAddress]::Parse('127.0.0.2'); Port = 80; Protocol = 'TCP'; JitterMs = 0 }
            [pscustomobject]@{ Entries = $entries; ExecProbes = @($exec); CountBefore = 2; CountAfter = 1 }
        }
        function Invoke-PPGate {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()]
            param($Resolution, [int] $Cap, [switch] $Icmp, [hashtable] $Schedule, [hashtable] $Adapters, $Recorder, [scriptblock] $OnAdmitted)
            $script:Stub.GateCap = $Cap
            & $OnAdmitted 1
            $r = [pscustomobject]@{ ExecKey = '127.0.0.2|80|TCP'; TargetIp = '127.0.0.2'; Port = 80; Protocol = 'TCP'; State = $script:Stub.TcpState
                ErrorName = 'None'; Outcome = (Get-PPOutcome -Protocol 'TCP' -State $script:Stub.TcpState -ErrorName 'None'); LatencyMs = 1; Timestamp = '2026-01-01T00:00:00.000Z' }
            [pscustomobject]@{ Results = @($r); AdmittedCount = 1; IcmpCount = 0; ExecutionPath = $Schedule.ExecutionPath }
        }
        function ConvertTo-PPJson { [CmdletBinding()] param($ResultSet) $script:Stub.ResultSet = $ResultSet; "{`"rows`": $(@($ResultSet.Rows).Count)}`n" }
        function ConvertTo-PPCsv { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()] param($ResultSet) "`"RunId`"`r`n" }
        function ConvertTo-PPHtml { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()] param($ResultSet) "<!DOCTYPE html>`n" }

        function Get-Expansion {
            param([string] $DcRequired = 'no')
            $row2 = [pscustomobject]@{ Row = 2; SourceName = 'client'; SourceGroup = ''; SourceIp = ''; TargetName = '127.0.0.2'; TargetGroup = ''
                TargetKind = 'IPv4'; Port = 80; Protocol = 'TCP'; Service = 'web'; Required = 'yes'; Notes = ''; ProbeKey = '127.0.0.2|80|TCP' }
            $row3 = [pscustomobject]@{ Row = 3; SourceName = 'client'; SourceGroup = ''; SourceIp = ''; TargetName = 'dc01.test'; TargetGroup = ''
                TargetKind = 'Hostname'; Port = 443; Protocol = 'TCP'; Service = 'tls'; Required = $DcRequired; Notes = ''; ProbeKey = 'dc01.test|443|TCP' }
            $p1 = [pscustomobject]@{ ProbeKey = '127.0.0.2|80|TCP'; Target = '127.0.0.2'; TargetKind = 'IPv4'; Address = [System.Net.IPAddress]::Parse('127.0.0.2'); Port = 80; Protocol = 'TCP'; Rows = @(2) }
            $p2 = [pscustomobject]@{ ProbeKey = 'dc01.test|443|TCP'; Target = 'dc01.test'; TargetKind = 'Hostname'; Address = $null; Port = 443; Protocol = 'TCP'; Rows = @(3) }
            [pscustomobject]@{ Rows = @($row2, $row3); Probes = @($p1, $p2); GroupOverrides = [string[]]@(); UnusedGroups = [string[]]@(); DistinctTargets = 2 }
        }
        $script:LiveStub = [pscustomobject]@{ PSTypeName = 'PortProof.Resolver'; Kind = 'Fixture'; Invocations = 0; Resolve = { throw 'unused' } }
    }

    BeforeEach {
        $script:Stub = @{ ExpandCap = $null; Expansion = (Get-Expansion); PreCall = $null; ResolveCalls = 0; ResultSet = $null; TcpState = 'Open'; GateCap = $null; ImportedPath = $null }
    }

    It '-Version prints ToolVersion, exits 0 and writes nothing to the information stream (AC1)' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ Version = $true; ProfilePath = '' })
        $r.ExitCode | Should -Be 0
        (@($r.Success) -join '|') | Should -BeExactly '1.0.0'
        $r.Info.Count | Should -Be 0
        $r.Errors.Count | Should -Be 0
    }

    It '-DryRun with -Quiet: notice first, list, counts, no resolution, exit 0' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; DryRun = $true; Quiet = $true })
        $r.ExitCode | Should -Be 0
        $r.Errors.Count | Should -Be 0
        $r.Success.Count | Should -Be 0
        $notice = @($r.Info | Where-Object { $_.Tags -contains 'PortProof.Notice' } | ForEach-Object { [string]$_.MessageData })
        ($notice -join "`n") | Should -BeExactly ((Get-PPAuthorizedUseNotice) -join "`n")
        [string]$r.Info[0].MessageData | Should -BeExactly (Get-PPContract).NoticeLine1
        $lines = @($r.Info | ForEach-Object { [string]$_.MessageData })
        $lines | Should -Contain 'row 2  client -> 127.0.0.2  TCP/80  yes  127.0.0.2'
        $lines | Should -Contain 'row 3  client -> dc01.test  TCP/443  no  unresolved (dry-run)'
        $lines | Should -Contain 'probes 2 (one connection attempt each; name coalescing may lower this on a live run)'
        $lines | Should -Contain 'ProbeCountBasis: pre-resolution-upper-bound'
        $lines | Should -Contain 'ProbeCount: 2'
        $lines | Should -Contain 'Flags.EffectiveCap: 1024'
        $lines | Should -Contain 'names are class-checked on the live run, not here'
        @($lines | Where-Object { $_ -like 'worst-case duration *' }).Count | Should -Be 1
        $script:Stub.ResolveCalls | Should -Be 0
        $script:Stub.PreCall.Count | Should -Be 2
        $script:Stub.PreCall.Cap | Should -Be 1024
        $script:Stub.PreCall.Ceiling | Should -Be 1024
        $script:Stub.ExpandCap | Should -Be 1024
        $script:Stub.ImportedPath | Should -BeExactly ([System.IO.Path]::GetFullPath($script:ProfileFile))
    }

    It 'passes the run effective cap to Expand-PPProfile' -ForEach @(
        @{ Over = @{}; Cap = 1024 }
        @{ Over = @{ AllowLarge = $true }; Cap = 8192 }
        @{ Over = @{ AllowLarge = $true; MaxProbes = 3000 }; Cap = 3000 }
        @{ Over = @{ MaxProbes = 100 }; Cap = 100 }
    ) {
        $Over['ProfilePath'] = $script:ProfileFile
        $Over['DryRun'] = $true
        (Invoke-MainEntry -Raw (Get-Raw -Overrides $Over)).ExitCode | Should -Be 0
        $script:Stub.ExpandCap | Should -Be $Cap
    }

    It '-DryRun -Icmp adds one echo per distinct target and refuses above the cap' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; DryRun = $true; Icmp = $true })
        $r.ExitCode | Should -Be 0
        $lines = @($r.Info | ForEach-Object { [string]$_.MessageData })
        $lines | Should -Contain 'icmp echoes 2 (upper bound)'
        $lines | Should -Contain 'ProbeCount: 4'
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; DryRun = $true; Icmp = $true; MaxProbes = 3 })
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.CapExceeded.PreResolution*'
        $r.Errors[0].Exception.Message | Should -BeLike '*4 probes exceed the cap of 3 (before name resolution; nothing was resolved or sent)*'
    }

    It 'refuses a profile on a missing drive or a non-FileSystem provider as Profile.NotFound (addendum 7, D42)' -ForEach @(
        @{ Path = 'PPNODRIVE:\p.csv' }, @{ Path = 'variable:\p.csv' }, @{ Path = '<TestDrive>/absent.csv' }
    ) {
        $profileArg = $Path.Replace('<TestDrive>', $TestDrive)
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $profileArg; DryRun = $true })
        $r.ExitCode | Should -Be 2
        $r.Errors.Count | Should -Be 1
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.Profile.NotFound*'
        $r.Errors[0].Exception.Message | Should -Not -BeLike '*internal error*'
    }

    It 'argument refusals exit 2 with the PortProof error id and print no notice' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ Concurrency = 0 })
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.Argument.Range*'
        $r.Info.Count | Should -Be 0
    }

    It 'live path, -Format Json without -Out: the success stream carries only the document; exit 0' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; Format = @('Json') }) -LiveResolver $script:LiveStub
        $r.Errors.Count | Should -Be 0
        $r.ExitCode | Should -Be 0
        (@($r.Success) -join '|') | Should -BeExactly "{`"rows`": 2}`n"
        $lines = @($r.Info | ForEach-Object { [string]$_.MessageData })
        $lines | Should -Contain 'ProbeCountBasis: admitted'
        $lines | Should -Contain 'ProbeCount: 1'
        $lines | Should -Contain 'Flags.ExecutionPath: Runspace'
        $lines | Should -Contain 'exit code 0'
        $script:Stub.GateCap | Should -Be 1024
        $rows = @($script:Stub.ResultSet.Rows)
        $rows.Count | Should -Be 2
        ($rows[0].PSObject.Properties.Name -join ',') | Should -BeExactly ((Get-PPShapeFields -Shape 'ResultRow') -join ',')
        $rows[0].ProfileRow | Should -Be 2
        $rows[0].Outcome | Should -BeExactly 'Pass'
        $rows[0].TargetIp | Should -BeExactly '127.0.0.2'
        $rows[1].Error | Should -BeExactly 'DnsFailure'
        $rows[1].State | Should -BeExactly ''
        $rows[1].Outcome | Should -BeExactly 'Fail'
        $rows[1].LatencyMs | Should -BeNullOrEmpty
        $script:Stub.ResultSet.Summary.Fail | Should -Be 1
        $script:Stub.ResultSet.Header.AuthorizedUseNotice | Should -BeExactly ((Get-PPAuthorizedUseNotice) -join ' ')
    }

    It 'live path exits 1 when a required row does not pass' {
        $script:Stub.Expansion = Get-Expansion -DcRequired 'yes'
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile }) -LiveResolver $script:LiveStub
        $r.ExitCode | Should -Be 1
        $r.Success.Count | Should -Be 0
        @($r.Info | ForEach-Object { [string]$_.MessageData }) | Should -Contain 'not passed: row 3  client -> dc01.test  TCP/443  Fail    DnsFailure'
    }

    It 'run header lines follow the RunHeader/Flags field order (literal member access only)' {
        $options = Assert-Arguments -Raw (Get-Raw -Overrides @{ AllowLarge = $true; Icmp = $true }) -Contract (Get-PPContract)
        $doc = [pscustomobject]@{ Name = 'n'; Version = 'v'; Sha256 = 'ab'; IgnoredColumns = [string[]]@('x', 'y') }
        $exp = [pscustomobject]@{ GroupOverrides = [string[]]@('DC') }
        $header = Get-PPRunHeader -Options $options -ProfileDocument $doc -Expansion $exp -ProbeCount 3 -Basis 'admitted' -ExecutionPath 'Runspace' `
            -StartedUtc ([datetime]::new(2026, 1, 2, 3, 4, 5, [DateTimeKind]::Utc)) -RunId 'r' -WorstCaseSeconds 9
        $lines = @(Write-PPRunHeader -Header $header 6>&1 | ForEach-Object { [string]$_.MessageData })
        $expected = foreach ($field in (Get-PPShapeFields -Shape 'RunHeader')) {
            if ($field -ceq 'Flags') {
                foreach ($flag in (Get-PPShapeFields -Shape 'Flags')) { 'Flags.{0}: {1}' -f $flag, (ConvertTo-PPInfoValue -Value $header.Flags.$flag) }
            }
            else { '{0}: {1}' -f $field, (ConvertTo-PPInfoValue -Value $header.$field) }
        }
        ($lines -join "`n") | Should -BeExactly (@($expected) -join "`n")
        $lines | Should -Contain 'Flags.GroupOverrides: DC'
        $lines | Should -Contain 'IgnoredColumns: x; y'
    }

    It '-NoOperator redacts the operator fields' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; DryRun = $true; NoOperator = $true })
        $lines = @($r.Info | ForEach-Object { [string]$_.MessageData })
        $lines | Should -Contain 'OperatorUser: redacted'
        $lines | Should -Contain 'OperatorHost: redacted'
        $lines | Should -Contain 'OriginNote: All probes were sent from redacted; Source values are labels from the profile.'
        # No UTC offset under -NoOperator; StartedLocal equals StartedUtc.
        $utc = @($lines | Where-Object { $_ -clike 'StartedUtc: *' })[0].Substring(12)
        $local = @($lines | Where-Object { $_ -clike 'StartedLocal: *' })[0].Substring(14)
        $utc | Should -Match '\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z\z'
        $local | Should -BeExactly $utc
    }

    It 'without -NoOperator StartedLocal keeps the local offset' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; DryRun = $true })
        $local = @($r.Info | ForEach-Object { [string]$_.MessageData } | Where-Object { $_ -clike 'StartedLocal: *' })[0]
        $local | Should -Match '[+-][0-9]{2}:[0-9]{2}\z'
    }

    It '-Out writes the fixed file names, refuses a collision without -Force, overwrites with -Force' {
        $out = Join-Path $TestDrive 'out1'
        $raw = Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; Out = $out; Format = @('Json,Csv') }
        $r = Invoke-MainEntry -Raw $raw -LiveResolver $script:LiveStub
        $r.ExitCode | Should -Be 0
        $r.Success.Count | Should -Be 0
        @(Get-ChildItem -LiteralPath $out | ForEach-Object { $_.Name } | Sort-Object) -join ',' | Should -BeExactly 'portproof-results.csv,portproof-results.json'
        $csv = [System.IO.File]::ReadAllBytes((Join-Path $out 'portproof-results.csv'))
        ($csv[0..2] -join ',') | Should -BeExactly '239,187,191'
        $json = [System.IO.File]::ReadAllBytes((Join-Path $out 'portproof-results.json'))
        [char]$json[0] | Should -BeExactly '{'
        [System.IO.File]::WriteAllText((Join-Path $out 'portproof-results.json'), 'keep')
        $r = Invoke-MainEntry -Raw $raw -LiveResolver $script:LiveStub
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.Output.Collision*'
        [System.IO.File]::ReadAllText((Join-Path $out 'portproof-results.json')) | Should -BeExactly 'keep'
        $raw.Force = $true
        (Invoke-MainEntry -Raw $raw -LiveResolver $script:LiveStub).ExitCode | Should -Be 0
        [System.IO.File]::ReadAllText((Join-Path $out 'portproof-results.json')) | Should -Not -BeExactly 'keep'
    }

    It '-Out naming an existing file is Output.NotDirectory and nothing is resolved' {
        $file = Join-Path $TestDrive 'plainfile'
        [System.IO.File]::WriteAllText($file, 'x')
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:ProfileFile; Out = $file }) -LiveResolver $script:LiveStub
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.Output.NotDirectory*'
        $script:Stub.ResolveCalls | Should -Be 0
    }

    It 'Measure-PPWorstCase: 1024 probes to one target at defaults is about 41 minutes' {
        $options = Assert-Arguments -Raw (Get-Raw) -Contract (Get-PPContract)
        $probes = foreach ($i in 1..1024) { [pscustomobject]@{ Target = '192.0.2.1'; TargetKind = 'IPv4' } }
        $seconds = Measure-PPWorstCase -Probes @($probes) -IcmpTargets 0 -Options $options
        $seconds | Should -Be 2448
        ConvertTo-PPDuration -Seconds $seconds | Should -BeExactly '00:40:48'
    }
}

Describe 'Output files refuse reparse points (junctions)' -Tag 'Windows' {
    BeforeAll {
        # Minimal stand-ins for the preflight steps; the refusal comes first, so
        # nothing is resolved or probed (Resolve-PPProbeList is deliberately not defined).
        $script:RpProfile = Join-Path $TestDrive 'rp.csv'
        [System.IO.File]::WriteAllText($script:RpProfile, "Source,Target,Port,Protocol,Required`n")
        function Import-PPProfile {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()]
            param([string] $Path, [hashtable] $Contract)
            [pscustomobject]@{ Name = 'rp'; Version = ''; Sha256 = 'ab'; FileName = 'rp.csv'; IgnoredColumns = [string[]]@() }
        }
        function Expand-PPProfile {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()]
            param($ProfileDocument, [string[]] $Bindings, [switch] $AllowCidr, [long] $EffectiveCap, [hashtable] $Contract)
            [pscustomobject]@{ Rows = @(); Probes = @(); GroupOverrides = [string[]]@(); UnusedGroups = [string[]]@(); DistinctTargets = 0 }
        }
        function Assert-PPPreResolutionCount {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Test stub mirrors the real function''s signature.')] [CmdletBinding()]
            param([int] $Count, [int] $Cap, [int] $Ceiling)
        }
        $script:RpLive = [pscustomobject]@{ PSTypeName = 'PortProof.Resolver'; Kind = 'Fixture'; Invocations = 0; Resolve = { throw 'unused' } }

        function Initialize-Junction {
            param([string] $Link, [string] $Target, [switch] $Dangling)
            $null = [System.IO.Directory]::CreateDirectory($Target)
            $null = New-Item -ItemType Junction -Path $Link -Value $Target
            if ($Dangling) { [System.IO.Directory]::Delete($Target, $true) }
        }
    }

    It '-Out that is a junction exits 2 Output.ReparsePoint and writes nothing' {
        $real = Join-Path $TestDrive 'realout'
        $link = Join-Path $TestDrive 'outlink'
        Initialize-Junction -Link $link -Target $real
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:RpProfile; Out = $link; Format = @('Json,Csv') }) -LiveResolver $script:RpLive
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.Output.ReparsePoint*'
        $r.Errors[0].Exception.Message | Should -BeLike "*-Out '*outlink' is a symbolic link or junction*"
        @(Get-ChildItem -LiteralPath $real -Force).Count | Should -Be 0
    }

    It 'a <State> junction at an output file name exits 2 Output.ReparsePoint, with and without -Force' -ForEach @(
        @{ State = 'dangling'; Dangling = $true }, @{ State = 'live'; Dangling = $false }
    ) {
        $out = Join-Path $TestDrive ('out-' + $State)
        $null = [System.IO.Directory]::CreateDirectory($out)
        $victim = Join-Path $TestDrive ('victim-' + $State)
        Initialize-Junction -Link (Join-Path $out 'portproof-results.json') -Target $victim -Dangling:$Dangling
        foreach ($force in $false, $true) {
            $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:RpProfile; Out = $out; Format = @('Csv,Json'); Force = $force }) -LiveResolver $script:RpLive
            $r.ExitCode | Should -Be 2
            $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.Output.ReparsePoint*'
            [System.IO.File]::Exists((Join-Path $out 'portproof-results.csv')) | Should -BeFalse
        }
        if ($Dangling) { [System.IO.Directory]::Exists($victim) | Should -BeFalse }
        else { @(Get-ChildItem -LiteralPath $victim -Force).Count | Should -Be 0 }
    }

    It 'Write-PPOutputFile itself refuses a dangling junction path and a junction parent' {
        $out = Join-Path $TestDrive 'wdirect'
        $null = [System.IO.Directory]::CreateDirectory($out)
        $victim = Join-Path $TestDrive 'wvictim'
        $path = Join-Path $out 'portproof-report.html'
        Initialize-Junction -Link $path -Target $victim -Dangling
        $err = Get-Refusal { Write-PPOutputFile -Path $path -Text 'x' -Bom $false -Force $true }
        $err.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Output.ReparsePoint'
        [System.IO.Directory]::Exists($victim) | Should -BeFalse
        $realParent = Join-Path $TestDrive 'wreal'
        $linkParent = Join-Path $TestDrive 'wlink'
        Initialize-Junction -Link $linkParent -Target $realParent
        $err = Get-Refusal { Write-PPOutputFile -Path (Join-Path $linkParent 'portproof-results.csv') -Text 'x' -Bom $true -Force $false }
        $err.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Output.ReparsePoint'
        @(Get-ChildItem -LiteralPath $realParent -Force).Count | Should -Be 0
    }

    It 'a junction -Out written with a trailing separator is still refused' {
        $real = Join-Path $TestDrive 'realout2'
        $link = Join-Path $TestDrive 'outlink2'
        Initialize-Junction -Link $link -Target $real
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:RpProfile; Out = ($link + '\'); Format = @('Json') }) -LiveResolver $script:RpLive
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.Output.ReparsePoint*'
    }

    It 'the reparse check records no error for a missing path, a missing parent or a plain file (-ErrorVariable stays empty)' {
        $plain = Join-Path $TestDrive 'plain.txt'
        [System.IO.File]::WriteAllText($plain, 'x')
        foreach ($p in @((Join-Path $TestDrive 'nope.json'), (Join-Path $TestDrive 'nodir\nope.json'), $plain, $TestDrive)) {
            $result = Test-PPReparsePoint -Path $p -ErrorVariable ev -ErrorAction SilentlyContinue
            $result | Should -BeFalse
            @($ev).Count | Should -Be 0 -Because $p
        }
    }

    It 'an ordinary -Out directory still passes preflight' {
        $out = Join-Path $TestDrive 'plainout'
        $null = [System.IO.Directory]::CreateDirectory($out)
        $options = Assert-Arguments -Raw (Get-Raw -Overrides @{ Out = $out; Format = @('Json') }) -Contract (Get-PPContract)
        (Test-PPOutputPreflight -Options $options).Files['Json'] | Should -BeExactly (Join-Path $out 'portproof-results.json')
    }
}

Describe 'Pass-1 expansion limit follows the effective cap (real parser and expander)' -Tag 'Portable' {
    BeforeAll {
        # Real 10-Parser and 20-Expander; -DryRun installs the refusing resolver, so nothing is
        # resolved and no probe exists. Targets are loopback literals only.
        . (Join-Path $script:Root 'src/10-Parser.ps1')
        . (Join-Path $script:Root 'src/20-Expander.ps1')
        $script:BigProfile = Join-Path $TestDrive 'big.csv'
        [System.IO.File]::WriteAllText($script:BigProfile, "Source,Target,Port,Protocol,Required`n%SRC%,%DST%,80,TCP,yes`n")
        # One row, 91 sources x 91 targets: E = 8281 expanded rows, above 1024 x 8 = 8192 and
        # below 8192 x 8 = 65536; P = 91 targets; 91 deduplicated probes.
        $sources = (1..91 | ForEach-Object { '10.1.0.{0}' -f $_ }) -join ','
        $targets = (2..92 | ForEach-Object { '127.0.0.{0}' -f $_ }) -join ','
        $script:BigSet = @('SRC=' + $sources + ';DST=' + $targets)
    }

    It 'without -AllowLarge the 8281-row expansion is refused at pass 1 (limit 1024 x 8)' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:BigProfile; Set = $script:BigSet; DryRun = $true })
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.CapExceeded.Expansion*'
        $r.Errors[0].Exception.Message | Should -BeLike '*8192*'
    }

    It 'with -AllowLarge the same expansion is admitted (limit 8192 x 8) and the DryRun lists it' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:BigProfile; Set = $script:BigSet; DryRun = $true; AllowLarge = $true })
        $r.Errors.Count | Should -Be 0 -Because (@($r.Errors | ForEach-Object { $_.Exception.Message }) -join '; ')
        $r.ExitCode | Should -Be 0
        $lines = @($r.Info | ForEach-Object { [string]$_.MessageData })
        $lines | Should -Contain 'ProbeCount: 91'
        $lines | Should -Contain 'Flags.EffectiveCap: 8192'
        @($lines | Where-Object { $_ -like 'row 2  *' }).Count | Should -Be 8281
        $lines | Should -Contain 'probes 91 (one connection attempt each; name coalescing may lower this on a live run)'
    }

    It 'with -AllowLarge -MaxProbes 1000 the limit is 1000 x 8 and the expansion is refused again' {
        $r = Invoke-MainEntry -Raw (Get-Raw -Overrides @{ ProfilePath = $script:BigProfile; Set = $script:BigSet; DryRun = $true; AllowLarge = $true; MaxProbes = 1000 })
        $r.ExitCode | Should -Be 2
        $r.Errors[0].FullyQualifiedErrorId | Should -BeLike 'PortProof.CapExceeded.Expansion*'
    }
}

Describe 'Contract-only artifact: help surface (AC20 help half)' -Tag 'Portable' {
    It 'Get-Help description carries a line byte-identical to AuthorizedUseClause' {
        $artifact = Get-ContractArtifact
        $help = Get-Help -Name $artifact
        $text = (@($help.description) | ForEach-Object { $_.Text }) -join "`n"
        $clause = (Get-PPContract).AuthorizedUseClause
        @($text -split "`r?`n" | Where-Object { $_ -ceq $clause }).Count | Should -Be 1
        $text | Should -Not -Match 'AUTHORIZED-USE-NOTICE'
        @($help.parameters.parameter | ForEach-Object { $_.name }) | Should -Contain 'ProfilePath'
    }
}

Describe 'Contract-only artifact: exit codes on both entry paths (AC1, AC8, AC10)' -Tag 'Windows' {
    BeforeAll {
        $script:Art = Get-ContractArtifact
    }

    It '<Entry>: <Label> exits <Code>' -ForEach @(
        foreach ($entry in 'File', 'Command') {
            @{ Entry = $entry; Label = 'no -Profile'; Arguments = @(); Code = 2; Text = '-Profile is required' }
            @{ Entry = $entry; Label = '-MaxProbes 200000'; Arguments = @('-Profile', 'p.csv', '-MaxProbes', '200000'); Code = 2; Text = 'ceiling in force (8192)' }
            @{ Entry = $entry; Label = '-MaxProbes 200000 -AllowLarge'; Arguments = @('-Profile', 'p.csv', '-MaxProbes', '200000', '-AllowLarge'); Code = 2; Text = 'ceiling in force (8192)' }
            @{ Entry = $entry; Label = '-MaxProbes 3000'; Arguments = @('-Profile', 'p.csv', '-MaxProbes', '3000'); Code = 2; Text = 'ceiling in force (1024)' }
            @{ Entry = $entry; Label = '-Concurrency 0'; Arguments = @('-Profile', 'p.csv', '-Concurrency', '0'); Code = 2; Text = '-Concurrency 0 is out of range' }
            @{ Entry = $entry; Label = '-Timeout 50'; Arguments = @('-Profile', 'p.csv', '-Timeout', '50'); Code = 2; Text = '-Timeout 50 is out of range' }
            @{ Entry = $entry; Label = '-MaxProbesPerSecond 0'; Arguments = @('-Profile', 'p.csv', '-MaxProbesPerSecond', '0'); Code = 2; Text = '-MaxProbesPerSecond 0 is out of range' }
            @{ Entry = $entry; Label = '-Jitter 9999'; Arguments = @('-Profile', 'p.csv', '-Jitter', '9999'); Code = 2; Text = '-Jitter 9999 is out of range' }
            @{ Entry = $entry; Label = '-Format Pdf'; Arguments = @('-Profile', 'p.csv', '-Format', 'Pdf'); Code = 2; Text = "-Format 'Pdf'" }
            @{ Entry = $entry; Label = '-Format Html without -Out'; Arguments = @('-Profile', 'p.csv', '-Format', 'Html'); Code = 2; Text = 'need -Out' }
            @{ Entry = $entry; Label = '-Set bad'; Arguments = @('-Profile', 'p.csv', '-Set', 'bad'); Code = 2; Text = 'is not NAME=VALUE' }
            @{ Entry = $entry; Label = "-Out '' -Format Html"; Arguments = @('-Profile', 'p.csv', '-Out', '', '-Format', 'Html'); Code = 2; Text = '-Out is empty.' }
            @{ Entry = $entry; Label = "-Out '' -Format Csv"; Arguments = @('-Profile', 'p.csv', '-Out', '', '-Format', 'Csv'); Code = 2; Text = '-Out is empty.' }
        }
        # PowerShell's own binding errors: exit 1 under -File only. Under -Command "& ...; exit
        # $LASTEXITCODE" the script never runs, $LASTEXITCODE stays unset and the host exits 0
        # (measured on 5.1), so these two are asserted on the -File path only.
        @{ Entry = 'File'; Label = '-Bogus'; Arguments = @('-Profile', 'p.csv', '-Bogus'); Code = 1; Text = 'Bogus' }
        @{ Entry = 'File'; Label = '-MaxProbes abc'; Arguments = @('-Profile', 'p.csv', '-MaxProbes', 'abc'); Code = 1; Text = 'MaxProbes' }
    ) {
        $r = Invoke-ProcessEntry -Artifact $script:Art -Arguments $Arguments -Entry $Entry
        $r.ExitCode | Should -Be $Code -Because ($r.StdOut + $r.StdErr)
        ($r.StdOut + $r.StdErr) | Should -BeLike ('*' + [WildcardPattern]::Escape($Text) + '*')
    }

    It '<Entry>: -Version prints the SemVer and exits 0' -ForEach @(@{ Entry = 'File' }, @{ Entry = 'Command' }) {
        $r = Invoke-ProcessEntry -Artifact $script:Art -Arguments @('-Version') -Entry $Entry
        $r.ExitCode | Should -Be 0
        $r.StdOut.Trim() | Should -BeExactly (Get-PPContract).ToolVersion
        $r.StdErr.Trim() | Should -BeExactly ''
    }
}

Describe 'Culture invariance of the grammar and argument checks' -Tag 'Portable' {
    BeforeAll {
        function Invoke-InCulture {
            # Runs $Action with CurrentCulture and CurrentUICulture set to $Name ('' = invariant), then restores both.
            param([string] $Name, [scriptblock] $Action)
            $thread = [System.Threading.Thread]::CurrentThread
            $savedCulture = $thread.CurrentCulture
            $savedUi = $thread.CurrentUICulture
            try {
                $culture = [System.Globalization.CultureInfo]::GetCultureInfo($Name)
                $thread.CurrentCulture = $culture
                $thread.CurrentUICulture = $culture
                & $Action
            }
            finally {
                $thread.CurrentCulture = $savedCulture
                $thread.CurrentUICulture = $savedUi
            }
        }
    }

    It '<Culture>: <Label> -> <Kind>' -ForEach @(
        foreach ($c in 'tr-TR', 'az-Latn-AZ', '') {
            @{ Culture = $c; Label = '%CLIENT%'; Text = '%CLIENT%'; Kind = 'Group'; Out = 'CLIENT' }
            @{ Culture = $c; Label = '%client%'; Text = '%client%'; Kind = 'Group'; Out = 'CLIENT' }
            @{ Culture = $c; Label = '%DIRECTORY%'; Text = '%DIRECTORY%'; Kind = 'Group'; Out = 'DIRECTORY' }
            @{ Culture = $c; Label = '%iI_9%'; Text = '%iI_9%'; Kind = 'Group'; Out = 'II_9' }
            @{ Culture = $c; Label = 'DC01.CORP.EXAMPLE'; Text = 'DC01.CORP.EXAMPLE'; Kind = 'Hostname'; Out = 'dc01.corp.example' }
            @{ Culture = $c; Label = 'FILES.INTRANET.EXAMPLE.'; Text = 'FILES.INTRANET.EXAMPLE.'; Kind = 'Hostname'; Out = 'files.intranet.example' }
            @{ Culture = $c; Label = 'FF02--1.IPV6-LITERAL.NET'; Text = 'FF02--1.IPV6-LITERAL.NET'; Kind = 'Invalid'; Out = 'FF02--1.IPV6-LITERAL.NET' }
            @{ Culture = $c; Label = '0XFFFFFFFF'; Text = '0XFFFFFFFF'; Kind = 'NonCanonicalLiteral'; Out = '0XFFFFFFFF' }
            @{ Culture = $c; Label = '0X1F.EXAMPLE'; Text = '0X1F.EXAMPLE'; Kind = 'Invalid'; Out = '0X1F.EXAMPLE' }
            @{ Culture = $c; Label = 'FE80::1'; Text = 'FE80::1'; Kind = 'IPv6'; Out = 'fe80::1' }
            @{ Culture = $c; Label = '10.0.0.1'; Text = '10.0.0.1'; Kind = 'IPv4'; Out = '10.0.0.1' }
            # Compatibility letters and look-alikes that case-fold to ASCII under IgnoreCase matching.
            @{ Culture = $c; Label = 'U+212A.test'; Text = ([string][char]0x212A + '.test'); Kind = 'Invalid'; Out = ([string][char]0x212A + '.test') }
            @{ Culture = $c; Label = 'aU+212Ab.test'; Text = ('a' + [char]0x212A + 'b.test'); Kind = 'Invalid'; Out = ('a' + [char]0x212A + 'b.test') }
            @{ Culture = $c; Label = 'host.teU+212A'; Text = ('host.te' + [char]0x212A); Kind = 'Invalid'; Out = ('host.te' + [char]0x212A) }
            @{ Culture = $c; Label = 'U+017Ferver.test'; Text = ([string][char]0x017F + 'erver.test'); Kind = 'Invalid'; Out = ([string][char]0x017F + 'erver.test') }
            @{ Culture = $c; Label = 'U+0130nfo.test'; Text = ([string][char]0x0130 + 'nfo.test'); Kind = 'Invalid'; Out = ([string][char]0x0130 + 'nfo.test') }
            @{ Culture = $c; Label = 'fU+0131les.test'; Text = ('f' + [char]0x0131 + 'les.test'); Kind = 'Invalid'; Out = ('f' + [char]0x0131 + 'les.test') }
            @{ Culture = $c; Label = 'U+FF21b.test'; Text = ([string][char]0xFF21 + 'b.test'); Kind = 'Invalid'; Out = ([string][char]0xFF21 + 'b.test') }
            @{ Culture = $c; Label = 'U+212Bngstrom.test'; Text = ([string][char]0x212B + 'ngstrom.test'); Kind = 'Invalid'; Out = ([string][char]0x212B + 'ngstrom.test') }
            @{ Culture = $c; Label = '%U+212A%'; Text = ('%' + [char]0x212A + '%'); Kind = 'Invalid'; Out = ('%' + [char]0x212A + '%') }
            @{ Culture = $c; Label = '%U+0130D%'; Text = ('%' + [char]0x0130 + 'D%'); Kind = 'Invalid'; Out = ('%' + [char]0x0130 + 'D%') }
            @{ Culture = $c; Label = '%CLU+0131ENT%'; Text = ('%CL' + [char]0x0131 + 'ENT%'); Kind = 'Invalid'; Out = ('%CL' + [char]0x0131 + 'ENT%') }
            @{ Culture = $c; Label = 'U+0661 0.0.0.1'; Text = ([string][char]0x0661 + '0.0.0.1'); Kind = 'Invalid'; Out = ([string][char]0x0661 + '0.0.0.1') }
            @{ Culture = $c; Label = 'host.U+0661U+0662'; Text = ('host.' + [char]0x0661 + [char]0x0662); Kind = 'Invalid'; Out = ('host.' + [char]0x0661 + [char]0x0662) }
        }
    ) {
        $k = Invoke-InCulture -Name $Culture -Action { Get-PPTargetKind -Text $Text }
        $k.Kind | Should -BeExactly $Kind
        $k.Text | Should -BeExactly $Out
    }

    It '<Culture>: argument checks accept ASCII case variants and refuse look-alikes' -ForEach @(
        foreach ($c in 'tr-TR', 'az-Latn-AZ', '') { @{ Culture = $c } }
    ) {
        Invoke-InCulture -Name $Culture -Action {
            $contract = Get-PPContract
            $o = Assert-Arguments -Raw (Get-Raw -Overrides @{ ProfilePath = 'P.CSV'; Set = @('DIRECTORY=10.0.0.1;client=x.test;II=y.test'); Format = @('JSON,HTML'); Out = 'o' }) -Contract $contract
            (@($o.Formats) -join ',') | Should -BeExactly 'Html,Json'
            (@($o.Bindings) -join '|') | Should -BeExactly 'DIRECTORY=10.0.0.1|client=x.test|II=y.test'
            (Assert-Arguments -Raw (Get-Raw -Overrides @{ ProfilePath = 'p.JSON' }) -Contract $contract).ProfilePath | Should -BeExactly 'p.JSON'
            (Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides @{ Set = @('ii=1;II=2') }) -Contract $contract }).FullyQualifiedErrorId | Should -BeExactly 'PortProof.Argument.SetSyntax'
            (Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides @{ Set = @(([string][char]0x212A + '=1')) }) -Contract $contract }).FullyQualifiedErrorId | Should -BeExactly 'PortProof.Argument.SetSyntax'
            (Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides @{ Set = @(('D' + [char]0x0130 + 'R=1')) }) -Contract $contract }).FullyQualifiedErrorId | Should -BeExactly 'PortProof.Argument.SetSyntax'
            (Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides @{ ProfilePath = ('p.c' + [char]0x017F + 'v') }) -Contract $contract }).FullyQualifiedErrorId | Should -BeExactly 'PortProof.Argument.Set'
            (Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides @{ ProfilePath = ('p.j' + [char]0x017F + 'on') }) -Contract $contract }).FullyQualifiedErrorId | Should -BeExactly 'PortProof.Argument.Set'
            (Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides @{ Format = @(('Js' + [char]0x212A)) }) -Contract $contract }).FullyQualifiedErrorId | Should -BeExactly 'PortProof.Argument.Set'
            (Get-Refusal { Assert-Arguments -Raw (Get-Raw -Overrides @{ Format = @(('Cs' + [char]0x0131)) }) -Contract $contract }).FullyQualifiedErrorId | Should -BeExactly 'PortProof.Argument.Set'
        }
    }

    It '<Culture>: predicate, outcome table, exit code and formatting are unchanged' -ForEach @(
        foreach ($c in 'tr-TR', 'az-Latn-AZ', '') { @{ Culture = $c } }
    ) {
        Invoke-InCulture -Name $Culture -Action {
            (Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse('::ffff:224.0.0.1'))).Class | Should -BeExactly 'multicast'
            Get-PPOutcome -Protocol 'UDP' -State 'Open|Filtered' -ErrorName 'NoResponse' | Should -BeExactly 'Inconclusive'
            Get-PPOutcome -Protocol 'ICMP' -State 'NoReply' -ErrorName 'Timeout' | Should -BeExactly 'Fail'
            Get-PPExitCode -Rows @([pscustomobject]@{ Required = 'yes'; Outcome = 'Inconclusive' }) | Should -Be 1
            @(Get-PPShapeFields -Shape 'ResultRow').Count | Should -Be 19
            Get-PPSafeText -Text ('I{0}i' -f [char]27) | Should -BeExactly 'I?i'
            ConvertTo-PPDuration -Seconds 3661 | Should -BeExactly '01:01:01'
        }
    }

    It 'restores the culture after each test' {
        [System.Threading.Thread]::CurrentThread.CurrentCulture.Name | Should -Not -BeIn @('tr-TR', 'az-Latn-AZ')
    }
}

Describe 'PortProof.psd1 (AC35 manifest side)' -Tag 'Portable' {
    BeforeAll {
        $script:ManifestPath = Join-Path $script:Root 'PortProof.psd1'
        $script:Manifest = Import-PowerShellDataFile -Path $script:ManifestPath
    }

    It 'ModuleVersion equals ToolVersion and PowerShellVersion is 5.1' {
        $script:Manifest.ModuleVersion | Should -BeExactly (Get-PPContract).ToolVersion
        $script:Manifest.PowerShellVersion | Should -BeExactly '5.1'
    }

    It 'has no RequiredModules and no RootModule key' {
        [System.IO.File]::ReadAllText($script:ManifestPath) | Should -Not -Match 'RequiredModules'
        $script:Manifest.ContainsKey('RootModule') | Should -BeFalse
    }

    It 'declares Apache-2.0, the project URI and a fixed GUID' {
        $script:Manifest.Copyright | Should -BeLike '(c) 2026 * Licensed under Apache-2.0.'
        $script:Manifest.PrivateData.PSData.ProjectUri | Should -BeExactly 'https://github.com/hansstudy/portproof'
        [guid]::Parse($script:Manifest.GUID) | Should -Not -Be ([guid]::Empty)
        @($script:Manifest.FunctionsToExport).Count | Should -Be 0
    }
}
