# Resolver tests: Resolve-PPProbeList against the harness
# FixtureResolver only (never DNS), plus the shape of the live seam. Nothing here opens a socket or
# sends a query: the one Get-PPDnsResolver call that runs Resolve hands it a name the .NET resolver
# rejects before any lookup (too long), and an IP literal it returns without a lookup.

BeforeDiscovery {
    $script:ExpanderPresent = Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/20-Expander.ps1')
    $script:ParserPresent = Test-Path -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'src/10-Parser.ps1')
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:Root 'src/05-Contract.ps1')
    . (Join-Path $script:Root 'src/30-Resolver.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Harness.ps1')
    . (Join-Path $PSScriptRoot 'Harness/FixtureResolver.ps1')

    function Get-Probe {
        # A pre-resolution Probe, built the way the Expander builds one.
        param([string] $Target, [int] $Port = 443, [string] $Protocol = 'TCP', [int[]] $Rows = @(2))
        $kind = Get-PPTargetKind -Text $Target
        [pscustomobject][ordered]@{
            PSTypeName = 'PortProof.Probe'
            ProbeKey   = '{0}|{1}|{2}' -f $kind.Text, $Port, $Protocol
            Target     = $kind.Text
            TargetKind = $kind.Kind
            Address    = $kind.Address
            Port       = $Port
            Protocol   = $Protocol
            Rows       = $Rows
        }
    }

    function Get-CountingResolver {
        # A FixtureResolver whose Resolve also appends every name it is really called with, so the
        # test counts calls independently of the Invocations counter under test.
        param([hashtable] $Table, [System.Collections.Generic.List[string]] $Calls)
        $inner = Get-PPFixtureResolver -Table $Table
        $innerResolve = $inner.Resolve
        $callLog = $Calls
        $inner.Resolve = {
            param([string] $Name)
            $callLog.Add($Name)
            & $innerResolve $Name
        }.GetNewClosure()
        $inner
    }

    function Get-CaughtError {
        param([scriptblock] $Action)
        try { & $Action; return $null } catch { return $_ }
    }

    $script:Table = Get-PPResolverTableFixture
}

Describe 'PortProof.Resolver.Literals' -Tag 'Portable' {

    It 'canonicalises literals without calling Resolve (Invocations stays 0)' {
        $calls = [System.Collections.Generic.List[string]]::new()
        $resolver = Get-CountingResolver -Table $script:Table -Calls $calls
        $probes = @(
            (Get-Probe -Target '127.0.0.5' -Port 80),
            (Get-Probe -Target '::ffff:127.0.0.6' -Port 81),
            (Get-Probe -Target '::1' -Port 82 -Protocol 'UDP')
        )
        $res = Resolve-PPProbeList -Probes $probes -Resolver $resolver
        $resolver.Invocations | Should -Be 0
        $calls.Count | Should -Be 0
        $res.CountBefore | Should -Be 3
        $res.CountAfter | Should -Be 3
        @($res.ExecProbes.ExecKey) | Should -Be @('127.0.0.5|80|TCP', '127.0.0.6|81|TCP', '::1|82|UDP')
        $mapped = $res.Entries[$probes[1].ProbeKey]
        $mapped.TargetIp.ToString() | Should -Be '127.0.0.6'
        @($mapped.ResolvedAddresses) | Should -Be @('127.0.0.6')
        $mapped.Failed | Should -BeFalse
        $res.ExecProbes[0].JitterMs | Should -Be 0
    }

    It 'returns an empty Resolution for an empty probe list' {
        $res = Resolve-PPProbeList -Probes @() -Resolver (Get-PPFixtureResolver -Table @{})
        $res.CountBefore | Should -Be 0
        $res.CountAfter | Should -Be 0
        @($res.ExecProbes).Count | Should -Be 0
    }
}

Describe 'PortProof.Resolver.Names' -Tag 'Portable' {

    It 'calls Resolve once per distinct lowercase name and counts every call (AC11-3)' {
        $calls = [System.Collections.Generic.List[string]]::new()
        $resolver = Get-CountingResolver -Table $script:Table -Calls $calls
        $probes = @(
            (Get-Probe -Target 'dc01.corp.example' -Port 88),
            (Get-Probe -Target 'DC01.corp.example' -Port 389),
            (Get-Probe -Target 'dc01.corp.example' -Port 53 -Protocol 'UDP'),
            (Get-Probe -Target 'alias-one.test' -Port 88)
        )
        $res = Resolve-PPProbeList -Probes $probes -Resolver $resolver
        $calls.Count | Should -Be 2
        @($calls | Sort-Object) | Should -Be @('alias-one.test', 'dc01.corp.example')
        $resolver.Invocations | Should -Be 2
        $res.CountAfter | Should -Be 4
    }

    It 'probes only the first of four addresses and records all four (AC30 multi-address)' {
        $resolver = Get-PPFixtureResolver -Table $script:Table
        $probe = Get-Probe -Target 'multi-address.test' -Port 443
        $res = Resolve-PPProbeList -Probes @($probe) -Resolver $resolver
        $entry = $res.Entries[$probe.ProbeKey]
        $entry.TargetIp.ToString() | Should -Be '127.1.2.1'
        @($entry.ResolvedAddresses) | Should -Be @('127.1.2.1', '127.1.2.2', '127.1.2.3', '127.1.2.4')
        $entry.TargetName | Should -Be 'multi-address.test'
        @($entry.Rows) | Should -Be @(2)
        @($res.ExecProbes).Count | Should -Be 1
        $res.ExecProbes[0].ExecKey | Should -Be '127.1.2.1|443|TCP'
        $res.ExecProbes[0].TargetIp.ToString() | Should -Be '127.1.2.1'
    }

    It 'coalesces two names that resolve to one address into one ExecProbe (AC30 coalescing)' {
        $resolver = Get-PPFixtureResolver -Table $script:Table
        $a = Get-Probe -Target 'alias-one.test' -Port 443 -Rows @(4)
        $b = Get-Probe -Target 'alias-two.test' -Port 443 -Rows @(5)
        $res = Resolve-PPProbeList -Probes @($a, $b) -Resolver $resolver
        $res.CountBefore | Should -Be 2
        $res.CountAfter | Should -Be 1
        $res.CountAfter | Should -BeLessOrEqual $res.CountBefore
        $res.ExecProbes[0].ExecKey | Should -Be '127.1.3.1|443|TCP'
        $res.Entries[$a.ProbeKey].TargetIp.ToString() | Should -Be '127.1.3.1'
        $res.Entries[$b.ProbeKey].TargetIp.ToString() | Should -Be '127.1.3.1'
    }

    It 'coalesces a name with a literal of the same address' {
        $resolver = Get-PPFixtureResolver -Table $script:Table
        $res = Resolve-PPProbeList -Probes @((Get-Probe -Target 'alias-one.test' -Port 22), (Get-Probe -Target '127.1.3.1' -Port 22)) -Resolver $resolver
        $res.CountAfter | Should -Be 1
    }

    It 'keeps CountAfter <= CountBefore over every committed fixture name' {
        $resolver = Get-PPFixtureResolver -Table $script:Table
        $probes = foreach ($name in @($script:Table.Keys | Sort-Object)) {
            Get-Probe -Target $name -Port 443
            Get-Probe -Target $name -Port 53 -Protocol 'UDP'
        }
        $res = Resolve-PPProbeList -Probes @($probes) -Resolver $resolver
        $res.CountBefore | Should -Be (@($probes).Count)
        $res.CountAfter | Should -BeLessOrEqual $res.CountBefore
        $res.CountAfter | Should -Be (@($res.ExecProbes).Count)
        $res.Entries.Count | Should -Be (@($probes).Count)
    }
}

Describe 'PortProof.Resolver.Failures' -Tag 'Portable' {

    It 'turns PortProof.DnsFailure into a Failed entry with no ExecProbe and carries on' {
        $resolver = Get-PPFixtureResolver -Table $script:Table
        $missing = Get-Probe -Target 'no-such-name.test' -Port 443 -Rows @(3)
        $good = Get-Probe -Target 'alias-one.test' -Port 443
        $res = Resolve-PPProbeList -Probes @($missing, $good) -Resolver $resolver
        $entry = $res.Entries[$missing.ProbeKey]
        $entry.Failed | Should -BeTrue
        $entry.TargetIp | Should -BeNullOrEmpty
        @($entry.ResolvedAddresses).Count | Should -Be 0
        @($entry.Rows) | Should -Be @(3)
        $res.CountBefore | Should -Be 2
        $res.CountAfter | Should -Be 1
        $resolver.Invocations | Should -Be 2
    }

    It 'resolves a failed name once, not once per probe' {
        $calls = [System.Collections.Generic.List[string]]::new()
        $resolver = Get-CountingResolver -Table $script:Table -Calls $calls
        $null = Resolve-PPProbeList -Probes @((Get-Probe -Target 'no-such-name.test' -Port 1), (Get-Probe -Target 'no-such-name.test' -Port 2)) -Resolver $resolver
        $calls.Count | Should -Be 1
    }

    It 'lets the Refusing resolver''s DryRunResolutionAttempted propagate (never swallowed as DnsFailure)' {
        $resolver = Get-PPRefusingResolver
        $err = Get-CaughtError { Resolve-PPProbeList -Probes @(Get-Probe -Target 'dc01.corp.example') -Resolver $resolver }
        $err | Should -Not -BeNullOrEmpty
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.DryRunResolutionAttempted*'
        $resolver.Invocations | Should -Be 1
    }

    It 'lets any other resolver exception propagate (harness non-loopback guard)' {
        $resolver = Get-PPFixtureResolver -Table @{ 'offhost.test' = '192.0.2.10' }
        $err = Get-CaughtError { Resolve-PPProbeList -Probes @(Get-Probe -Target 'offhost.test') -Resolver $resolver }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProofTest.NonLoopbackAddress*'
    }

    It 'refuses a resolver that returns something other than an address (InternalInvariant)' {
        $resolver = [pscustomobject]@{ PSTypeName = 'PortProof.Resolver'; Kind = 'Fixture'; Invocations = 0; Resolve = { '127.0.0.1' } }
        $err = Get-CaughtError { Resolve-PPProbeList -Probes @(Get-Probe -Target 'x.test') -Resolver $resolver }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.InternalInvariant*'
    }

    It 'treats an empty answer as DnsFailure' {
        $resolver = [pscustomobject]@{ PSTypeName = 'PortProof.Resolver'; Kind = 'Fixture'; Invocations = 0; Resolve = { } }
        $probe = Get-Probe -Target 'empty.test'
        $res = Resolve-PPProbeList -Probes @($probe) -Resolver $resolver
        $res.Entries[$probe.ProbeKey].Failed | Should -BeTrue
        $res.CountAfter | Should -Be 0
    }

    It 'refuses a probe whose TargetKind is not IPv4, IPv6 or Hostname' {
        $probe = Get-Probe -Target '127.0.0.1'
        $probe.TargetKind = 'Group'
        $err = Get-CaughtError { Resolve-PPProbeList -Probes @($probe) -Resolver (Get-PPFixtureResolver -Table @{}) }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.InternalInvariant*'
    }
}

Describe 'PortProof.Resolver.DnsSeam' -Tag 'Portable' {

    It 'has the seam shape (Kind Dns, Invocations 0, a Resolve scriptblock)' {
        $dns = Get-PPDnsResolver -TimeoutMs 1000
        $dns.PSObject.TypeNames[0] | Should -Be 'PortProof.Resolver'
        $dns.Kind | Should -Be 'Dns'
        $dns.Invocations | Should -Be 0
        $dns.Resolve | Should -BeOfType ([scriptblock])
    }

    It 'maps a name the OS resolver rejects before any lookup to PortProof.DnsFailure' {
        $dns = Get-PPDnsResolver -TimeoutMs 1000
        $err = Get-CaughtError { & $dns.Resolve ('a' * 300) }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.DnsFailure*'
    }

    It 'returns an address for an IP literal (no lookup is made for a literal)' {
        $dns = Get-PPDnsResolver -TimeoutMs 1000
        $answer = @(& $dns.Resolve '127.0.0.1')
        $answer.Count | Should -Be 1
        $answer[0].ToString() | Should -Be '127.0.0.1'
    }

    It 'a DnsFailure from the live seam becomes a Failed entry in Resolve-PPProbeList' {
        $dns = Get-PPDnsResolver -TimeoutMs 1000
        $probe = [pscustomobject]@{ ProbeKey = 'k'; Target = ('a' * 300); TargetKind = 'Hostname'; Address = $null; Port = 1; Protocol = 'TCP'; Rows = @(2) }
        $res = Resolve-PPProbeList -Probes @($probe) -Resolver $dns
        $res.Entries['k'].Failed | Should -BeTrue
        $dns.Invocations | Should -Be 1
    }
}

Describe 'PortProof.Resolver.EarlyExit (AC30: early exit with zero resolutions)' -Tag 'Portable' {

    BeforeAll {
        if (Test-Path -LiteralPath (Join-Path $script:Root 'src/20-Expander.ps1')) {
            . (Join-Path $script:Root 'src/20-Expander.ps1')
        }
        . (Join-Path $script:Root 'src/90-Main.ps1')
    }

    It 'refuses 1030 pre-resolution probes with the Resolver counter at zero' -Skip:(-not $script:ExpanderPresent) {
        $profilePath = Join-Path $TestDrive 'early.csv'
        [System.IO.File]::WriteAllText($profilePath, "Source,Target,Port,Protocol,Required`r`n")
        $probes = foreach ($i in 1..1030) { Get-Probe -Target ('h{0}.test' -f $i) -Port 443 -Rows @($i + 1) }
        $expansion = [pscustomobject]@{ Rows = @(); Probes = @($probes); GroupOverrides = @(); UnusedGroups = @(); DistinctTargets = 1030 }
        # The parser and expander's own work is covered elsewhere; here they only hand Main a
        # 1030-probe list, so the real Assert-PPPreResolutionCount and Main's ordering are what is
        # exercised.
        function Import-PPProfile {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Contract',
                Justification = 'Test stub with the real Import-PPProfile signature so Main binds it; it only returns a fixed document.')]
            param($Path, $Contract)
            [pscustomobject]@{ Path = $Path; FileName = 'early.csv'; Format = 'Csv'; Sha256 = ''; Name = 'early'; Version = ''; Groups = [ordered]@{}; IgnoredColumns = @(); Rows = @(); Warnings = @() }
        }
        function Expand-PPProfile {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
                Justification = 'Test stub with the real Expand-PPProfile signature so Main binds it; it only returns the fixed 1030-probe expansion.')]
            param($ProfileDocument, $Bindings, [switch] $AllowCidr, $Contract)
            $expansion
        }

        $calls = [System.Collections.Generic.List[string]]::new()
        $resolver = Get-CountingResolver -Table @{} -Calls $calls
        $raw = @{
            ProfilePath = $profilePath; Set = $null; Out = ''; Format = $null; Timeout = 2000; Concurrency = 16
            MaxProbesPerSecond = 50; Jitter = 0; MaxProbes = 0; MaxProbesGiven = $false; AllowLarge = $false
            AllowCidr = $false; Icmp = $false; DryRun = $false; NoOperator = $true; Force = $false; Quiet = $true; Version = $false
        }
        $exit = [ref]99
        $all = @(Invoke-PortProof -Raw $raw -ExitCode $exit -LiveResolver $resolver *>&1)
        $exit.Value | Should -Be 2
        $errors = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
        ($errors | ForEach-Object { $_.FullyQualifiedErrorId }) -join ' ' | Should -Match 'CapExceeded\.PreResolution'
        $resolver.Invocations | Should -Be 0
        $calls.Count | Should -Be 0
    }
}
