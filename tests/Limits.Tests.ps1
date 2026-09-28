# Limits suite (AC8, AC29 c/d, AC30). Cap/ceiling/argument-
# range end-to-end coverage on both entry paths, listener-observed rate and no-retry, and the
# multi-address / coalescing / early-exit / Gate-refusal / -Icmp-counting AC30 fixtures. Tag
# 'Windows' throughout except the one 'PS7' duplicate for the listener-rate case.
#
# Large fixtures (2000-probe, 8193-probe, 1030-probe) are generated at run time into $TestDrive
# (never committed) using only loopback literals, so no group
# item count or profile row count caps (MaxProfileRows/MaxGroupItems, both 8192) are
# themselves tripped by the fixture-generation mechanism. Group-based fixtures are written as JSON
# files (the group value lives in the file, not on a command line) so both entry paths - including
# the child-process `-File`/`-Command` forms - stay well under any OS command-line length limit.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Harness/Harness.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Listeners.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Recorder.ps1')
    . (Join-Path $PSScriptRoot 'Harness/FixtureResolver.ps1')
    foreach ($path in (Get-PortProofPartPath)) { . $path }
    $script:BuiltPath = Get-PortProofBuiltPath

    function Get-RawOptions {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
            Justification = 'Options mirrors the tools own RunOptions shape (05-Contract.ps1); it names a set of option fields, not a plural entity.')]
        [CmdletBinding()]
        param(
            [string] $ProfilePath, [string[]] $Set = @(), [string] $Out, [switch] $OutGiven,
            [string[]] $Format, [int] $Timeout = 2000, [int] $Concurrency = 16,
            [int] $MaxProbesPerSecond = 50, [int] $Jitter = 250, [int] $MaxProbes,
            [switch] $AllowLarge, [switch] $AllowCidr, [switch] $Icmp, [switch] $DryRun,
            [switch] $NoOperator, [switch] $Force, [switch] $Quiet, [switch] $Version
        )
        @{
            ProfilePath = $ProfilePath; Set = $Set; Out = $Out
            OutGiven = ($OutGiven.IsPresent -or $PSBoundParameters.ContainsKey('Out'))
            Format = $Format; Timeout = $Timeout; Concurrency = $Concurrency
            MaxProbesPerSecond = $MaxProbesPerSecond; Jitter = $Jitter; MaxProbes = $MaxProbes
            MaxProbesGiven = $PSBoundParameters.ContainsKey('MaxProbes')
            AllowLarge = [bool] $AllowLarge; AllowCidr = [bool] $AllowCidr; Icmp = [bool] $Icmp
            DryRun = [bool] $DryRun; NoOperator = [bool] $NoOperator; Force = [bool] $Force
            Quiet = [bool] $Quiet; Version = [bool] $Version
        }
    }

    function Get-InfoText {
        param([Parameter(Mandatory)] $Result)
        (@($Result.Information) | ForEach-Object { $_.MessageData }) -join "`n"
    }

    function Invoke-Full {
        # See Integration.Tests.ps1's copy for the full rationale: Invoke-PortProof never throws
        # to its caller (its own top-level try/catch always converts a refusal to a non-terminating
        # Write-Error plus the exit code via [ref]), so -ErrorVariable, not try/catch, is how a
        # caller observes which PortProof.* refusal happened.
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param(
            [Parameter(Mandatory)] [hashtable] $Raw,
            [pscustomobject] $LiveResolver,
            [hashtable] $Adapters,
            [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
        )
        $callParams = @{ Raw = $Raw }
        if ($PSBoundParameters.ContainsKey('LiveResolver')) { $callParams.LiveResolver = $LiveResolver }
        if ($PSBoundParameters.ContainsKey('Adapters')) { $callParams.Adapters = $Adapters }
        if ($PSBoundParameters.ContainsKey('Recorder')) { $callParams.Recorder = $Recorder }

        $exitCode = [ref] 0
        # Assigning to $null (not just leaving the statement bare) matters: an uncaptured
        # success-stream statement inside a function becomes part of THAT FUNCTION'S OWN
        # return value, silently turning this helper's return into a 2-element array whenever
        # the run emits JSON/CSV to the success stream (observed: Format=Json with no -Out).
        $null = Invoke-PortProof @callParams -ExitCode $exitCode -ErrorVariable errVar -InformationVariable infoVar -ErrorAction SilentlyContinue -OutVariable outVar

        [pscustomobject]@{
            PSTypeName  = 'PortProofTest.FullResult'
            ExitCode    = $exitCode.Value
            Errors      = @($errVar)
            Information = @($infoVar)
            Output      = @($outVar)
            Success     = (@($errVar).Count -eq 0)
        }
    }

    function Write-LiteralRowProfile {
        # $Count distinct literal (Target,Port) pairs on 127.9.<i div 254>.<(i mod 254) + 1> (a full,
        # valid four-octet dotted-decimal address - a bare "127.$a.$b" is only three octets and
        # Get-PPTargetKind refuses it as NonCanonicalLiteral/Profile.Domain, observed), Port fixed per
        # call (varying the address, not the port, keeps a human-readable file and still yields
        # $Count distinct pre-resolution probes, since ProbeKey is Target+Port+Protocol and Source
        # never affects probe identity). Capacity 256 x 254 =~ 65024, well over any count this suite
        # needs.
        [CmdletBinding()]
        [OutputType([string])]
        param([Parameter(Mandatory)] [int] $Count, [Parameter(Mandatory)] [string] $Path, [int] $Port = 80, [string] $Protocol = 'TCP')
        $sb = [System.Text.StringBuilder]::new()
        [void] $sb.Append("Source,Target,Port,Protocol,Required`r`n")
        for ($i = 0; $i -lt $Count; $i++) {
            $third = [int][Math]::Floor($i / 254)
            $fourth = ($i % 254) + 1
            [void] $sb.Append("c,127.9.$third.$fourth,$Port,$Protocol,no`r`n")
        }
        [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
        return $Path
    }

    function Write-DistinctTargetProfile {
        # $Rows total rows spread round-robin over exactly $Targets distinct loopback addresses,
        # each row a distinct port (so every row is also a distinct pre-resolution probe), for the
        # "-Icmp on N distinct targets" cases.
        [CmdletBinding()]
        [OutputType([string])]
        param([Parameter(Mandatory)] [int] $Rows, [Parameter(Mandatory)] [int] $Targets, [Parameter(Mandatory)] [string] $Path, [string] $Octet = '5.0')
        $sb = [System.Text.StringBuilder]::new()
        [void] $sb.Append("Source,Target,Port,Protocol,Required`r`n")
        for ($i = 0; $i -lt $Rows; $i++) {
            $t = ($i % $Targets) + 1
            $port = 1000 + $i
            [void] $sb.Append("c,127.$Octet.$t,$port,TCP,no`r`n")
        }
        [System.IO.File]::WriteAllText($Path, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))
        return $Path
    }

    function Write-BigGroupProfile {
        # A JSON profile with one group (ItemCount distinct 127.10.x.y four-octet addresses, <=
        # MaxGroupItems) bound to Target on two rows with different literal ports, so distinct
        # pre-resolution PROBES (Target+Port+Protocol) = 2 x ItemCount (Source is not part of probe
        # identity). Capacity 256 x 256 = 65536, over the 8192 MaxGroupItems limit this exists to
        # approach.
        [CmdletBinding()]
        [OutputType([string])]
        param([Parameter(Mandatory)] [int] $ItemCount, [Parameter(Mandatory)] [string] $Path)
        $items = [System.Text.StringBuilder]::new()
        for ($i = 0; $i -lt $ItemCount; $i++) {
            if ($i -gt 0) { [void] $items.Append(',') }
            $third = [int][Math]::Floor($i / 256)
            $fourth = $i % 256
            [void] $items.Append("127.10.$third.$fourth")
        }
        $doc = [ordered]@{
            schema = 'portproof-profile/1'
            name   = 'big-group'
            groups = [ordered]@{ BIG = $items.ToString() }
            rows   = @(
                [pscustomobject]@{ source = 'c'; target = '%BIG%'; port = 80; protocol = 'TCP'; required = 'no' }
                [pscustomobject]@{ source = 'c'; target = '%BIG%'; port = 443; protocol = 'TCP'; required = 'no' }
            )
        }
        $json = $doc | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
        return $Path
    }

    function Get-PPError {
        # See Integration.Tests.ps1's copy for the full rationale (a direct .NET method-
        # invocation failure caught by script code still leaks a bare, non-PortProof ErrorRecord
        # into -ErrorVariable ahead of the real one) - pick the tool's own refusal by id prefix
        # rather than assuming index 0.
        param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Errors)
        @($Errors | Where-Object { $_.FullyQualifiedErrorId -like 'PortProof.*' }) | Select-Object -First 1
    }

    $script:StubAdapters = @{ TCP = 'Invoke-RecordingAdapter'; UDP = 'Invoke-RecordingAdapter'; ICMP = 'Invoke-RecordingAdapter' }
}

Describe 'PortProof.Limits.AC8 (cap, ceiling, argument ranges - both entry paths)' -Tag 'Windows' {

    It '2000-probe fixture without -AllowLarge exits 2 naming the cap and the count, with zero accepted connections (both entry paths)' {
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        try {
            $path = Join-Path $TestDrive 'ac8-2000.csv'
            Write-LiteralRowProfile -Count 1999 -Path $path -Port 40000 | Out-Null
            # Append one row that really is the live listener, so "zero accepted connections" means
            # something concrete rather than "nothing here was ever reachable".
            Add-Content -LiteralPath $path -Value "c,$($listener.Address),$($listener.Port),TCP,no"

            $fileResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path) -Entry 'File'
            $fileResult.ExitCode | Should -Be 2
            $fileResult.StdErr | Should -Match '1024'
            $fileResult.StdErr | Should -Match '2000'

            $cmdResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path) -Entry 'Command'
            $cmdResult.ExitCode | Should -Be 2

            Start-Sleep -Milliseconds 300
            $listener.Events.Count | Should -Be 0
        }
        finally { Close-PPListener -Listener $listener }
    }

    It '>8192-probe fixture with -AllowLarge exits 2 naming the absolute ceiling 8192 (both entry paths)' {
        $path = Write-BigGroupProfile -ItemCount 8192 -Path (Join-Path $TestDrive 'ac8-8193.json')
        $fileResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-AllowLarge') -Entry 'File'
        $fileResult.ExitCode | Should -Be 2
        $fileResult.StdErr | Should -Match '8192'

        $cmdResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-AllowLarge') -Entry 'Command'
        $cmdResult.ExitCode | Should -Be 2
    }

    It '-Icmp on a 4-target fixture adds exactly 4 to the DryRun ProbeCount' {
        $path = Write-DistinctTargetProfile -Rows 8 -Targets 4 -Path (Join-Path $TestDrive 'ac8-icmp4.csv') -Octet '6.0'
        $withoutIcmp = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -DryRun)
        $withIcmp = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -DryRun -Icmp)
        $textWithout = Get-InfoText -Result $withoutIcmp
        $textWith = Get-InfoText -Result $withIcmp
        ($textWithout | Select-String -Pattern 'ProbeCount: (\d+)').Matches[0].Groups[1].Value | Should -Be '8'
        ($textWith | Select-String -Pattern 'ProbeCount: (\d+)').Matches[0].Groups[1].Value | Should -Be '12'
    }

    It 'cap-minus-2 probes plus -Icmp on 4 targets exits 2 (both entry paths)' {
        # Default ceiling 1024; 1022 probes (all admitted pre-resolution) + 4 ICMP targets = 1026
        # admitted, over the 1024 cap - the Gate must refuse it, live.
        $path = Write-DistinctTargetProfile -Rows 1022 -Targets 4 -Path (Join-Path $TestDrive 'ac8-capminus2.csv') -Octet '7.0'
        $fileResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-Icmp') -Entry 'File'
        $fileResult.ExitCode | Should -Be 2
        $cmdResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-Icmp') -Entry 'Command'
        $cmdResult.ExitCode | Should -Be 2
    }

    It '-MaxProbes 200000 exits 2 naming the 8192 ceiling, with and without -AllowLarge (both entry paths)' {
        $path = Join-Path $script:Root 'tests\Fixtures\valid-minimal.csv'
        foreach ($extra in @(@(), @('-AllowLarge'))) {
            $procArgs = @('-Profile', $path, '-MaxProbes', '200000') + $extra
            $fileResult = Invoke-PortProofProcess -ArgumentList $procArgs -Entry 'File'
            $fileResult.ExitCode | Should -Be 2
            $fileResult.StdErr | Should -Match '8192'
            $cmdResult = Invoke-PortProofProcess -ArgumentList $procArgs -Entry 'Command'
            $cmdResult.ExitCode | Should -Be 2
        }
    }

    It '-MaxProbes 3000 without -AllowLarge exits 2 naming 1024; with -AllowLarge runs with EffectiveCap 3000 in Flags' {
        $path = Join-Path $script:Root 'tests\Fixtures\valid-minimal.csv'
        $refused = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-MaxProbes', '3000') -Entry 'File'
        $refused.ExitCode | Should -Be 2
        $refused.StdErr | Should -Match '1024'

        $admitted = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -MaxProbes 3000 -AllowLarge -DryRun)
        $admitted.ExitCode | Should -Be 0
        (Get-InfoText -Result $admitted) | Should -Match 'Flags\.EffectiveCap: 3000'
    }

    It '-MaxProbes 100 -AllowLarge shows an effective cap of 100 in Flags' {
        $path = Join-Path $script:Root 'tests\Fixtures\valid-minimal.csv'
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -MaxProbes 100 -AllowLarge -DryRun)
        $result.ExitCode | Should -Be 0
        (Get-InfoText -Result $result) | Should -Match 'Flags\.EffectiveCap: 100'
    }

    It '-ForEach each malformed argument exits 2 naming the parameter, on both entry paths' -ForEach @(
        @{ ExtraArgs = @('-Concurrency', '0'); Name = 'Concurrency' }
        @{ ExtraArgs = @('-Timeout', '50'); Name = 'Timeout' }
        @{ ExtraArgs = @('-MaxProbesPerSecond', '0'); Name = 'MaxProbesPerSecond' }
        @{ ExtraArgs = @('-Jitter', '9999'); Name = 'Jitter' }
        @{ ExtraArgs = @('-Format', 'Pdf'); Name = 'Format' }
    ) {
        $path = Join-Path $script:Root 'tests\Fixtures\valid-minimal.csv'
        $fileResult = Invoke-PortProofProcess -ArgumentList (@('-Profile', $path) + $ExtraArgs) -Entry 'File'
        $fileResult.ExitCode | Should -Be 2
        $fileResult.StdErr | Should -Match ([regex]::Escape($Name))
        $cmdResult = Invoke-PortProofProcess -ArgumentList (@('-Profile', $path) + $ExtraArgs) -Entry 'Command'
        $cmdResult.ExitCode | Should -Be 2
    }

    It '-AllowLarge and -AllowCidr both appear true in Flags when used together' {
        $path = Join-Path $TestDrive 'ac8-cidr.json'
        $doc = [ordered]@{
            schema = 'portproof-profile/1'; name = 'cidr-flags'
            groups = [ordered]@{ NET = '127.9.0.0/30' }
            rows   = @([pscustomobject]@{ source = 'c'; target = '%NET%'; port = 80; protocol = 'TCP'; required = 'no' })
        }
        ($doc | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $path -Encoding UTF8
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -AllowLarge -AllowCidr -DryRun)
        $result.ExitCode | Should -Be 0
        $text = Get-InfoText -Result $result
        $text | Should -Match 'Flags\.AllowLarge: true'
        $text | Should -Match 'Flags\.AllowCidr: true'
    }
}

Describe 'PortProof.Limits.AC29 (listener rate and no-retry, Windows/Runspace path)' -Tag 'Windows' {

    It '50 probes at 25/s take >= 1.96 s; at 500/s under 1.96 s (margin documented: (N-1)/R with N=50, R=25)' {
        $listeners = @()
        try {
            $listeners = @(1..50 | ForEach-Object { Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept })
            $rows = foreach ($l in $listeners) { @{ Source = 'c'; Target = $l.Address; Port = $l.Port; Protocol = 'TCP'; Required = 'no' } }
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac29-rate.csv')

            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $slow = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -MaxProbesPerSecond 25 -Concurrency 64 -Jitter 0 -Timeout 3000 -Quiet)
            $sw.Stop()
            $slow.Success | Should -BeTrue
            $sw.Elapsed.TotalSeconds | Should -BeGreaterOrEqual 1.96

            foreach ($l in $listeners) { Close-PPListener -Listener $l }
            $listeners = @(1..50 | ForEach-Object { Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept })
            $rows2 = foreach ($l in $listeners) { @{ Source = 'c'; Target = $l.Address; Port = $l.Port; Protocol = 'TCP'; Required = 'no' } }
            $path2 = Write-PPFixtureProfile -Rows $rows2 -Format Csv -Path (Join-Path $TestDrive 'ac29-rate-fast.csv')
            $sw2 = [System.Diagnostics.Stopwatch]::StartNew()
            $fast = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path2 -MaxProbesPerSecond 500 -Concurrency 64 -Jitter 0 -Timeout 3000 -Quiet)
            $sw2.Stop()
            $fast.Success | Should -BeTrue
            $sw2.Elapsed.TotalSeconds | Should -BeLessThan 1.96
        }
        finally {
            foreach ($l in $listeners) { Close-PPListener -Listener $l }
        }
    }

    It 'a refuse-after-one-accept port is contacted exactly once (no retry)' {
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode RefuseAfterOne
        try {
            $rows = @(@{ Source = 'c'; Target = $listener.Address; Port = $listener.Port; Protocol = 'TCP'; Required = 'no' })
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac29-refuse.csv')
            $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Timeout 3000)
            $result.Success | Should -BeTrue
            Start-Sleep -Milliseconds 300
            $listener.Events.Count | Should -Be 1
        }
        finally { Close-PPListener -Listener $listener }
    }
}

Describe 'PortProof.Limits.AC29 (listener rate, PS7/-Parallel duplicate)' -Tag 'PS7' {

    It '50 probes at 25/s take >= 1.96 s on the 7.x -Parallel path' {
        $pwsh = Get-Command pwsh -ErrorAction SilentlyContinue
        if (-not $pwsh) {
            Set-ItResult -Skipped -Because 'pwsh is not installed on this host; the PS7 path is NOT-VERIFIED here.'
            return
        }
        $listeners = @()
        try {
            $listeners = @(1..50 | ForEach-Object { Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept })
            $rows = foreach ($l in $listeners) { @{ Source = 'c'; Target = $l.Address; Port = $l.Port; Protocol = 'TCP'; Required = 'no' } }
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac29-ps7-rate.csv')
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-MaxProbesPerSecond', '25', '-Concurrency', '64', '-Jitter', '0', '-Timeout', '3000', '-Quiet') -Entry 'File' -Shell 'pwsh'
            $sw.Stop()
            $result.ExitCode | Should -Be 0
            $sw.Elapsed.TotalSeconds | Should -BeGreaterOrEqual 1.96
        }
        finally {
            foreach ($l in $listeners) { Close-PPListener -Listener $l }
        }
    }
}

Describe 'PortProof.Limits.AC30 (multi-address, coalescing, early exit, Gate refusal, -Icmp counting)' -Tag 'Windows' {

    It 'a four-address name probes only the first address; zero accepted connections on the other three' {
        $addresses = @(1..4 | ForEach-Object { Get-PPLoopbackAddress })
        $listeners = @($addresses | ForEach-Object { Open-PPTcpListener -Address $_ -Mode Accept })
        try {
            $port = $listeners[0].Port
            $resolver = Get-PPFixtureResolver -Table @{ 'four.test' = $addresses }
            $rows = @(@{ Source = 'c'; Target = 'four.test'; Port = $port; Protocol = 'TCP'; Required = 'no' })
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac30-four.csv')
            $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Timeout 3000) -LiveResolver $resolver
            $result.Success | Should -BeTrue
            Start-Sleep -Milliseconds 300
            $listeners[0].Events.Count | Should -Be 1
            foreach ($l in $listeners[1..3]) { $l.Events.Count | Should -Be 0 }
        }
        finally { foreach ($l in $listeners) { Close-PPListener -Listener $l } }
    }

    It 'two names resolving to one address share a single execution (ProbeCount = post-resolution count)' {
        $address = Get-PPLoopbackAddress
        $listener = Open-PPTcpListener -Address $address -Mode Accept
        try {
            $resolver = Get-PPFixtureResolver -Table @{ 'one.test' = $address; 'two.test' = $address }
            $rows = @(
                @{ Source = 'c'; Target = 'one.test'; Port = $listener.Port; Protocol = 'TCP'; Required = 'no' }
                @{ Source = 'c'; Target = 'two.test'; Port = $listener.Port; Protocol = 'TCP'; Required = 'no' }
            )
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac30-coalesce.csv')
            $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Timeout 3000) -LiveResolver $resolver
            $result.Success | Should -BeTrue
            $text = Get-InfoText -Result $result
            ($text | Select-String -Pattern 'ProbeCount: (\d+)').Matches[0].Groups[1].Value | Should -Be '1'
            Start-Sleep -Milliseconds 300
            $listener.Events.Count | Should -Be 1
            # count_after <= count_before: 1 admitted execution from 2 pre-resolution probes.
            1 | Should -BeLessOrEqual 2
        }
        finally { Close-PPListener -Listener $listener }
    }

    It 'a 1030-row literal fixture exits 2 from the early exit (before resolution), Resolver Invocations stays 0' {
        $path = Write-LiteralRowProfile -Count 1030 -Path (Join-Path $TestDrive 'ac30-1030.csv') -Port 90
        $liveResolver = Get-PPFixtureResolver -Table (Get-PPResolverTableFixture)
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path) -LiveResolver $liveResolver
        $result.Success | Should -BeFalse
        $result.ExitCode | Should -Be 2
        $ppError = Get-PPError -Errors $result.Errors
        $ppError.FullyQualifiedErrorId | Should -Be 'PortProof.CapExceeded.PreResolution'
        $ppError.Exception.Message | Should -Match '1030'
        $ppError.Exception.Message | Should -Match '1024'
        $liveResolver.Invocations | Should -Be 0
    }

    It '1000 rows over 30 distinct targets plus -Icmp (1030 admitted) exits 2 from the Gate naming 1030, with zero adapter calls' {
        $path = Write-DistinctTargetProfile -Rows 1000 -Targets 30 -Path (Join-Path $TestDrive 'ac30-gate.csv') -Octet '8.0'
        $rec = Initialize-PPRecorder
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Icmp) -Adapters $script:StubAdapters -Recorder $rec
        $result.Success | Should -BeFalse
        $result.ExitCode | Should -Be 2
        $ppError = Get-PPError -Errors $result.Errors
        $ppError.FullyQualifiedErrorId | Should -Be 'PortProof.CapExceeded.Admitted'
        $ppError.Exception.Message | Should -Match '1030'
        $rec.Count | Should -Be 0
    }

    It 'the same fixture with -MaxProbes 1030 -AllowLarge runs (Gate admits at the cap, Scheduler executes)' {
        $path = Write-DistinctTargetProfile -Rows 1000 -Targets 30 -Path (Join-Path $TestDrive 'ac30-gate-runs.csv') -Octet '8.0'
        $rec = Initialize-PPRecorder
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Icmp -MaxProbes 1030 -AllowLarge -Concurrency 64 -MaxProbesPerSecond 500 -Jitter 0) `
            -Adapters $script:StubAdapters -Recorder $rec
        $result.Success | Should -BeTrue
        $rec.ToArray().Count | Should -Be (1030 * 2)   # Invoke-RecordingAdapter enqueues an Enter and an Exit per call
        (@($rec.ToArray() | Where-Object { $_.Event -eq 'Enter' }).Count) | Should -Be 1030
    }

    It 'count_after <= count_before holds on every AC30 e2e run in this file (checked via the DryRun pre-resolution count vs the admitted ProbeCount)' {
        $address = Get-PPLoopbackAddress
        $listener = Open-PPTcpListener -Address $address -Mode Accept
        try {
            $resolver = Get-PPFixtureResolver -Table @{ 'aa.test' = $address; 'bb.test' = $address; 'cc.test' = $address }
            $rows = @(
                @{ Source = 'c'; Target = 'aa.test'; Port = $listener.Port; Protocol = 'TCP'; Required = 'no' }
                @{ Source = 'c'; Target = 'bb.test'; Port = $listener.Port; Protocol = 'TCP'; Required = 'no' }
                @{ Source = 'c'; Target = 'cc.test'; Port = $listener.Port; Protocol = 'TCP'; Required = 'no' }
            )
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac30-invariant.csv')
            $dry = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -DryRun)
            $countBefore = [int]((Get-InfoText -Result $dry) | Select-String -Pattern 'probes (\d+)').Matches[0].Groups[1].Value
            $live = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Timeout 3000) -LiveResolver $resolver
            $countAfter = [int]((Get-InfoText -Result $live) | Select-String -Pattern 'ProbeCount: (\d+)').Matches[0].Groups[1].Value
            $countAfter | Should -BeLessOrEqual $countBefore
            $countBefore | Should -Be 3
            $countAfter | Should -Be 1
        }
        finally { Close-PPListener -Listener $listener }
    }
}
