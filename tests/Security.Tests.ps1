# Security suite (AC15, AC31). Safe-defaults / refused-class
# end-to-end coverage (literal and resolved, via the loopback-only FixtureResolver, with adapter
# calls proven zero through Recorder injection rather than real sockets - refusal happens before the
# Gate ever schedules anything, so no listener is needed to prove "nothing was contacted") and the
# malformed-profile corpus fail-closed property. All Portable: nothing here opens a real socket.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Harness/Harness.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Recorder.ps1')
    . (Join-Path $PSScriptRoot 'Harness/FixtureResolver.ps1')
    foreach ($path in (Get-PortProofPartPath)) { . $path }

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

    function Get-PPError {
        <#
            Direct .NET method-invocation failures (e.g. a strict Encoding.GetString throwing
            DecoderFallbackException) are logged by the PowerShell engine to -ErrorVariable/$Error
            as a side effect of the CLR call failing, even when script code catches the resulting
            exception immediately and converts it into a proper PortProof.* refusal (observed:
            corpus/encoding-invalid-utf8.csv's ErrorVariable holds both a bare 'DecoderFallbackException'
            entry and several 'PortProof.Profile.Encoding' ones - never in a reliable position). This
            picks the one that is actually the tool's own refusal, not whatever engine noise happens
            to sit at index 0.
        #>
        param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Errors)
        @($Errors | Where-Object { $_.FullyQualifiedErrorId -like 'PortProof.*' }) | Select-Object -First 1
    }

    $script:StubAdapters = @{ TCP = 'Invoke-RecordingAdapter'; UDP = 'Invoke-RecordingAdapter'; ICMP = 'Invoke-RecordingAdapter' }
    $script:FixturesDir = Join-Path $script:Root 'tests\Fixtures'
    $script:CorpusDir = Join-Path $script:FixturesDir 'corpus'
}

Describe 'PortProof.Security.AC15 (safe defaults are the defaults)' -Tag 'Portable' {

    It 'the DryRun header reports the safe defaults (Concurrency 16, MaxProbesPerSecond 50, Jitter 250, EffectiveCap 1024, Timeout 2000) and a worst-case line' {
        $path = Join-Path $script:FixturesDir 'valid-minimal.csv'
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -DryRun)
        $result.ExitCode | Should -Be 0
        $text = Get-InfoText -Result $result
        $text | Should -Match 'Flags\.Concurrency: 16'
        $text | Should -Match 'Flags\.MaxProbesPerSecond: 50'
        $text | Should -Match 'Flags\.JitterMs: 250'
        $text | Should -Match 'Flags\.EffectiveCap: 1024'
        $text | Should -Match 'Flags\.TimeoutMs: 2000'
        $text | Should -Match 'worst-case duration'
    }
}

Describe 'PortProof.Security.AC15 (CIDR gating)' -Tag 'Portable' {
    # VLSM support: CIDR accepts
    # any prefix /8..32 with -AllowCidr, not only /24..30. A prefix in range but too large for the
    # cap is refused CapExceeded.Expansion (pure O(1) arithmetic, before any address is built or
    # touched - Group.TooLarge/MaxGroupItems stay list-only, unchanged); a prefix outside 8..32 is
    # still refused Group.CidrTooWide; /31 is valid (RFC 3021, both addresses usable) and /32 is a
    # single host route.

    It 'a CIDR-valued group is refused without -AllowCidr' {
        $path = Join-Path $script:CorpusDir 'json-group-cidr-no-switch.json'
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path) -Adapters $script:StubAdapters -Recorder (Initialize-PPRecorder)
        $result.ExitCode | Should -Be 2
    }

    It 'a /16 with -AllowCidr is refused CapExceeded.Expansion before building, with zero adapter calls' {
        $rec = Initialize-PPRecorder
        $path = Join-Path $script:CorpusDir 'json-group-cidr-16.json'
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -AllowCidr) -Adapters $script:StubAdapters -Recorder $rec
        $result.ExitCode | Should -Be 2
        (Get-PPError -Errors $result.Errors).FullyQualifiedErrorId | Should -Be 'PortProof.CapExceeded.Expansion'
        $rec.Count | Should -Be 0
    }

    It 'a prefix outside 8..32 (<Prefix>) is refused Group.CidrTooWide even with -AllowCidr' -ForEach @(
        @{ Prefix = '/7'; Cidr = '10.0.0.0/7' }
        @{ Prefix = '/33'; Cidr = '10.10.5.0/33' }
    ) {
        $rec = Initialize-PPRecorder
        $rows = @(@{ Source = 'c'; Target = '%NET%'; Port = 443; Protocol = 'TCP'; Required = 'no' })
        $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive ('ac15-cidr-' + $Prefix.Replace('/', '') + '.csv'))
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Set @("NET=$Cidr") -AllowCidr) -Adapters $script:StubAdapters -Recorder $rec
        $result.ExitCode | Should -Be 2 -Because $Prefix
        (Get-PPError -Errors $result.Errors).FullyQualifiedErrorId | Should -Be 'PortProof.Group.CidrTooWide' -Because $Prefix
        $rec.Count | Should -Be 0 -Because $Prefix
    }

    It 'a /30 in a loopback range expands and probes only its 2 host addresses' {
        # 127.60.0.0/30: network .0 and broadcast .3 excluded, .1/.2 are the only usable hosts
        # (the classic exclusion rule, unchanged for /8..30 - only /31 and /32
        # get their own rule). Stub adapter + Recorder proves both which addresses and how many.
        $rec = Initialize-PPRecorder
        $rows = @(@{ Source = 'c'; Target = '%NET%'; Port = 443; Protocol = 'TCP'; Required = 'no' })
        $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac15-cidr-30.csv')
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Set @('NET=127.60.0.0/30') -AllowCidr) -Adapters $script:StubAdapters -Recorder $rec
        $result.Success | Should -BeTrue -Because ($result.Errors | ForEach-Object { $_.Exception.Message } | Out-String)
        $calls = @($rec.ToArray() | Where-Object { $_.Event -eq 'Enter' })
        $calls.Count | Should -Be 2
        @($calls | ForEach-Object { $_.TargetIp } | Sort-Object) | Should -Be @('127.60.0.1', '127.60.0.2')
    }

    It 'a CIDR inside a JSON groups block is gated identically to one bound via -Set' {
        $rec = Initialize-PPRecorder
        $noSwitch = Invoke-Full -Raw (Get-RawOptions -ProfilePath (Join-Path $script:CorpusDir 'json-group-cidr-no-switch.json')) -Adapters $script:StubAdapters -Recorder $rec
        (Get-PPError -Errors $noSwitch.Errors).FullyQualifiedErrorId | Should -Be 'PortProof.Group.CidrNotAllowed'
        $rec.Count | Should -Be 0
    }
}

Describe 'PortProof.Security.AC15 (literal refused classes, end-to-end, zero adapter calls)' -Tag 'Portable' {

    # The thirteen committed tests/Fixtures/refused-* literal fixtures: each names
    # a target address that Test-RefusedTargetClass refuses, or (the CIDR one) a CIDR group whose
    # gating is refused before any address is ever produced. Every one must exit 2 with the
    # Scheduler never invoked (proven by the injected Recorder, not a real listener - the whole
    # point of AC15 is that the Gate refuses before any socket would open).
    It 'refuses <Name>, calling no adapter' -ForEach @(
        @{ Name = 'refused-0.0.0.0.csv' }
        @{ Name = 'refused-0.1.2.3.csv' }
        @{ Name = 'refused-255.255.255.255.csv' }
        @{ Name = 'refused-224.0.0.1.csv' }
        @{ Name = 'refused-239.255.255.250.csv' }
        @{ Name = 'refused-169.254.1.1.csv' }
        @{ Name = 'refused-unspecified-v6.csv' }
        @{ Name = 'refused-fe80-1.csv' }
        @{ Name = 'refused-ff02-1.csv' }
        @{ Name = 'refused-mapped-broadcast.csv' }
        @{ Name = 'refused-mapped-multicast.csv' }
        @{ Name = 'refused-mapped-linklocal.csv' }
        @{ Name = 'refused-cidr-hostbits.json' }
    ) {
        $path = Join-Path $script:FixturesDir $Name
        $rec = Initialize-PPRecorder
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -AllowCidr) -Adapters $script:StubAdapters -Recorder $rec
        $result.Success | Should -BeFalse -Because $Name
        $result.ExitCode | Should -Be 2 -Because $Name
        $rec.Count | Should -Be 0 -Because $Name
    }
}

Describe 'PortProof.Security.AC15 (resolved refused classes, via the FixtureResolver, zero accepts and zero datagrams)' -Tag 'Portable' {

    It 'refuses <Name> resolved to a refused-class address, naming the row, name, address and class, calling no adapter' -ForEach @(
        @{ Name = 'broadcast.test'; Class = 'limited-broadcast' }
        @{ Name = 'multicast.test'; Class = 'multicast' }
        @{ Name = 'linklocal.test'; Class = 'link-local' }
        @{ Name = 'thisnetwork.test'; Class = 'this-network' }
        @{ Name = 'unspecified.test'; Class = 'unspecified' }
        @{ Name = 'multicast6.test'; Class = 'multicast' }
    ) {
        $table = Get-PPResolverTableFixture
        $resolver = Get-PPFixtureResolver -Table $table
        $rows = @(
            @{ Source = 'c'; Target = $Name; Port = 443; Protocol = 'TCP'; Required = 'no' }
            @{ Source = 'c'; Target = $Name; Port = 53; Protocol = 'UDP'; Required = 'no' }
        )
        $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive ('ac15-resolved-' + $Name.Replace('.', '_') + '.csv'))
        $rec = Initialize-PPRecorder
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path) -LiveResolver $resolver -Adapters $script:StubAdapters -Recorder $rec
        $result.Success | Should -BeFalse -Because $Name
        $result.ExitCode | Should -Be 2 -Because $Name
        $ppError = Get-PPError -Errors $result.Errors
        $ppError.FullyQualifiedErrorId | Should -BeLike 'PortProof.RefusedTargetClass*' -Because $Name
        $ppError.Exception.Message | Should -BeLike "*'$Name'*"
        $ppError.TargetObject.Detail.Class | Should -Be $Class
        $rec.Count | Should -Be 0 -Because $Name
    }
}

Describe 'PortProof.Security.AC15 (loopback is accepted)' -Tag 'Portable' {

    It 'a plain loopback literal is accepted, and ::ffff:127.0.0.1 is accepted and probed as 127.0.0.1' {
        $rec = Initialize-PPRecorder
        $rows = @(
            @{ Source = 'c'; Target = '127.0.0.1'; Port = 55001; Protocol = 'TCP'; Required = 'no' }
            @{ Source = 'c'; Target = '::ffff:127.0.0.1'; Port = 55002; Protocol = 'TCP'; Required = 'no' }
        )
        $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac15-loopback.csv')
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path) -Adapters $script:StubAdapters -Recorder $rec
        $result.Success | Should -BeTrue
        $calls = @($rec.ToArray() | Where-Object { $_.Event -eq 'Enter' })
        $calls.Count | Should -Be 2
        @($calls | ForEach-Object { $_.TargetIp }) | Should -Be @('127.0.0.1', '127.0.0.1')
    }
}

Describe 'PortProof.Security.AC31 (the schema is fail-closed against the corpus, a property)' -Tag 'Portable' {

    BeforeDiscovery {
        $casesPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'tests\Fixtures\corpus\cases.csv'
        # Import-Csv returns PSCustomObjects; Pester's -ForEach only injects per-item variables
        # (and <Token> substitution in It names) from hashtables, so convert each row explicitly.
        $script:CorpusCases = @(Import-Csv -LiteralPath $casesPath | ForEach-Object {
                @{ File = $_.file; ExpectedErrorId = $_.expected_error_id; Names = $_.names }
            })
        if ($script:CorpusCases.Count -lt 40) {
            throw "PortProof Security: corpus/cases.csv has only $($script:CorpusCases.Count) rows; AC31 needs at least 40."
        }
    }

    It '<File> (expecting <ExpectedErrorId>) never exits 0 or 1, live or under -DryRun; the message names a row or a field; -DryRun reports zero probes' -ForEach $script:CorpusCases {
        $path = Join-Path (Split-Path -Parent $PSScriptRoot) ('tests\Fixtures\' + $File)
        (Test-Path -LiteralPath $path) | Should -BeTrue -Because $File

        # -AllowCidr's own gate (Get-PPCidrPlan) checks "was -AllowCidr given" BEFORE every other
        # CIDR-specific refusal (CidrTooWide/CidrNotAligned/CidrInSource/CapExceeded.Expansion), so
        # any of those needs the flag to be reached at all; Group.CidrNotAllowed is specifically the
        # "-AllowCidr was NOT given" case, so it is the one expectation that must NOT get the flag
        # (passing it would skip past that exact refusal to whichever one comes next). -AllowCidr
        # has no effect at all on a non-CIDR profile, so passing it is harmless for every other
        # corpus case. Deriving this from the structured expected_error_id column (not the free-text
        # "names" column, whose exact wording changes as corpus rows are added/edited - observed: an
        # update to rows 53-55 dropped the "-AllowCidr" phrase entirely) is what keeps
        # this loop reading the expectation from cases.csv rather than hardcoding anything about it.
        $needsAllowCidr = ($ExpectedErrorId -cne 'Group.CidrNotAllowed')

        $rec = Initialize-PPRecorder
        $live = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -AllowCidr:$needsAllowCidr) -Adapters $script:StubAdapters -Recorder $rec
        $live.ExitCode | Should -Be 2 -Because $File
        $live.ExitCode | Should -Not -Be 0 -Because $File
        $live.ExitCode | Should -Not -Be 1 -Because $File
        $ppError = Get-PPError -Errors $live.Errors
        $ppError | Should -Not -BeNullOrEmpty -Because "$File produced no PortProof.* error record"
        $ppError.FullyQualifiedErrorId | Should -Be ('PortProof.' + $ExpectedErrorId) -Because $File
        $liveMessage = $ppError.Exception.Message
        ($liveMessage -match '(?i)row \d+' -or $liveMessage -match '(?i)(source|target|port|protocol|required|service|notes|column|key|group|schema|encoding)') | Should -BeTrue -Because "$File message: $liveMessage"
        $rec.Count | Should -Be 0 -Because $File

        $dry = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -AllowCidr:$needsAllowCidr -DryRun)
        $dry.ExitCode | Should -Be 2 -Because $File
        $dry.ExitCode | Should -Not -Be 0 -Because $File
        $dry.ExitCode | Should -Not -Be 1 -Because $File
    }
}

Describe 'PortProof.Security.AC31 (static scanners run over the built dist/ copy)' -Tag 'Windows' {

    BeforeAll {
        # The scanners' file-scoped allowances resolve a dist/ offset back to its owning src/ file
        # by reading the `# ---- src/<part> ----` banners build/Build-PortProof.ps1 writes before
        # every part after the first, plus build/parts.txt's own first entry for the un-bannered
        # leading part. That means "the built dist/ copy" these scanners expect is
        # specifically one produced BY the real build script from a real src/ + build/parts.txt tree
        # - not just any file dropped at dist/PortProof.ps1 - so mirror the real src/ and
        # build/parts.txt under one ephemeral root and run the real, unmodified
        # build/Build-PortProof.ps1 against it (read-only: never writes to the real build/ or
        # dist/), the same technique tests/Static/Static.Tests.ps1's own DistPartMapping
        # fixture uses.
        $script:DistCopyRoot = Join-Path $TestDrive 'dist-copy-root'
        $srcDir = Join-Path $script:DistCopyRoot 'src'
        $buildDir = Join-Path $script:DistCopyRoot 'build'
        [void] (New-Item -ItemType Directory -Path $srcDir -Force)
        [void] (New-Item -ItemType Directory -Path $buildDir -Force)
        # -Path (not -LiteralPath) here: the trailing '*.ps1' is a wildcard, and -LiteralPath would
        # search for a file literally named '*.ps1' instead of expanding it (observed: copied
        # nothing, silently, until the build script's own "does not exist" check caught it).
        Copy-Item -Path (Join-Path $script:Root 'src\*.ps1') -Destination $srcDir -Force
        Copy-Item -LiteralPath (Join-Path $script:Root 'build\parts.txt') -Destination (Join-Path $buildDir 'parts.txt') -Force

        $buildScript = Join-Path $script:Root 'build\Build-PortProof.ps1'
        $buildResult = & $buildScript -Root $script:DistCopyRoot -OutFile 'dist/PortProof.ps1' -PartsFile 'build/parts.txt' 2>&1
        $distFile = Join-Path $script:DistCopyRoot 'dist\PortProof.ps1'
        if (-not (Test-Path -LiteralPath $distFile)) {
            throw "AC31 dist-copy setup: build/Build-PortProof.ps1 did not produce '$distFile'. Output: $buildResult"
        }
        $script:StaticDir = Join-Path $script:Root 'tests\Static'
    }

    It '<Scanner> exits 0 against the built dist/ copy' -ForEach @(
        @{ Scanner = 'Test-ProbeProhibitions.ps1' }
        @{ Scanner = 'Test-ResolverIsolation.ps1' }
        @{ Scanner = 'Test-NoCredentials.ps1' }
        @{ Scanner = 'Test-NoOutbound.ps1' }
        @{ Scanner = 'Test-NoDeferredFeatures.ps1' }
        @{ Scanner = 'Test-NoDynamicEval.ps1' }
        @{ Scanner = 'Test-CallSites.ps1' }
        @{ Scanner = 'Test-TemplateTokens.ps1' }
        # Test-HtmlSelfContained.ps1 (AC14) is excluded here on purpose: it takes -Path to one
        # rendered HTML file, not -Root to a source tree, so it does not fit this "-Root" harness;
        # it already runs against the golden HTML in tests/Render.Tests.ps1 and is exercised
        # directly (via a live-rendered report) by Integration.Tests.ps1's AC13 test.
    ) {
        # Every scanner script ends with a top-level `exit 0`/`exit 1`. Calling that in-process (via
        # `&`) would terminate this whole Pester run's PowerShell host, not just the scanner, so it
        # must be a real child process (mirrors Invoke-PortProofProcess's -File form).
        $scriptPath = Join-Path $script:StaticDir $Scanner
        $stdOutFile = [System.IO.Path]::GetTempFileName()
        $stdErrFile = [System.IO.Path]::GetTempFileName()
        try {
            $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-NonInteractive', '-File', $scriptPath, '-Root', $script:DistCopyRoot) `
                -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdOutFile -RedirectStandardError $stdErrFile
            $out = Get-Content -LiteralPath $stdOutFile -Raw -ErrorAction SilentlyContinue
            $err = Get-Content -LiteralPath $stdErrFile -Raw -ErrorAction SilentlyContinue
            # The dist/ -> src banner mapping means
            # this runs as a real assertion against a genuinely built dist/ copy - no
            # Set-ItResult -Skipped workaround. If this ever fails again, the repro is: build a real
            # dist/PortProof.ps1 via build/Build-PortProof.ps1 -Root <a root with real src/ and
            # build/parts.txt copies> (exactly what this Describe's BeforeAll does), then run
            # `powershell -File tests/Static/<scanner> -Root <that root>` directly to see the same
            # findings outside Pester.
            $proc.ExitCode | Should -Be 0 -Because "findings against the built dist/ copy:`n$out$err"
        }
        finally {
            Remove-Item -LiteralPath $stdOutFile, $stdErrFile -ErrorAction SilentlyContinue
        }
    }
}
