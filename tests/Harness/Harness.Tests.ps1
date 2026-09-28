# Self-tests for the test harness itself: listeners, the FixtureResolver, the recording adapter,
# and the Pester-version guard's failure path. All of this opens sockets or spawns a process, so
# every Describe here is tagged Windows (AC4).

BeforeAll {
    . (Join-Path $PSScriptRoot 'Harness.ps1')
    . (Join-Path $PSScriptRoot 'Listeners.ps1')
    . (Join-Path $PSScriptRoot 'Recorder.ps1')
    . (Join-Path $PSScriptRoot 'FixtureResolver.ps1')
}

Describe 'PortProof.Harness.Listeners' -Tag 'Windows' {

    It 'binds distinct loopback addresses and refuses a connect to the wrong alias (E2)' {
        $addrA = Get-PPLoopbackAddress
        $addrB = Get-PPLoopbackAddress
        $addrA | Should -Not -Be $addrB

        $listener = Open-PPTcpListener -Address $addrA -Mode Accept
        try {
            # Connect to the address the listener actually bound: succeeds.
            $good = [System.Net.Sockets.TcpClient]::new()
            $goodConnected = $good.ConnectAsync($addrA, $listener.Port).Wait(2000)
            $good.Close()
            $goodConnected | Should -BeTrue

            # Connect to a different loopback alias on the same port: nothing is listening there.
            # Measured on this host: the refusal can take close to 2 seconds to surface (unlike the
            # near-instant RST on 127.0.0.1), so treat "still not connected after the wait" as the
            # refusal signal rather than requiring the wait call itself to throw before then.
            $bad = [System.Net.Sockets.TcpClient]::new()
            $refused = $false
            try {
                $null = $bad.ConnectAsync($addrB, $listener.Port).Wait(5000)
                if (-not $bad.Connected) { $refused = $true }
            } catch {
                $refused = $true
            }
            $bad.Close()
            $refused | Should -BeTrue
        } finally {
            Close-PPListener -Listener $listener
        }
    }

    It 'RefuseAfterOne accepts exactly one connection then refuses the next' {
        $addr = Get-PPLoopbackAddress
        $listener = Open-PPTcpListener -Address $addr -Mode RefuseAfterOne
        try {
            $first = [System.Net.Sockets.TcpClient]::new()
            $null = $first.ConnectAsync($addr, $listener.Port).Wait(2000)
            $first.Close()

            # Give the background loop time to observe the accept and stop the listener.
            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while ($listener.Events.Count -lt 1 -and $deadline.Elapsed.TotalSeconds -lt 5) {
                Start-Sleep -Milliseconds 25
            }
            $listener.Events.Count | Should -Be 1

            $second = [System.Net.Sockets.TcpClient]::new()
            $secondThrew = $false
            try {
                $null = $second.ConnectAsync($addr, $listener.Port).Wait(2000)
                if (-not $second.Connected) { $secondThrew = $true }
            } catch {
                $secondThrew = $true
            }
            $second.Close()
            $secondThrew | Should -BeTrue
        } finally {
            Close-PPListener -Listener $listener
        }
    }

    It 'counts an unbound port as refused (Get-PPUnboundPort)' {
        $addr = Get-PPLoopbackAddress
        $port = Get-PPUnboundPort -Address $addr

        $client = [System.Net.Sockets.TcpClient]::new()
        $threw = $false
        try {
            $null = $client.ConnectAsync($addr, $port).Wait(2000)
            if (-not $client.Connected) { $threw = $true }
        } catch {
            $threw = $true
        }
        $client.Close()
        $threw | Should -BeTrue
    }

    It 'UDP listener in Reply mode sends one byte back and counts the datagram' {
        $addr = Get-PPLoopbackAddress
        $listener = Open-PPUdpListener -Address $addr -Reply
        try {
            $client = [System.Net.Sockets.UdpClient]::new()
            $client.Client.ReceiveTimeout = 2000
            $client.Connect($addr, $listener.Port)
            [void] $client.Send([byte[]] @(1), 1)

            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            $reply = $client.Receive([ref] $remote)
            $client.Close()

            $reply.Length | Should -Be 1

            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while ($listener.Events.Count -lt 1 -and $deadline.Elapsed.TotalSeconds -lt 5) {
                Start-Sleep -Milliseconds 25
            }
            $listener.Events.Count | Should -Be 1
        } finally {
            Close-PPListener -Listener $listener
        }
    }

    It 'refuses to bind or send to a non-loopback address' {
        { Open-PPTcpListener -Address '10.0.0.5' -Mode Accept } | Should -Throw
        { Open-PPUdpListener -Address '10.0.0.5' } | Should -Throw
        { Get-PPUnboundPort -Address '10.0.0.5' } | Should -Throw
    }
}

Describe 'PortProof.Harness.FixtureResolver' -Tag 'Windows' {

    BeforeAll {
        # Every test in this Describe must see the opt-in gate off, regardless of the outer
        # environment, so the loopback-only guard's default behaviour is what gets exercised.
        $script:savedOffHost = $env:PORTPROOF_TEST_OFFHOST
        $script:savedTimeoutTarget = $env:PORTPROOF_TEST_TIMEOUT_TARGET
        $env:PORTPROOF_TEST_OFFHOST = $null
        $env:PORTPROOF_TEST_TIMEOUT_TARGET = $null
    }

    AfterAll {
        $env:PORTPROOF_TEST_OFFHOST = $script:savedOffHost
        $env:PORTPROOF_TEST_TIMEOUT_TARGET = $script:savedTimeoutTarget
    }

    It 'resolves a table entry to the addresses given, case-insensitively, without touching DNS' {
        $resolver = Get-PPFixtureResolver -Table @{ 'dc01.corp.example' = @('127.1.1.20', '127.1.1.21') }
        $resolver.PSTypeNames | Should -Contain 'PortProof.Resolver'
        $resolver.Kind | Should -Be 'Fixture'
        $resolver.Invocations | Should -Be 0

        $addresses = & $resolver.Resolve 'DC01.Corp.Example'
        $addresses.Count | Should -Be 2
        $addresses[0].ToString() | Should -Be '127.1.1.20'
        $addresses[1].ToString() | Should -Be '127.1.1.21'
    }

    It 'throws PortProof.DnsFailure for a name not in the table' {
        $resolver = Get-PPFixtureResolver -Table @{ 'known.test' = @('127.0.9.1') }
        $errorRecord = $null
        try {
            & $resolver.Resolve 'unknown.test'
        } catch {
            $errorRecord = $_
        }
        $errorRecord | Should -Not -BeNullOrEmpty
        $errorRecord.FullyQualifiedErrorId | Should -Match '^PortProof\.DnsFailure'
    }

    It 'off-host opt-in gate (Test-PPOffHostOptIn) is off by default' {
        Test-PPOffHostOptIn | Should -BeFalse
    }

    It 'throws a named, non-DnsFailure error for a non-loopback, non-refused-class entry' {
        $resolver = Get-PPFixtureResolver -Table @{ 'offhost.test' = @('192.0.2.55') }
        $errorRecord = $null
        try {
            & $resolver.Resolve 'offhost.test'
        } catch {
            $errorRecord = $_
        }
        $errorRecord | Should -Not -BeNullOrEmpty
        $errorRecord.FullyQualifiedErrorId | Should -Be 'PortProofTest.NonLoopbackAddress'
        $errorRecord.FullyQualifiedErrorId | Should -Not -Match '^PortProof\.DnsFailure'
    }

    It 'allows a RefusedClass-marked entry to resolve off loopback without the opt-in gate' {
        $resolver = Get-PPFixtureResolver -Table @{
            'refused.test' = @{ Addresses = @('224.0.0.1'); RefusedClass = $true }
        }
        $addresses = & $resolver.Resolve 'refused.test'
        $addresses[0].ToString() | Should -Be '224.0.0.1'
    }

    It 'allows a non-loopback entry when PORTPROOF_TEST_OFFHOST=1 is set (the single opt-in gate)' {
        $env:PORTPROOF_TEST_OFFHOST = '1'
        try {
            $resolver = Get-PPFixtureResolver -Table @{ 'offhost.test' = @('192.0.2.55') }
            $addresses = & $resolver.Resolve 'offhost.test'
            $addresses[0].ToString() | Should -Be '192.0.2.55'
        } finally {
            $env:PORTPROOF_TEST_OFFHOST = $null
        }
    }

    It 'every resolver-table.json entry is loopback or explicitly marked refused_class' {
        $table = Get-PPResolverTableFixture
        $table.Count | Should -BeGreaterThan 0
        foreach ($name in $table.Keys) {
            $entry = $table[$name]
            if ($entry.RefusedClass) { continue }
            foreach ($addressText in $entry.Addresses) {
                $addr = [System.Net.IPAddress]::Parse($addressText)
                $isV4Loopback = $addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $addr.GetAddressBytes()[0] -eq 127
                $isV6Loopback = $addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $addr.Equals([System.Net.IPAddress]::IPv6Loopback)
                ($isV4Loopback -or $isV6Loopback) | Should -BeTrue -Because "resolver-table.json entry '$name' address '$addressText' must be loopback or marked refused_class"
            }
        }
    }

    It 'the committed resolver-table.json resolves without throwing through the real guard' {
        $table = Get-PPResolverTableFixture
        $resolver = Get-PPFixtureResolver -Table $table
        foreach ($name in $table.Keys) {
            { & $resolver.Resolve $name } | Should -Not -Throw
        }
    }

    It 'AC30 fixtures in resolver-table.json are correct: multi-address distinct, alias coalescing, dc01 pair distinct' {
        $table = Get-PPResolverTableFixture
        $resolver = Get-PPFixtureResolver -Table $table

        $multi = & $resolver.Resolve 'multi-address.test'
        $multi.Count | Should -Be 4
        (@($multi | ForEach-Object { $_.ToString() }) | Select-Object -Unique).Count | Should -Be 4

        $aliasOne = & $resolver.Resolve 'alias-one.test'
        $aliasTwo = & $resolver.Resolve 'alias-two.test'
        $aliasOne[0].ToString() | Should -Be $aliasTwo[0].ToString()

        $dc01 = & $resolver.Resolve 'dc01.corp.example'
        $dc01.Count | Should -Be 2
        $dc01[0].ToString() | Should -Not -Be $dc01[1].ToString()
    }

    It 'refused_class entries resolve to addresses the class predicate refuses (the Gate would refuse them before any probe)' {
        . (Join-Path (Get-PPRepoRoot) 'src\05-Contract.ps1')

        $table = Get-PPResolverTableFixture
        $resolver = Get-PPFixtureResolver -Table $table
        $refusedNames = @($table.Keys | Where-Object { $table[$_].RefusedClass })
        $refusedNames.Count | Should -BeGreaterThan 0

        foreach ($name in $refusedNames) {
            $addresses = & $resolver.Resolve $name
            foreach ($addr in $addresses) {
                $verdict = Test-RefusedTargetClass -Address $addr
                $verdict.Refused | Should -BeTrue -Because "'$name' resolves to '$addr', which the refused-class table must refuse before any probe is scheduled"
            }
        }
    }
}

Describe 'PortProof.Harness.Recorder' -Tag 'Windows' {

    It 'records Enter/Exit pairs and reports a peak that matches concurrent invocation' {
        $recorder = Initialize-PPRecorder

        $jobs = 1..3 | ForEach-Object {
            [System.Management.Automation.PowerShell]::Create().
                AddScript(${function:Invoke-RecordingAdapter}).
                AddParameter('Address', [System.Net.IPAddress]::Parse('127.0.0.1')).
                AddParameter('Port', 80).
                AddParameter('TimeoutMs', 2000).
                AddParameter('Recorder', $recorder)
        }
        $handles = $jobs | ForEach-Object { $_.BeginInvoke() }
        for ($i = 0; $i -lt $jobs.Count; $i++) {
            [void] $jobs[$i].EndInvoke($handles[$i])
            $jobs[$i].Dispose()
        }

        $recorder.Count | Should -Be 6
        (Measure-PPPeakOccupancy -Recorder $recorder) | Should -BeGreaterOrEqual 1
        (Measure-PPPeakOccupancy -Recorder $recorder) | Should -BeLessOrEqual 3
    }

    It 'Measure-PPOverlap is zero for a single serial call' {
        $recorder = Initialize-PPRecorder
        [void] (Invoke-RecordingAdapter -Address ([System.Net.IPAddress]::Parse('127.0.0.9')) -Port 80 -TimeoutMs 2000 -Recorder $recorder)
        (Measure-PPOverlap -Recorder $recorder -TargetIp '127.0.0.9') | Should -Be 0
    }
}

Describe 'PortProof.Invoke-Tests Pester guard' -Tag 'Windows' {

    It 'exits 3 with a named message when only Pester < 5 is importable' {
        $repoRoot = Get-PPRepoRoot
        $runner = Join-Path $repoRoot 'tests\Invoke-Tests.ps1'

        $fakeModuleRoot = Join-Path $TestDrive 'FakePesterModules'
        $fakePesterDir = Join-Path $fakeModuleRoot 'Pester\3.4.0'
        New-Item -ItemType Directory -Path $fakePesterDir -Force | Out-Null
        @'
@{
    ModuleVersion = '3.4.0'
    GUID = 'a698358a-8a34-4a9f-8fb9-6f7a75fb1e5e'
    RootModule = 'Pester.psm1'
    FunctionsToExport = @()
}
'@ | Set-Content -LiteralPath (Join-Path $fakePesterDir 'Pester.psd1') -Encoding utf8
        @'
# fake in-box Pester for the guard-failure-path test; exports nothing real.
'@ | Set-Content -LiteralPath (Join-Path $fakePesterDir 'Pester.psm1') -Encoding utf8

        $stdOutFile = Join-Path $TestDrive 'stdout.txt'
        $stdErrFile = Join-Path $TestDrive 'stderr.txt'
        $cmd = "`$env:PSModulePath = '$fakeModuleRoot'; & '$runner' -Suite Portable; exit `$LASTEXITCODE"
        $proc = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $cmd) `
            -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdOutFile -RedirectStandardError $stdErrFile

        $proc.ExitCode | Should -Be 3
        $output = (Get-Content -LiteralPath $stdOutFile -Raw -ErrorAction SilentlyContinue) +
                  (Get-Content -LiteralPath $stdErrFile -Raw -ErrorAction SilentlyContinue)
        $output | Should -Match 'Pester 5'
    }
}

Describe 'PortProof.Harness.InvokePortProofProcess (-Entry Command quoting)' -Tag 'Windows' {
    <#
        Invoke-PortProofProcess -Entry 'Command' used to single-quote every -ArgumentList
        token, including flag names like '-Profile'. Quoted, '-Profile' is just a string value, not
        a recognised parameter name, and 90-Main.ps1's PositionalBinding = $false then refuses to
        bind it positionally - the -Command entry path could only ever produce a binding error.
        Fixed: a flag token (leading '-' then an identifier) now passes bare; only value tokens are
        single-quoted, with an embedded ' doubled to ''.
    #>

    BeforeAll {
        $script:ValidProfilePath = Join-Path (Get-PPRepoRoot) 'tests\Fixtures\valid-minimal.csv'
    }

    It 'a real in-script refusal (-MaxProbes 0) reaches Assert-Arguments and exits 2 through -Command' {
        $result = Invoke-PortProofProcess -Entry Command -ArgumentList @(
            '-Profile', $script:ValidProfilePath, '-MaxProbes', '0'
        )
        $result.ExitCode | Should -Be 2
    }

    It 'documents the binding-error case: an unknown parameter exits 0 under -Command "...; exit $LASTEXITCODE"' {
        $result = Invoke-PortProofProcess -Entry Command -ArgumentList @('-Bogus')
        # Not ours: PowerShell's own binding failure happens before "&" ever runs, so
        # $LASTEXITCODE is never set by this invocation and "exit $LASTEXITCODE" exits 0 -
        # reproduced here so a regression in the quoting fix cannot silently
        # change this documented (if surprising) behaviour without failing a test.
        $result.ExitCode | Should -Be 0
    }

    It 'a value containing a space and an apostrophe survives the round trip (the profile path itself)' {
        $oddDir = Join-Path $TestDrive "it's a test dir"
        New-Item -ItemType Directory -Path $oddDir -Force | Out-Null
        $oddProfilePath = Join-Path $oddDir 'profile.csv'
        Copy-Item -LiteralPath $script:ValidProfilePath -Destination $oddProfilePath -Force

        $result = Invoke-PortProofProcess -Entry Command -ArgumentList @('-Profile', $oddProfilePath, '-DryRun')
        $result.ExitCode | Should -Be 0
    }

    It 'the same -MaxProbes 0 refusal also exits 2 through the -File entry path (parity check)' {
        $result = Invoke-PortProofProcess -Entry File -ArgumentList @(
            '-Profile', $script:ValidProfilePath, '-MaxProbes', '0'
        )
        $result.ExitCode | Should -Be 2
    }
}
