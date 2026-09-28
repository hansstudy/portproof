# Gate tests. The Portable groups replace every adapter with an in-test
# recording stub, so no socket opens: the Recorder proves that a refusal happens before any adapter
# call. The Windows group runs the real TCP adapter against distinct 127.0.0.0/8 listeners (AC30
# multi-address and coalescing, observed at the listener).

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    foreach ($part in @('05-Contract', '30-Resolver', '35-Gate', '40-Scheduler', '50-Probe.Tcp', '55-Probe.Udp', '58-Probe.Icmp')) {
        . (Join-Path $script:Root "src/$part.ps1")
    }
    . (Join-Path $PSScriptRoot 'Harness/Harness.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Recorder.ps1')
    . (Join-Path $PSScriptRoot 'Harness/FixtureResolver.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Listeners.ps1')

    function Invoke-StubAdapter {
        # Worker-safe stub (only .NET): records every call, opens nothing, returns a valid result.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimeoutMs',
            Justification = 'The fixed adapter signature; the stub never waits.')]
        param(
            [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
            [Parameter(Mandatory)] [int] $Port,
            [Parameter(Mandatory)] [int] $TimeoutMs,
            [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
        )
        if ($null -ne $Recorder) {
            $Recorder.Enqueue([pscustomobject]@{ Event = 'Call'; TargetIp = $Address.ToString(); Port = $Port; Ticks = [System.Diagnostics.Stopwatch]::GetTimestamp() })
        }
        $state = 'Open'
        if ($Port -eq 0) { $state = 'Reply' }
        [pscustomobject]@{ PSTypeName = 'PortProof.AdapterResult'; State = $state; ErrorName = 'None'; LatencyMs = 0 }
    }

    function Get-Probe {
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

    function Get-Resolution {
        # A Resolution built directly (not by Resolve-PPProbeList): Count probes spread round-robin
        # over Targets distinct 127.2.x.y addresses, ports 1.., TCP.
        param([int] $Count, [int] $Targets)
        $exec = [System.Collections.Generic.List[object]]::new()
        $entries = @{}
        for ($i = 0; $i -lt $Count; $i++) {
            $t = $i % $Targets
            $third = [int][Math]::Floor($t / 250)
            $fourth = ($t % 250) + 1
            $ip = [System.Net.IPAddress]::Parse(('127.2.{0}.{1}' -f $third, $fourth))
            $port = [int][Math]::Floor($i / $Targets) + 1
            $key = '{0}|{1}|TCP' -f $ip, $port
            $exec.Add([pscustomobject]@{ ExecKey = $key; TargetIp = $ip; Port = $port; Protocol = 'TCP'; JitterMs = 0 })
            $entries[$key] = [pscustomobject]@{ TargetIp = $ip; ResolvedAddresses = [string[]]@($ip.ToString()); Failed = $false; TargetName = $ip.ToString(); Rows = @($i + 2) }
        }
        [pscustomobject]@{ PSTypeName = 'PortProof.Resolution'; Entries = $entries; ExecProbes = $exec.ToArray(); CountBefore = $Count; CountAfter = $Count }
    }

    function Get-Schedule {
        param([int] $JitterMs = 0)
        @{ Concurrency = 4; MaxProbesPerSecond = 500; JitterMs = $JitterMs; TimeoutMs = 1000; ExecutionPath = 'Runspace' }
    }

    function Get-CaughtError {
        param([scriptblock] $Action)
        try { & $Action; return $null } catch { return $_ }
    }

    $script:Stub = @{ TCP = 'Invoke-StubAdapter'; UDP = 'Invoke-StubAdapter'; ICMP = 'Invoke-StubAdapter' }
    $script:Table = Get-PPResolverTableFixture
}

Describe 'PortProof.Gate.ResolvedClass (AC15 resolved half)' -Tag 'Portable' {

    It 'refuses <Name> naming row, name, address and class, before any adapter call' -ForEach @(
        @{ Name = 'broadcast.test'; Address = '255.255.255.255'; Class = 'limited-broadcast' }
        @{ Name = 'multicast.test'; Address = '224.0.0.1'; Class = 'multicast' }
        @{ Name = 'linklocal.test'; Address = '169.254.1.1'; Class = 'link-local' }
        @{ Name = 'thisnetwork.test'; Address = '0.1.2.3'; Class = 'this-network' }
        @{ Name = 'unspecified.test'; Address = '::'; Class = 'unspecified' }
        @{ Name = 'multicast6.test'; Address = 'ff02::1'; Class = 'multicast' }
    ) {
        $rec = Initialize-PPRecorder
        $seenAdmitted = [System.Collections.Generic.List[int]]::new()
        $resolver = Get-PPFixtureResolver -Table $script:Table
        $probes = @((Get-Probe -Target 'alias-one.test' -Port 443 -Rows @(2)), (Get-Probe -Target $Name -Port 443 -Rows @(7)))
        $resolution = Resolve-PPProbeList -Probes $probes -Resolver $resolver
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec -OnAdmitted { param($n) $seenAdmitted.Add($n) } }

        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.RefusedTargetClass*'
        $expectedLabel = (Test-RefusedTargetClass -Address ([System.Net.IPAddress]::Parse($Address))).ClassLabel
        $message = $err.Exception.Message
        $message | Should -BeLike "*row 7 *"
        $message | Should -BeLike "*'$Name'*"
        $message | Should -BeLike "* $Address*"
        $message | Should -BeLike "*$expectedLabel*"
        $err.TargetObject.Detail.Class | Should -Be $Class
        $err.TargetObject.Row | Should -Be 7
        $rec.Count | Should -Be 0
        $seenAdmitted.Count | Should -Be 0
    }

    It 'refuses every refused_class entry of resolver-table.json with zero adapter calls' {
        $rec = Initialize-PPRecorder
        $refusedNames = @($script:Table.Keys | Where-Object { $script:Table[$_].RefusedClass } | Sort-Object)
        $refusedNames.Count | Should -BeGreaterOrEqual 6
        foreach ($name in $refusedNames) {
            $resolution = Resolve-PPProbeList -Probes @(Get-Probe -Target $name -Port 80) -Resolver (Get-PPFixtureResolver -Table $script:Table)
            $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
            $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.RefusedTargetClass*' -Because $name
        }
        $rec.Count | Should -Be 0
    }

    It 'refuses a name whose first address is loopback but a later one is refused (D16)' {
        $rec = Initialize-PPRecorder
        $resolver = Get-PPFixtureResolver -Table @{ 'mixed.test' = @{ Addresses = @('127.1.9.1', '224.0.0.251'); RefusedClass = $true } }
        $resolution = Resolve-PPProbeList -Probes @(Get-Probe -Target 'mixed.test' -Rows @(4)) -Resolver $resolver
        $resolution.ExecProbes[0].TargetIp.ToString() | Should -Be '127.1.9.1'
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.RefusedTargetClass*'
        $err.Exception.Message | Should -BeLike "*row 4 target 'mixed.test' resolves to 224.0.0.251*"
        $rec.Count | Should -Be 0
    }

    It 'refuses a refused ExecProbe.TargetIp even when Entries is clean (check b)' {
        $rec = Initialize-PPRecorder
        $resolution = Get-Resolution -Count 2 -Targets 2
        $resolution.ExecProbes[1].TargetIp = [System.Net.IPAddress]::Parse('::ffff:169.254.1.1')
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.RefusedTargetClass*'
        $err.Exception.Message | Should -BeLike '*169.254.1.1*link-local*'
        $rec.Count | Should -Be 0
    }

    It 'refuses a refused literal that reached it (224.0.0.1 as an IPv4 probe)' {
        $rec = Initialize-PPRecorder
        $resolution = Resolve-PPProbeList -Probes @(Get-Probe -Target '224.0.0.1' -Rows @(9)) -Resolver (Get-PPFixtureResolver -Table @{})
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.RefusedTargetClass*'
        $err.Exception.Message | Should -BeLike '*row 9 *'
        $rec.Count | Should -Be 0
    }

    It 'admits loopback, and ::ffff:127.0.0.1 is probed as 127.0.0.1' {
        $rec = Initialize-PPRecorder
        $resolution = Resolve-PPProbeList -Probes @(Get-Probe -Target '::ffff:127.0.0.1' -Port 8080) -Resolver (Get-PPFixtureResolver -Table @{})
        $result = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec
        $result.AdmittedCount | Should -Be 1
        @($result.Results)[0].ExecKey | Should -Be '127.0.0.1|8080|TCP'
        @($rec.ToArray())[0].TargetIp | Should -Be '127.0.0.1'
    }
}

Describe 'PortProof.Gate.Cap (AC8 -Icmp counting, AC30 Gate refusal)' -Tag 'Portable' {

    It 'refuses 1000 probes + 30 ICMP (1030) at cap 1024, naming the cap and 1030, with zero adapter calls' {
        $rec = Initialize-PPRecorder
        $seenAdmitted = [System.Collections.Generic.List[int]]::new()
        $resolution = Get-Resolution -Count 1000 -Targets 30
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Icmp -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec -OnAdmitted { param($n) $seenAdmitted.Add($n) } }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.CapExceeded.Admitted*'
        $err.Exception.Message | Should -BeLike '*1030 admitted probes exceed the cap of 1024*'
        $rec.Count | Should -Be 0
        $seenAdmitted.Count | Should -Be 0
    }

    It 'refuses at Cap + 1 and admits at Cap exactly (1030 with -Icmp; admission stopped in OnAdmitted)' {
        $resolution = Get-Resolution -Count 1000 -Targets 30
        $rec = Initialize-PPRecorder
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1029 -Icmp -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.CapExceeded.Admitted*'

        $seenAdmitted = [System.Collections.Generic.List[int]]::new()
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1030 -Icmp -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec -OnAdmitted { param($n) $seenAdmitted.Add($n); throw 'STOP-AFTER-ADMISSION' } }
        $err.Exception.Message | Should -Be 'STOP-AFTER-ADMISSION'
        @($seenAdmitted) | Should -Be @(1030)
        $rec.Count | Should -Be 0
    }

    It 'adds exactly one ICMP echo per distinct target to the admitted count (4 targets, cap - 2 fixture)' {
        $rec = Initialize-PPRecorder
        $resolution = Get-Resolution -Count 8 -Targets 4
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 10 -Icmp -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.CapExceeded.Admitted*'
        $err.Exception.Message | Should -BeLike '*12 admitted probes exceed the cap of 10*'
        $rec.Count | Should -Be 0

        $result = Invoke-PPGate -Resolution $resolution -Cap 10 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec
        $result.AdmittedCount | Should -Be 8
        $result.IcmpCount | Should -Be 0
    }

    It 'schedules the ICMP echoes (Port 0, one per target, after the TCP/UDP probes) and returns one result each' {
        $rec = Initialize-PPRecorder
        $resolution = Get-Resolution -Count 4 -Targets 2
        $result = Invoke-PPGate -Resolution $resolution -Cap 6 -Icmp -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec
        $result.AdmittedCount | Should -Be 6
        $result.IcmpCount | Should -Be 2
        $result.ExecutionPath | Should -Be 'Runspace'
        $results = @($result.Results)
        $results.Count | Should -Be 6
        @($results | Where-Object { $_.Protocol -eq 'ICMP' } | ForEach-Object { $_.ExecKey } | Sort-Object) | Should -Be @('127.2.0.1|0|ICMP', '127.2.0.2|0|ICMP')
        @($results | Where-Object { $_.Protocol -eq 'ICMP' } | ForEach-Object { $_.Outcome }) | Should -Be @('Pass', 'Pass')
        $rec.Count | Should -Be 6
    }

    It 'clamps a caller cap above the absolute ceiling to 8192' {
        $resolution = Get-Resolution -Count 8193 -Targets 250
        $rec = Initialize-PPRecorder
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 100000 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.CapExceeded.Admitted*'
        $err.Exception.Message | Should -BeLike '*8193 admitted probes exceed the cap of 8192*'
        $rec.Count | Should -Be 0
    }
}

Describe 'PortProof.Gate.Invariant and admission order' -Tag 'Portable' {

    It 'refuses a Resolution whose CountAfter exceeds CountBefore (InternalInvariant), zero adapter calls' {
        $rec = Initialize-PPRecorder
        $resolution = Get-Resolution -Count 3 -Targets 3
        $resolution.CountBefore = 2
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.InternalInvariant*'
        $rec.Count | Should -Be 0
    }

    It 'refuses a Resolution whose CountAfter does not match its ExecProbes (InternalInvariant)' {
        $rec = Initialize-PPRecorder
        $resolution = Get-Resolution -Count 3 -Targets 3
        $resolution.CountAfter = 2
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.InternalInvariant*'
        $rec.Count | Should -Be 0
    }

    It 'refuses an ExecProbe that is not TCP/UDP to port 1..65535 (InternalInvariant)' {
        $rec = Initialize-PPRecorder
        $resolution = Get-Resolution -Count 1 -Targets 1
        $resolution.ExecProbes[0].Protocol = 'ICMP'
        $err = Get-CaughtError { Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec }
        $err.FullyQualifiedErrorId | Should -BeLike 'PortProof.InternalInvariant*'
        $rec.Count | Should -Be 0
    }

    It 'calls OnAdmitted exactly once, with the admitted count, before the first adapter call' {
        $rec = Initialize-PPRecorder
        $resolution = Get-Resolution -Count 6 -Targets 3
        $onAdmitted = { param($n) $rec.Enqueue([pscustomobject]@{ Event = 'Admitted'; Count = $n; Ticks = [System.Diagnostics.Stopwatch]::GetTimestamp() }) }
        $result = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec -OnAdmitted $onAdmitted
        $events = @($rec.ToArray())
        $admittedEvents = @($events | Where-Object { $_.Event -eq 'Admitted' })
        $admittedEvents.Count | Should -Be 1
        $admittedEvents[0].Count | Should -Be 6
        $calls = @($events | Where-Object { $_.Event -eq 'Call' })
        $calls.Count | Should -Be 6
        $firstCall = ($calls | Measure-Object -Property Ticks -Minimum).Minimum
        $admittedEvents[0].Ticks | Should -BeLessThan $firstCall
        @($result.Results).Count | Should -Be 6
    }

    It 'an OnAdmitted callback cannot change what is scheduled (it runs in a child scope of the Gate)' {
        # $admitted is also the name of the Gate's own list: before the fix, this callback's .Add
        # reached that list through dynamic scoping and scheduled a bogus probe.
        $rec = Initialize-PPRecorder
        $admitted = [System.Collections.Generic.List[int]]::new()
        $resolution = Get-Resolution -Count 3 -Targets 3
        $result = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -Recorder $rec -OnAdmitted { param($n) $admitted.Add($n); 'callback output' }
        $result.AdmittedCount | Should -Be 3
        @($result.Results).Count | Should -Be 3
        @($result.Results | Where-Object { $_ -is [string] }).Count | Should -Be 0
        $rec.Count | Should -Be 3
    }

    It 'admits an empty list: OnAdmitted(0), no results, ExecutionPath None' {
        $seenAdmitted = [System.Collections.Generic.List[int]]::new()
        $resolution = [pscustomobject]@{ Entries = @{}; ExecProbes = @(); CountBefore = 0; CountAfter = 0 }
        $result = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule) -Adapters $script:Stub -OnAdmitted { param($n) $seenAdmitted.Add($n) }
        @($seenAdmitted) | Should -Be @(0)
        $result.AdmittedCount | Should -Be 0
        @($result.Results).Count | Should -Be 0
        $result.ExecutionPath | Should -Be 'None'
    }
}

Describe 'PortProof.Gate.Jitter' -Tag 'Portable' {

    It 'assigns JitterMs 0 to every probe when J = 0' {
        Mock Invoke-ProbeSchedule { }
        $resolution = Get-Resolution -Count 20 -Targets 5
        $null = Invoke-PPGate -Resolution $resolution -Cap 1024 -Icmp -Schedule (Get-Schedule -JitterMs 0) -Adapters $script:Stub
        Should -Invoke Invoke-ProbeSchedule -Times 1 -Exactly -ParameterFilter {
            @($Probes).Count -eq 25 -and @($Probes | Where-Object { $_.JitterMs -ne 0 }).Count -eq 0
        }
    }

    It 'assigns JitterMs within 0..J from one generator when J > 0' {
        Mock Invoke-ProbeSchedule { }
        $resolution = Get-Resolution -Count 60 -Targets 6
        $null = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule (Get-Schedule -JitterMs 100) -Adapters $script:Stub
        Should -Invoke Invoke-ProbeSchedule -Times 1 -Exactly -ParameterFilter {
            $values = @($Probes | ForEach-Object { [int]$_.JitterMs })
            $values.Count -eq 60 -and
            @($values | Where-Object { $_ -lt 0 -or $_ -gt 100 }).Count -eq 0 -and
            @($values | Sort-Object -Unique).Count -gt 1
        }
    }

    It 'passes Concurrency, MaxProbesPerSecond, TimeoutMs and the resolved ExecutionPath to the Scheduler' {
        Mock Invoke-ProbeSchedule { }
        $resolution = Get-Resolution -Count 2 -Targets 1
        $schedule = @{ Concurrency = 7; MaxProbesPerSecond = 33; JitterMs = 0; TimeoutMs = 1500; ExecutionPath = 'Runspace' }
        $null = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule $schedule -Adapters $script:Stub
        Should -Invoke Invoke-ProbeSchedule -Times 1 -Exactly -ParameterFilter {
            $Concurrency -eq 7 -and $MaxProbesPerSecond -eq 33 -and $TimeoutMs -eq 1500 -and $ExecutionPath -eq 'Runspace'
        }
    }
}

Describe 'PortProof.Gate.Listeners (AC30 multi-address and coalescing at the listener)' -Tag 'Windows' {

    It 'probes only the first of four addresses: one accept there, zero on the other three' {
        $addresses = @(1..4 | ForEach-Object { Get-PPLoopbackAddress })
        $listeners = @()
        try {
            $listeners = @(Open-PPTcpListener -Address $addresses[0] -Mode Accept)
            $port = $listeners[0].Port
            foreach ($a in $addresses[1..3]) { $listeners += Open-PPTcpListener -Address $a -Mode Accept }
            $resolver = Get-PPFixtureResolver -Table @{ 'four.test' = $addresses }
            $resolution = Resolve-PPProbeList -Probes @(Get-Probe -Target 'four.test' -Port $port) -Resolver $resolver
            $schedule = @{ Concurrency = 4; MaxProbesPerSecond = 50; JitterMs = 0; TimeoutMs = 3000; ExecutionPath = 'Runspace' }
            $result = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule $schedule -Adapters (Get-PPContract).DefaultAdapters
            @($result.Results).Count | Should -Be 1
            @($result.Results)[0].State | Should -Be 'Open'
            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while ($listeners[0].Events.Count -lt 1 -and $deadline.ElapsedMilliseconds -lt 3000) { Start-Sleep -Milliseconds 25 }
            Start-Sleep -Milliseconds 300
            $listeners[0].Events.Count | Should -Be 1
            foreach ($l in $listeners[1..3]) { $l.Events.Count | Should -Be 0 }
            @($resolution.Entries.Values)[0].ResolvedAddresses.Count | Should -Be 4
        }
        finally {
            foreach ($l in $listeners) { Close-PPListener -Listener $l }
        }
    }

    It 'sends one connection for two names that resolve to one address' {
        $address = Get-PPLoopbackAddress
        $listener = Open-PPTcpListener -Address $address -Mode Accept
        try {
            $resolver = Get-PPFixtureResolver -Table @{ 'one.test' = $address; 'two.test' = $address }
            $probes = @((Get-Probe -Target 'one.test' -Port $listener.Port -Rows @(2)), (Get-Probe -Target 'two.test' -Port $listener.Port -Rows @(3)))
            $resolution = Resolve-PPProbeList -Probes $probes -Resolver $resolver
            $resolution.CountAfter | Should -Be 1
            $schedule = @{ Concurrency = 4; MaxProbesPerSecond = 50; JitterMs = 0; TimeoutMs = 3000; ExecutionPath = 'Runspace' }
            $result = Invoke-PPGate -Resolution $resolution -Cap 1024 -Schedule $schedule -Adapters (Get-PPContract).DefaultAdapters
            $result.AdmittedCount | Should -Be 1
            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while ($listener.Events.Count -lt 1 -and $deadline.ElapsedMilliseconds -lt 3000) { Start-Sleep -Milliseconds 25 }
            Start-Sleep -Milliseconds 300
            $listener.Events.Count | Should -Be 1
        }
        finally {
            Close-PPListener -Listener $listener
        }
    }
}
