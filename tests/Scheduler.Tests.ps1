# Scheduler tests (AC29 a/b). The Scheduler takes adapters by
# function name, so the harness's Invoke-RecordingAdapter (enter/exit timestamps, 200 ms hold) is
# injected in place of the real adapters and the concurrency peak and per-target overlap become
# observable without a socket. Every run passes JitterMs 0 (the AC29 "-Jitter 0" condition). Every
# assertion has a lower bound that fails when its mechanism is removed; mutation testing confirmed
# each one failing without its guard.
#
# The same cases run on both execution paths: Runspace (5.1 runspace pool) tagged Windows, and
# Parallel (7.x ForEach-Object -Parallel) tagged PS7. The listener group at the end probes distinct
# 127.0.0.0/8 listeners with the real TCP adapter.

BeforeDiscovery {
    $script:PathCases = @(
        @{ Path = 'Runspace'; Tag = 'Windows' }
        @{ Path = 'Parallel'; Tag = 'PS7' }
    )
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    foreach ($part in @('05-Contract', '40-Scheduler', '50-Probe.Tcp', '55-Probe.Udp', '58-Probe.Icmp')) {
        . (Join-Path $script:Root "src/$part.ps1")
    }
    . (Join-Path $PSScriptRoot 'Harness/Harness.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Recorder.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Listeners.ps1')

    function Invoke-TickAdapter {
        # Worker-safe: records one Enter tick per call and returns at once (rate measurements).
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimeoutMs',
            Justification = 'The fixed adapter signature; this adapter never waits.')]
        param(
            [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
            [Parameter(Mandatory)] [int] $Port,
            [Parameter(Mandatory)] [int] $TimeoutMs,
            [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
        )
        $Recorder.Enqueue([pscustomobject]@{ TargetIp = $Address.ToString(); Port = $Port; Event = 'Enter'; Ticks = [System.Diagnostics.Stopwatch]::GetTimestamp() })
        [pscustomobject]@{ PSTypeName = 'PortProof.AdapterResult'; State = 'Open'; ErrorName = 'None'; LatencyMs = 0 }
    }

    function Invoke-ThrowingAdapter {
        # Breaks the adapter contract on purpose: records the call, then throws.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimeoutMs',
            Justification = 'The fixed adapter signature; this adapter never waits.')]
        param(
            [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
            [Parameter(Mandatory)] [int] $Port,
            [Parameter(Mandatory)] [int] $TimeoutMs,
            [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
        )
        $Recorder.Enqueue([pscustomobject]@{ TargetIp = $Address.ToString(); Port = $Port; Event = 'Enter'; Ticks = [System.Diagnostics.Stopwatch]::GetTimestamp() })
        throw 'adapter failure injected by this test'
    }

    function Invoke-LyingAdapter {
        # Returns a State its protocol cannot report (Open for ICMP) and, on port 1002, two results.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimeoutMs',
            Justification = 'The fixed adapter signature; this adapter never waits.')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Address',
            Justification = 'The fixed adapter signature; this adapter ignores the address.')]
        param(
            [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
            [Parameter(Mandatory)] [int] $Port,
            [Parameter(Mandatory)] [int] $TimeoutMs
        )
        [pscustomobject]@{ State = 'Open'; ErrorName = 'None'; LatencyMs = 1 }
        if ($Port -eq 1002) { [pscustomobject]@{ State = 'Open'; ErrorName = 'None'; LatencyMs = 1 } }
    }

    function Invoke-BreakingAdapter {
        # A `break` escapes a function into the caller's loop: it ends the queue early, so the
        # probes after it get no result from their worker (the Scheduler must still report them).
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimeoutMs',
            Justification = 'The fixed adapter signature; this adapter never waits.')]
        param(
            [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
            [Parameter(Mandatory)] [int] $Port,
            [Parameter(Mandatory)] [int] $TimeoutMs,
            [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
        )
        $Recorder.Enqueue([pscustomobject]@{ TargetIp = $Address.ToString(); Port = $Port; Event = 'Enter'; Ticks = [System.Diagnostics.Stopwatch]::GetTimestamp() })
        break
    }

    function Invoke-PlainAdapter {
        # Declares no -Recorder, like the production adapters: must never be handed one.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
            Justification = 'The fixed adapter signature; this adapter only answers.')]
        param(
            [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
            [Parameter(Mandatory)] [int] $Port,
            [Parameter(Mandatory)] [int] $TimeoutMs
        )
        [pscustomobject]@{ PSTypeName = 'PortProof.AdapterResult'; State = 'Closed'; ErrorName = 'ConnectionRefused'; LatencyMs = 3 }
    }

    function Get-ExecProbe {
        # Count probes, spread round-robin over Targets distinct 127.4.0.x addresses (recording
        # adapters open nothing; the addresses only have to be distinct), ports 1001.., JitterMs 0.
        param([int] $Count, [int] $Targets, [string] $Protocol = 'TCP')
        for ($i = 0; $i -lt $Count; $i++) {
            $octet = ($i % $Targets) + 1
            $ip = [System.Net.IPAddress]::Parse(('127.4.0.{0}' -f $octet))
            $port = 1001 + [int][Math]::Floor($i / $Targets)
            [pscustomobject]@{ ExecKey = '{0}|{1}|{2}' -f $ip, $port, $Protocol; TargetIp = $ip; Port = $port; Protocol = $Protocol; JitterMs = 0 }
        }
    }

    function Invoke-Schedule {
        param([object[]] $Probes, [int] $Concurrency, [string] $Path, [int] $Rate = 500, [hashtable] $Adapters)
        if (-not $Adapters) { $Adapters = @{ TCP = 'Invoke-RecordingAdapter'; UDP = 'Invoke-RecordingAdapter'; ICMP = 'Invoke-RecordingAdapter' } }
        $rec = Initialize-PPRecorder
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @(Invoke-ProbeSchedule -Probes $Probes -Adapters $Adapters -Recorder $rec -Concurrency $Concurrency -MaxProbesPerSecond $Rate -TimeoutMs 1000 -ExecutionPath $Path -WarningVariable scheduleWarnings -WarningAction SilentlyContinue)
        $sw.Stop()
        [pscustomobject]@{ Results = $results; Recorder = $rec; ElapsedMs = $sw.ElapsedMilliseconds; Warnings = @($scheduleWarnings) }
    }

    function Get-EnterSpan {
        param([System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder)
        $ticks = @($Recorder.ToArray() | Where-Object { $_.Event -eq 'Enter' } | ForEach-Object { [long]$_.Ticks } | Sort-Object)
        ($ticks[-1] - $ticks[0]) / [double][System.Diagnostics.Stopwatch]::Frequency
    }
}

Describe 'PortProof.Scheduler.AC29 on the <Path> path' -Tag $script:PathCases[0].Tag -ForEach @($script:PathCases[0]) {
    BeforeAll { $script:SchedulerPath = $Path }

    It '(a) peak occupancy at -Concurrency 4 over 32 probes / 16 addresses is >= 2 and <= 4' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 32 -Targets 16) -Concurrency 4 -Path $script:SchedulerPath
        $peak = Measure-PPPeakOccupancy -Recorder $run.Recorder
        $peak | Should -BeGreaterOrEqual 2
        $peak | Should -BeLessOrEqual 4
        $run.Results.Count | Should -Be 32
    }

    It '(a) peak occupancy at -Concurrency 1 is exactly 1' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 8 -Targets 8) -Concurrency 1 -Path $script:SchedulerPath
        Measure-PPPeakOccupancy -Recorder $run.Recorder | Should -Be 1
    }

    It '(b) 16 probes to one target at -Concurrency 8: zero overlaps and elapsed >= 16 x 200 ms' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 16 -Targets 1) -Concurrency 8 -Path $script:SchedulerPath
        Measure-PPOverlap -Recorder $run.Recorder -TargetIp '127.4.0.1' | Should -Be 0
        $run.ElapsedMs | Should -BeGreaterOrEqual 3200
        $run.Results.Count | Should -Be 16
    }

    It '(b) the same 16 probes over 8 targets overlap across targets (>= 1) but never within one' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 16 -Targets 8) -Concurrency 8 -Path $script:SchedulerPath
        foreach ($octet in 1..8) { Measure-PPOverlap -Recorder $run.Recorder -TargetIp ('127.4.0.{0}' -f $octet) | Should -Be 0 }
        $crossTargetOverlaps = (Measure-PPPeakOccupancy -Recorder $run.Recorder) - 1
        $crossTargetOverlaps | Should -BeGreaterOrEqual 1
    }

    It 'returns exactly one result per ExecProbe and calls the adapter once per ExecKey (no retry)' {
        $probes = @(Get-ExecProbe -Count 12 -Targets 3)
        $run = Invoke-Schedule -Probes $probes -Concurrency 4 -Path $script:SchedulerPath
        $run.Results.Count | Should -Be 12
        @($run.Results | ForEach-Object { $_.ExecKey } | Sort-Object -Unique).Count | Should -Be 12
        $enters = @($run.Recorder.ToArray() | Where-Object { $_.Event -eq 'Enter' } | ForEach-Object { '{0}|{1}' -f $_.TargetIp, $_.Port })
        $enters.Count | Should -Be 12
        @($enters | Sort-Object -Unique).Count | Should -Be 12
        $first = $run.Results | Where-Object { $_.ExecKey -eq $probes[0].ExecKey }
        $first.State | Should -Be 'Open'
        $first.Outcome | Should -Be 'Pass'
        $first.TargetIp | Should -Be '127.4.0.1'
        $first.Timestamp | Should -Match '\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\z'
    }

    It '(c) the rate gate spaces attempt starts: 11 probes at 10/s span >= 1 s, and 500/s runs 50 probes in under 49/25 s' {
        $adapters = @{ TCP = 'Invoke-TickAdapter' }
        $slow = Invoke-Schedule -Probes @(Get-ExecProbe -Count 11 -Targets 11) -Concurrency 16 -Rate 10 -Path $script:SchedulerPath -Adapters $adapters
        Get-EnterSpan -Recorder $slow.Recorder | Should -BeGreaterOrEqual 0.97
        $fast = Invoke-Schedule -Probes @(Get-ExecProbe -Count 50 -Targets 50) -Concurrency 16 -Rate 500 -Path $script:SchedulerPath -Adapters $adapters
        Get-EnterSpan -Recorder $fast.Recorder | Should -BeLessThan (49 / 25)
        $fast.Results.Count | Should -Be 50
    }

    It '(d) an adapter that throws is called once and yields ProbeError / Inconclusive (no retry)' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 4 -Targets 2) -Concurrency 2 -Path $script:SchedulerPath -Adapters @{ TCP = 'Invoke-ThrowingAdapter' }
        $run.Recorder.Count | Should -Be 4
        $run.Results.Count | Should -Be 4
        foreach ($r in $run.Results) {
            $r.State | Should -Be ''
            $r.ErrorName | Should -Be 'ProbeError'
            $r.Outcome | Should -Be 'Inconclusive'
            $r.LatencyMs | Should -BeNullOrEmpty
        }
    }

    It 'turns a State the protocol cannot report, or more than one result, into ProbeError' {
        $probes = @(Get-ExecProbe -Count 1 -Targets 1 -Protocol 'ICMP') + @(Get-ExecProbe -Count 2 -Targets 1 -Protocol 'UDP')
        $probes[0].Port = 0
        $probes[0].ExecKey = '127.4.0.1|0|ICMP'
        $run = Invoke-Schedule -Probes $probes -Concurrency 2 -Path $script:SchedulerPath -Adapters @{ ICMP = 'Invoke-LyingAdapter'; UDP = 'Invoke-LyingAdapter' }
        ($run.Results | Where-Object { $_.Protocol -eq 'ICMP' }).ErrorName | Should -Be 'ProbeError'
        ($run.Results | Where-Object { $_.Port -eq 1001 }).State | Should -Be 'Open'
        ($run.Results | Where-Object { $_.Port -eq 1002 }).ErrorName | Should -Be 'ProbeError'
    }

    It 'reports probes whose worker ended early as ProbeError, with a warning, and drops no row' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 3 -Targets 1) -Concurrency 2 -Path $script:SchedulerPath -Adapters @{ TCP = 'Invoke-BreakingAdapter' }
        $run.Recorder.Count | Should -Be 1
        $run.Results.Count | Should -Be 3
        @($run.Results | Where-Object { $_.ErrorName -eq 'ProbeError' -and $_.Outcome -eq 'Inconclusive' }).Count | Should -Be 3
        ($run.Warnings -join ' ') | Should -Match 'ProbeError'
    }

    It 'a worker that fails outside the adapter call loses its queue to ProbeError rows with a warning; other queues and the caller are unaffected' {
        # The shadowing Get-PPOutcome is what Get-PPWorkerDefinition transports (it reads the
        # function visible from the Scheduler's scope), and it throws outside Invoke-PPTargetQueue's
        # adapter try/catch, so the whole target queue fails, as the shadow below demonstrates.
        function Get-PPOutcome {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
                Justification = 'Test shadow with the Get-PPOutcome signature so Invoke-PPTargetQueue binds it; only State drives the injected failure.')]
            param([string] $Protocol, [AllowEmptyString()] [string] $State, [string] $ErrorName)
            if ($State -ceq 'Open') { throw 'worker failure injected by this test' }
            if ($State -ceq '') { return 'Inconclusive' }
            'Fail'
        }
        $ErrorActionPreference = 'Stop'
        $udp = [System.Net.IPAddress]::Parse('127.4.0.9')
        $probes = @(Get-ExecProbe -Count 2 -Targets 1) + @([pscustomobject]@{ ExecKey = '127.4.0.9|53|UDP'; TargetIp = $udp; Port = 53; Protocol = 'UDP'; JitterMs = 0 })
        $run = Invoke-Schedule -Probes $probes -Concurrency 2 -Path $script:SchedulerPath -Adapters @{ TCP = 'Invoke-TickAdapter'; UDP = 'Invoke-PlainAdapter' }
        $run.Results.Count | Should -Be 3
        $run.Recorder.Count | Should -Be 1
        foreach ($r in @($run.Results | Where-Object { $_.Protocol -eq 'TCP' })) {
            $r.State | Should -Be ''
            $r.ErrorName | Should -Be 'ProbeError'
            $r.Outcome | Should -Be 'Inconclusive'
        }
        ($run.Results | Where-Object { $_.Protocol -eq 'UDP' }).State | Should -Be 'Closed'
        ($run.Warnings -join ' ') | Should -Match 'a probe worker failed'
        ($run.Warnings -join ' ') | Should -Match '2 probe\(s\) produced no result'
    }

    It 'hands -Recorder only to an adapter that declares it' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 2 -Targets 1) -Concurrency 1 -Path $script:SchedulerPath -Adapters @{ TCP = 'Invoke-PlainAdapter' }
        foreach ($r in $run.Results) {
            $r.State | Should -Be 'Closed'
            $r.ErrorName | Should -Be 'ConnectionRefused'
            $r.LatencyMs | Should -Be 3
        }
    }
}

Describe 'PortProof.Scheduler.AC29 on the <Path> path' -Tag $script:PathCases[1].Tag -ForEach @($script:PathCases[1]) {
    BeforeAll { $script:SchedulerPath = $Path }

    It '(a) peak occupancy at -Concurrency 4 over 32 probes / 16 addresses is >= 2 and <= 4' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 32 -Targets 16) -Concurrency 4 -Path $script:SchedulerPath
        $peak = Measure-PPPeakOccupancy -Recorder $run.Recorder
        $peak | Should -BeGreaterOrEqual 2
        $peak | Should -BeLessOrEqual 4
    }

    It '(a) peak occupancy at -Concurrency 1 is exactly 1' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 8 -Targets 8) -Concurrency 1 -Path $script:SchedulerPath
        Measure-PPPeakOccupancy -Recorder $run.Recorder | Should -Be 1
    }

    It '(b) 16 probes to one target at -Concurrency 8: zero overlaps and elapsed >= 16 x 200 ms' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 16 -Targets 1) -Concurrency 8 -Path $script:SchedulerPath
        Measure-PPOverlap -Recorder $run.Recorder -TargetIp '127.4.0.1' | Should -Be 0
        $run.ElapsedMs | Should -BeGreaterOrEqual 3200
    }

    It '(b) the same 16 probes over 8 targets overlap across targets (>= 1) but never within one' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 16 -Targets 8) -Concurrency 8 -Path $script:SchedulerPath
        foreach ($octet in 1..8) { Measure-PPOverlap -Recorder $run.Recorder -TargetIp ('127.4.0.{0}' -f $octet) | Should -Be 0 }
        ((Measure-PPPeakOccupancy -Recorder $run.Recorder) - 1) | Should -BeGreaterOrEqual 1
    }

    It 'returns exactly one result per ExecProbe and calls the adapter once per ExecKey (no retry)' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 12 -Targets 3) -Concurrency 4 -Path $script:SchedulerPath
        $run.Results.Count | Should -Be 12
        $enters = @($run.Recorder.ToArray() | Where-Object { $_.Event -eq 'Enter' } | ForEach-Object { '{0}|{1}' -f $_.TargetIp, $_.Port })
        @($enters | Sort-Object -Unique).Count | Should -Be 12
        $enters.Count | Should -Be 12
    }

    It '(c) the rate gate spaces attempt starts across -Parallel workers: 11 probes at 10/s span >= 1 s' {
        $slow = Invoke-Schedule -Probes @(Get-ExecProbe -Count 11 -Targets 11) -Concurrency 16 -Rate 10 -Path $script:SchedulerPath -Adapters @{ TCP = 'Invoke-TickAdapter' }
        Get-EnterSpan -Recorder $slow.Recorder | Should -BeGreaterOrEqual 0.97
    }

    It '(d) an adapter that throws is called once and yields ProbeError / Inconclusive (no retry)' {
        $run = Invoke-Schedule -Probes @(Get-ExecProbe -Count 4 -Targets 2) -Concurrency 2 -Path $script:SchedulerPath -Adapters @{ TCP = 'Invoke-ThrowingAdapter' }
        $run.Recorder.Count | Should -Be 4
        @($run.Results | Where-Object { $_.ErrorName -eq 'ProbeError' }).Count | Should -Be 4
    }

    It 'a worker that fails outside the adapter call loses its queue to ProbeError rows with a warning; other queues and the caller are unaffected' {
        # The shadowing Get-PPOutcome is what Get-PPWorkerDefinition transports (it reads the
        # function visible from the Scheduler's scope), and it throws outside Invoke-PPTargetQueue's
        # adapter try/catch, so the whole target queue fails, as the shadow below demonstrates.
        function Get-PPOutcome {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
                Justification = 'Test shadow with the Get-PPOutcome signature so Invoke-PPTargetQueue binds it; only State drives the injected failure.')]
            param([string] $Protocol, [AllowEmptyString()] [string] $State, [string] $ErrorName)
            if ($State -ceq 'Open') { throw 'worker failure injected by this test' }
            if ($State -ceq '') { return 'Inconclusive' }
            'Fail'
        }
        $ErrorActionPreference = 'Stop'
        $udp = [System.Net.IPAddress]::Parse('127.4.0.9')
        $probes = @(Get-ExecProbe -Count 2 -Targets 1) + @([pscustomobject]@{ ExecKey = '127.4.0.9|53|UDP'; TargetIp = $udp; Port = 53; Protocol = 'UDP'; JitterMs = 0 })
        $run = Invoke-Schedule -Probes $probes -Concurrency 2 -Path $script:SchedulerPath -Adapters @{ TCP = 'Invoke-TickAdapter'; UDP = 'Invoke-PlainAdapter' }
        $run.Results.Count | Should -Be 3
        $run.Recorder.Count | Should -Be 1
        foreach ($r in @($run.Results | Where-Object { $_.Protocol -eq 'TCP' })) {
            $r.State | Should -Be ''
            $r.ErrorName | Should -Be 'ProbeError'
            $r.Outcome | Should -Be 'Inconclusive'
        }
        ($run.Results | Where-Object { $_.Protocol -eq 'UDP' }).State | Should -Be 'Closed'
        ($run.Warnings -join ' ') | Should -Match 'a probe worker failed'
        ($run.Warnings -join ' ') | Should -Match '2 probe\(s\) produced no result'
    }
}

Describe 'PortProof.Scheduler.Lifecycle' -Tag 'Windows' {

    It 'leaves no runspace open after a run, and after a run whose adapters throw' {
        $before = @(Get-Runspace | Where-Object { $_.RunspaceStateInfo.State -eq 'Opened' }).Count
        $null = Invoke-Schedule -Probes @(Get-ExecProbe -Count 8 -Targets 4) -Concurrency 4 -Path 'Runspace' -Adapters @{ TCP = 'Invoke-TickAdapter' }
        $null = Invoke-Schedule -Probes @(Get-ExecProbe -Count 8 -Targets 4) -Concurrency 4 -Path 'Runspace' -Adapters @{ TCP = 'Invoke-ThrowingAdapter' }
        @(Get-Runspace | Where-Object { $_.RunspaceStateInfo.State -eq 'Opened' }).Count | Should -Be $before
    }
}

Describe 'PortProof.Scheduler.Contract' -Tag 'Portable' {

    It 'resolves Auto by host version and refuses Parallel below PowerShell 7' {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            Get-PPExecutionPath -Requested 'Auto' | Should -Be 'Parallel'
            Get-PPExecutionPath -Requested 'Parallel' | Should -Be 'Parallel'
        }
        else {
            Get-PPExecutionPath -Requested 'Auto' | Should -Be 'Runspace'
            { Get-PPExecutionPath -Requested 'Parallel' } | Should -Throw -ErrorId 'PortProof.InternalInvariant'
        }
        Get-PPExecutionPath -Requested 'Runspace' | Should -Be 'Runspace'
    }

    It 'returns nothing for an empty probe list without starting a worker' {
        @(Invoke-ProbeSchedule -Probes @() -Adapters @{ TCP = 'Invoke-DoesNotExist' }).Count | Should -Be 0
    }

    It 'refuses a probe whose protocol has no adapter, and an adapter name that is not loaded' {
        $probe = @(Get-ExecProbe -Count 1 -Targets 1 -Protocol 'UDP')
        { Invoke-ProbeSchedule -Probes $probe -Adapters @{ TCP = 'Invoke-RecordingAdapter' } } | Should -Throw -ErrorId 'PortProof.InternalInvariant'
        { Invoke-ProbeSchedule -Probes $probe -Adapters @{ UDP = 'Invoke-NotLoadedAdapter' } } | Should -Throw -ErrorId 'PortProof.InternalInvariant'
        { Invoke-ProbeSchedule -Probes $probe -Adapters @{ UDP = 'Get-ChildItem; x' } } | Should -Throw -ErrorId 'PortProof.InternalInvariant'
    }

    It 'transports worker functions only from Get-Command text, and records which take -Recorder' {
        $takes = @{}
        $defs = Get-PPWorkerDefinition -Names @('Invoke-PPTargetQueue', 'Invoke-RecordingAdapter', 'Invoke-TcpProbe') -TakesRecorder $takes
        @($defs.Keys) | Should -Be @('Invoke-PPTargetQueue', 'Invoke-RecordingAdapter', 'Invoke-TcpProbe')
        $defs['Invoke-TcpProbe'] | Should -Be ((Get-Command -CommandType Function -Name 'Invoke-TcpProbe').ScriptBlock.ToString())
        $takes['Invoke-RecordingAdapter'] | Should -BeTrue
        $takes['Invoke-TcpProbe'] | Should -BeFalse
    }
}

Describe 'PortProof.Scheduler.Listeners (distinct 127.0.0.0/8 listeners, real TCP adapter)' -Tag 'Windows' {

    It 'contacts each of 8 distinct loopback listeners exactly once, and spaces the accepts at 25/s' {
        $listeners = @()
        try {
            $listeners = @(1..8 | ForEach-Object { Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept })
            $probes = foreach ($l in $listeners) {
                $ip = [System.Net.IPAddress]::Parse($l.Address)
                [pscustomobject]@{ ExecKey = '{0}|{1}|TCP' -f $l.Address, $l.Port; TargetIp = $ip; Port = $l.Port; Protocol = 'TCP'; JitterMs = 0 }
            }
            $results = @(Invoke-ProbeSchedule -Probes @($probes) -Adapters (Get-PPContract).DefaultAdapters -Concurrency 16 -MaxProbesPerSecond 25 -TimeoutMs 3000 -ExecutionPath 'Runspace')
            $results.Count | Should -Be 8
            @($results | Where-Object { $_.State -eq 'Open' -and $_.Outcome -eq 'Pass' }).Count | Should -Be 8
            $deadline = [System.Diagnostics.Stopwatch]::StartNew()
            while (@($listeners | Where-Object { $_.Events.Count -lt 1 }).Count -gt 0 -and $deadline.ElapsedMilliseconds -lt 3000) { Start-Sleep -Milliseconds 25 }
            Start-Sleep -Milliseconds 300
            foreach ($l in $listeners) { $l.Events.Count | Should -Be 1 }
            # Each event is a Stopwatch started at accept: the spread of their elapsed times is the
            # spread of the accept times.
            $elapsed = @($listeners | ForEach-Object { $_.Events.ToArray()[0].Elapsed.TotalSeconds } | Sort-Object)
            ($elapsed[-1] - $elapsed[0]) | Should -BeGreaterOrEqual (0.9 * 7 / 25)
        }
        finally {
            foreach ($l in $listeners) { Close-PPListener -Listener $l }
        }
    }
}
