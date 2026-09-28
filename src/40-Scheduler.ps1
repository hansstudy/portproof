# PortProof scheduler. Function definitions only.
#
# Per-target serial queues are the per-target lock: probes are grouped by canonical TargetIp and
# one queue runs strictly in order inside one worker, so two probes to one address never overlap
# on either execution path. Concurrency is the number of queues in flight. One rate gate is shared
# by reference across all workers. Adapters are taken by function NAME and called exactly once per
# probe; there is no retry anywhere.
#
# Worker set (transported into worker runspaces, closed under calls - Test-WorkerClosure.ps1):
# Invoke-PPTargetQueue, Wait-PPRateSlot, Get-PPOutcome (05-Contract.ps1) and the adapters named in
# -Adapters. These call only each other, .NET and Start-Sleep. Function text reaches a worker only
# through Get-PPWorkerDefinition: SessionStateFunctionEntry on the 5.1
# runspace-pool path, one function-drive Set-Item inside the -Parallel block on the 7.x path.

function Get-PPExecutionPath {
    # 'Auto' -> 'Parallel' on PowerShell 7 or later, else 'Runspace'. 'Parallel' below 7 is refused.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Requested)

    $major = [int]$PSVersionTable.PSVersion.Major
    if ($Requested -ceq 'Auto') {
        if ($major -ge 7) { return 'Parallel' }
        return 'Runspace'
    }
    if ($Requested -ceq 'Runspace') { return 'Runspace' }
    if ($Requested -ceq 'Parallel') {
        if ($major -lt 7) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message 'internal error: the Parallel execution path needs PowerShell 7 or later.'
        }
        return 'Parallel'
    }
    Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: unknown execution path '{0}'." -f (Get-PPSafeText -Text $Requested))
}

function Get-PPWorkerDefinition {
    # The one reader of function text for transport: an [ordered] name -> source text
    # map, read only through Get-Command -CommandType Function for names from the fixed worker set
    # and the -Adapters map. Also records, per name, whether the function declares -Recorder, so that
    # decision is made here on the calling thread and travels to the worker as a boolean.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]] $Names,
        [Parameter(Mandatory)] [hashtable] $TakesRecorder
    )

    $definitions = [ordered]@{}
    foreach ($n in $Names) {
        if ($definitions.Contains($n)) { continue }
        if ($n -cnotmatch '\A[A-Za-z][A-Za-z0-9]*-[A-Za-z][A-Za-z0-9]*\z') {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: '{0}' is not a function name." -f (Get-PPSafeText -Text $n))
        }
        $found = @(Get-Command -CommandType Function -Name $n -ErrorAction SilentlyContinue)
        if ($found.Count -ne 1) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: worker function '{0}' is not loaded." -f (Get-PPSafeText -Text $n))
        }
        $definitions[$n] = $found[0].ScriptBlock.ToString()
        $TakesRecorder[$n] = [bool]$found[0].Parameters.ContainsKey('Recorder')
    }
    $definitions
}

function Invoke-ProbeSchedule {
    # -> ProbeResult[], exactly one per ExecProbe (returned in input order). Called
    # only from Invoke-PPGate (AC30). Disposes every worker in finally, Ctrl+C included.
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Probes,
        [Parameter(Mandatory)] [hashtable] $Adapters,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder,
        [ValidateRange(1, 64)] [int] $Concurrency = 16,
        [ValidateRange(1, 500)] [int] $MaxProbesPerSecond = 50,
        [ValidateRange(100, 30000)] [int] $TimeoutMs = 2000,
        [ValidateSet('Auto', 'Runspace', 'Parallel')] [string] $ExecutionPath = 'Auto'
    )

    $work = @($Probes | Where-Object { $null -ne $_ })
    if ($work.Count -eq 0) { return }
    $path = Get-PPExecutionPath -Requested $ExecutionPath

    # Adapter names: one per protocol in use, all from -Adapters.
    $adapterNames = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $Adapters.Keys) {
        $value = [string]$Adapters[$key]
        if (-not $adapterNames.Contains($value)) { $adapterNames.Add($value) }
    }
    foreach ($probe in $work) {
        $protocol = [string]$probe.Protocol
        if (-not $Adapters.ContainsKey($protocol) -or [string]::IsNullOrEmpty([string]$Adapters[$protocol])) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: no adapter for protocol '{0}'." -f (Get-PPSafeText -Text $protocol))
        }
    }
    $takesRecorder = @{}
    $names = [string[]](@('Invoke-PPTargetQueue', 'Wait-PPRateSlot', 'Get-PPOutcome') + $adapterNames.ToArray())
    $defs = Get-PPWorkerDefinition -Names $names -TakesRecorder $takesRecorder

    # The rate gate, shared by reference by every worker.
    $rate = [hashtable]::Synchronized(@{
            NextTicks     = [long]0
            IntervalTicks = [long]([System.Diagnostics.Stopwatch]::Frequency / $MaxProbesPerSecond)
        })

    # Per-target queues: groups in first-appearance order of canonical TargetIp, probes in input order.
    $queueByIp = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $queueOrder = [System.Collections.Generic.List[string]]::new()
    foreach ($probe in $work) {
        $ipText = $probe.TargetIp.ToString()
        if (-not $queueByIp.ContainsKey($ipText)) {
            $queueByIp[$ipText] = [System.Collections.Generic.List[object]]::new()
            $queueOrder.Add($ipText)
        }
        $adapterName = [string]$Adapters[[string]$probe.Protocol]
        $queueByIp[$ipText].Add([pscustomobject][ordered]@{
                ExecKey      = [string]$probe.ExecKey
                TargetIp     = $probe.TargetIp
                Port         = [int]$probe.Port
                Protocol     = [string]$probe.Protocol
                JitterMs     = [int]$probe.JitterMs
                AdapterName  = $adapterName
                PassRecorder = ([bool]$takesRecorder[$adapterName] -and $null -ne $Recorder)
            })
    }
    $workItems = [System.Collections.Generic.List[object]]::new()
    foreach ($ipText in $queueOrder) {
        $workItems.Add([pscustomobject][ordered]@{
                Queue     = $queueByIp[$ipText].ToArray()
                Rate      = $rate
                Recorder  = $Recorder
                TimeoutMs = $TimeoutMs
            })
    }

    $collected = [System.Collections.Generic.List[object]]::new()
    if ($path -ceq 'Parallel') {
        # 7.x path. NOT-VERIFIED on this host (no pwsh): runs in the PS7 test group in CI. The work
        # item carries the shared rate gate and Recorder by reference; the only $using: value is the
        # worker definitions from Get-PPWorkerDefinition.
        # Failure handling mirrors the 5.1 path exactly: a queue's output is kept only when the whole
        # queue completed (EndInvoke throws and yields nothing when a 5.1 worker fails); a failed
        # queue comes back as one PortProof.WorkerFailure marker, which becomes the same warning
        # here, and its probes become ProbeError rows in the fill step below. No retry. The worker's
        # error stream is discarded, as the 5.1 path never reads PowerShell.Streams.Error, so no
        # error record can reach a caller running with ErrorActionPreference 'Stop'.
        $parallelOut = $workItems | ForEach-Object -Parallel {
            try {
                $workerDefs = $using:defs
                foreach ($d in $workerDefs.GetEnumerator()) { Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value }
                $queueOut = @(Invoke-PPTargetQueue -Queue $_.Queue -Rate $_.Rate -Recorder $_.Recorder -TimeoutMs $_.TimeoutMs 2>$null)
                $queueOut
            }
            catch {
                [pscustomobject]@{ PSTypeName = 'PortProof.WorkerFailure'; Message = [string]$_.Exception.Message }
            }
        } -ThrottleLimit $Concurrency
        foreach ($o in @($parallelOut)) {
            if ($null -eq $o) { continue }
            if ($o.PSObject.TypeNames[0] -ceq 'PortProof.WorkerFailure') {
                Write-Warning -Message ('PortProof: a probe worker failed: {0}' -f (Get-PPSafeText -Text ([string]$o.Message)))
                continue
            }
            $collected.Add($o)
        }
    }
    else {
        # 5.1 path: one runspace pool of $Concurrency, one [PowerShell] per queue.
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
        foreach ($d in $defs.GetEnumerator()) {
            $iss.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($d.Key, $d.Value))
        }
        $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Concurrency, $iss, $Host)
        $jobs = [System.Collections.Generic.List[object]]::new()
        try {
            $pool.Open()
            foreach ($item in $workItems) {
                $ps = [System.Management.Automation.PowerShell]::Create()
                $jobs.Add([pscustomobject]@{ PowerShell = $ps; Handle = $null })
                $ps.RunspacePool = $pool
                [void]$ps.AddCommand('Invoke-PPTargetQueue').AddParameter('Queue', $item.Queue).AddParameter('Rate', $item.Rate).AddParameter('Recorder', $item.Recorder).AddParameter('TimeoutMs', $item.TimeoutMs)
                $jobs[$jobs.Count - 1].Handle = $ps.BeginInvoke()
            }
            foreach ($job in $jobs) {
                # A bounded wait in a loop, so Ctrl+C is honoured between waits and reaches finally.
                while (-not $job.Handle.AsyncWaitHandle.WaitOne(100)) { continue }
                try {
                    foreach ($o in $job.PowerShell.EndInvoke($job.Handle)) { if ($null -ne $o) { $collected.Add($o) } }
                }
                catch {
                    Write-Warning -Message ('PortProof: a probe worker failed: {0}' -f (Get-PPSafeText -Text $_.Exception.Message))
                }
            }
        }
        finally {
            foreach ($job in $jobs) { $job.PowerShell.Dispose() }
            try { $pool.Close() } catch { $null = $_ }   # a pool that never opened has nothing to close
            $pool.Dispose()
        }
    }

    # Exactly one result per ExecProbe: a queue whose worker failed yields ProbeError rows, never
    # missing rows; a result for a key nobody asked for, or a second result for a key, is dropped.
    $byKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($r in $collected) {
        $k = [string]$r.ExecKey
        if (-not $byKey.ContainsKey($k)) { $byKey[$k] = $r }
    }
    $missing = 0
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($probe in $work) {
        $k = [string]$probe.ExecKey
        if ($byKey.ContainsKey($k)) {
            $results.Add($byKey[$k])
            continue
        }
        $missing++
        $results.Add([pscustomobject][ordered]@{
                PSTypeName = 'PortProof.ProbeResult'
                ExecKey    = $k
                TargetIp   = $probe.TargetIp.ToString()
                Port       = [int]$probe.Port
                Protocol   = [string]$probe.Protocol
                State      = ''
                ErrorName  = 'ProbeError'
                Outcome    = Get-PPOutcome -Protocol ([string]$probe.Protocol) -State '' -ErrorName 'ProbeError'
                LatencyMs  = $null
                Timestamp  = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)
            })
    }
    if ($missing -gt 0) {
        Write-Warning -Message ('PortProof: {0} probe(s) produced no result from their worker and are reported as ProbeError.' -f
            $missing.ToString([cultureinfo]::InvariantCulture))
    }
    $results.ToArray()
}

function Invoke-PPTargetQueue {
    # Worker set. Runs one target's probes strictly in order: sleep JitterMs, take a rate slot,
    # stamp the time, call the adapter exactly once, classify via Get-PPOutcome. No retry. The one
    # dynamic call in the worker set is the adapter dispatch on $AdapterName; its value is always a
    # name the caller took from the -Adapters map.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Queue,
        [Parameter(Mandatory)] [hashtable] $Rate,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder,
        [Parameter(Mandatory)] [int] $TimeoutMs,
        [string] $AdapterName = ''
    )

    foreach ($item in $Queue) {
        if ([int]$item.JitterMs -gt 0) { Start-Sleep -Milliseconds ([int]$item.JitterMs) }
        Wait-PPRateSlot -Rate $Rate
        $stamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)

        $protocol = [string]$item.Protocol
        $AdapterName = [string]$item.AdapterName
        $callArgs = @{ Address = $item.TargetIp; Port = [int]$item.Port; TimeoutMs = $TimeoutMs }
        if ([bool]$item.PassRecorder) { $callArgs['Recorder'] = $Recorder }

        $state = ''
        $errorName = 'ProbeError'
        $latency = $null
        try {
            $returned = @(& $AdapterName @callArgs)
            if ($returned.Count -eq 1 -and $null -ne $returned[0]) {
                $state = [string]$returned[0].State
                $errorName = [string]$returned[0].ErrorName
                if ($null -ne $returned[0].LatencyMs) { $latency = [int]$returned[0].LatencyMs }
            }
        }
        catch {
            $state = ''
            $errorName = 'ProbeError'
            $latency = $null
        }

        # The adapter's State must be one its protocol can report (DESIGN 3.8.3); anything else is
        # a ProbeError, never a guess (a stray 'Open' on UDP silence would be a lie, AC7).
        $known = $false
        if ($state -ceq '' -or $errorName -ceq 'ProbeError') { $known = $true }
        elseif ($protocol -ceq 'TCP') { $known = ($state -ceq 'Open' -or $state -ceq 'Closed' -or $state -ceq 'Unreachable') }
        elseif ($protocol -ceq 'UDP') { $known = ($state -ceq 'Open' -or $state -ceq 'Closed' -or $state -ceq 'Open|Filtered') }
        elseif ($protocol -ceq 'ICMP') { $known = ($state -ceq 'Reply' -or $state -ceq 'NoReply') }
        if (-not $known -or [string]::IsNullOrEmpty($errorName)) {
            $state = ''
            $errorName = 'ProbeError'
        }
        if ($errorName -ceq 'ProbeError') { $state = '' }

        [pscustomobject][ordered]@{
            PSTypeName = 'PortProof.ProbeResult'
            ExecKey    = [string]$item.ExecKey
            TargetIp   = $item.TargetIp.ToString()
            Port       = [int]$item.Port
            Protocol   = $protocol
            State      = $state
            ErrorName  = $errorName
            Outcome    = Get-PPOutcome -Protocol $protocol -State $state -ErrorName $errorName
            LatencyMs  = $latency
            Timestamp  = $stamp
        }
    }
}

function Wait-PPRateSlot {
    # Worker set. Process-wide token bucket of one: take the next slot under the gate's lock
    # (slot = max(now, NextTicks); NextTicks = slot + IntervalTicks), then sleep until the slot, so
    # attempt starts are at least 1/R apart across every worker (AC29 c).
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Rate)

    $slot = [long]0
    $syncRoot = $Rate.SyncRoot
    [System.Threading.Monitor]::Enter($syncRoot)
    try {
        $now = [System.Diagnostics.Stopwatch]::GetTimestamp()
        $next = [long]$Rate['NextTicks']
        $slot = $next
        if ($now -gt $next) { $slot = $now }
        $Rate['NextTicks'] = $slot + [long]$Rate['IntervalTicks']
    }
    finally {
        [System.Threading.Monitor]::Exit($syncRoot)
    }

    $frequency = [double][System.Diagnostics.Stopwatch]::Frequency
    while ($true) {
        $remaining = $slot - [System.Diagnostics.Stopwatch]::GetTimestamp()
        if ($remaining -le 0) { break }
        $ms = [int][Math]::Ceiling(($remaining * 1000.0) / $frequency)
        if ($ms -lt 1) { $ms = 1 }
        Start-Sleep -Milliseconds $ms
    }
}
