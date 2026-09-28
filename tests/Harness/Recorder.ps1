# PortProof test harness - the thread-safe Recorder and the recording adapter (AC29).
#
# Two loopback-observable assertions the scheduler design needs (concurrency peak, per-target
# serialisation) cannot be seen from a listener alone: a loopback handshake completes in the
# kernel before Accept, and the tool closes on connect, so a listener-observed peak is always 1-2
# regardless of what the scheduler does. Invoke-RecordingAdapter is injected in place of the real
# adapters (Contract signature Invoke-ProbeSchedule -Adapters -Recorder) so the peak and any
# overlap become directly observable.

function Initialize-PPRecorder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseCmdletCorrectly', '',
        Justification = 'PSScriptAnalyzer 1.25.0 misreads Write-Output -NoEnumerate $queue as a
        missing mandatory InputObject; the analyzer does not resolve the positional binding past a
        preceding switch parameter here. The call is correct: Write-Output has one mandatory
        parameter, InputObject, and $queue satisfies it positionally, verified by direct testing.')]
    [CmdletBinding()]
    [OutputType([System.Collections.Concurrent.ConcurrentQueue[object]])]
    param()
    # -NoEnumerate: an empty (or later non-empty) ConcurrentQueue is IEnumerable, and PowerShell's
    # default pipeline behaviour unrolls it into its elements (zero of them here), which collapses
    # the return value to $null. The queue itself, not its contents, is the return value.
    $queue = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    Write-Output -NoEnumerate $queue
}

function Invoke-RecordingAdapter {
    <#
        Self-contained: runs inside worker runspaces (5.1 runspace pool and 7.x -Parallel alike),
        so it touches only .NET primitives and Start-Sleep, never Get-PPContract or any other tool
        function. Enqueues an Enter record, sleeps 200 ms, enqueues an Exit record, and returns a
        successful AdapterResult - it never actually opens a socket.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'TimeoutMs',
        Justification = 'Part of the fixed adapter contract shared
        with Invoke-TcpProbe, Invoke-UdpProbe and Invoke-IcmpProbe, which the Scheduler calls by
        name; this recording adapter always sleeps a fixed 200 ms rather than actually timing out,
        but must still accept the parameter so it can be substituted for a real adapter without
        changing the call site.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [int] $TimeoutMs,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
    )

    $targetIp = $Address.ToString()
    $threadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId

    if ($Recorder) {
        $Recorder.Enqueue([pscustomobject]@{
            TargetIp = $targetIp
            Port     = $Port
            Event    = 'Enter'
            Ticks    = [System.Diagnostics.Stopwatch]::GetTimestamp()
            ThreadId = $threadId
        })
    }

    Start-Sleep -Milliseconds 200

    if ($Recorder) {
        $Recorder.Enqueue([pscustomobject]@{
            TargetIp = $targetIp
            Port     = $Port
            Event    = 'Exit'
            Ticks    = [System.Diagnostics.Stopwatch]::GetTimestamp()
            ThreadId = $threadId
        })
    }

    [pscustomobject]@{
        PSTypeName = 'PortProof.AdapterResult'
        State      = 'Open'
        ErrorName  = 'None'
        LatencyMs  = 200
    }
}

function Measure-PPPeakOccupancy {
    <#
        The largest number of Enter events outstanding (without a matching Exit) at any point in
        the recorded sequence, ordered by Ticks.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder)

    $events = $Recorder.ToArray() | Sort-Object Ticks
    $current = 0
    $peak = 0
    foreach ($e in $events) {
        if ($e.Event -eq 'Enter') {
            $current++
            if ($current -gt $peak) { $peak = $current }
        } else {
            $current--
        }
    }
    $peak
}

function Measure-PPOverlap {
    <#
        The count of Enter events for -TargetIp that occurred while another interval for the same
        target was already open. Zero means every probe to that target ran strictly one at a time.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder,
        [Parameter(Mandatory)] [string] $TargetIp
    )

    $events = $Recorder.ToArray() | Where-Object { $_.TargetIp -eq $TargetIp } | Sort-Object Ticks
    $current = 0
    $overlaps = 0
    foreach ($e in $events) {
        if ($e.Event -eq 'Enter') {
            if ($current -gt 0) { $overlaps++ }
            $current++
        } else {
            $current--
        }
    }
    $overlaps
}
