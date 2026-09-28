# PortProof Gate: the sole admission point between resolution and the first socket,
# and the only caller of Invoke-ProbeSchedule in src/ (AC30). Function definitions only.

function Invoke-PPGate {
    # Order, all before any socket: (1) invariant and effective cap, (2) class check on every
    # resolved address and on every ExecProbe.TargetIp, (3) ICMP echoes, (4) the one authoritative
    # cap, (5) jitter, (6) OnAdmitted, then the Scheduler. Throws only PortProof.InternalInvariant,
    # PortProof.RefusedTargetClass and PortProof.CapExceeded.Admitted.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $Resolution,
        [Parameter(Mandatory)] [int] $Cap,
        [switch] $Icmp,
        [Parameter(Mandatory)] [hashtable] $Schedule,
        [Parameter(Mandatory)] [hashtable] $Adapters,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder,
        [scriptblock] $OnAdmitted
    )

    $inv = [cultureinfo]::InvariantCulture

    # 1. Invariant. The counts the resolver reports must match what it built, and resolution must
    #    never have grown the list. The effective cap can never exceed the absolute ceiling.
    $execProbes = @($Resolution.ExecProbes | Where-Object { $null -ne $_ })
    $countBefore = [int]$Resolution.CountBefore
    $countAfter = [int]$Resolution.CountAfter
    if ($countAfter -ne $execProbes.Count -or $countAfter -gt $countBefore) {
        Invoke-PPRefusal -Code 'InternalInvariant' -Message ('internal error: resolution count invariant violated (before {0}, after {1}, built {2}).' -f
            $countBefore.ToString($inv), $countAfter.ToString($inv), $execProbes.Count.ToString($inv))
    }
    $effectiveCap = [Math]::Min($Cap, [int](Get-PPContract).AbsoluteProbeCeiling)

    # 2. Class check, twice over, with one predicate call per distinct address text (the verdict is
    #    cached), so the cost stays linear in distinct addresses at the 8192 ceiling.
    #    (a) Every address every non-failed entry resolved to, in a deterministic order:
    #    lowest profile row first, then ProbeKey.
    $verdicts = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $entries = $Resolution.Entries
    if ($null -eq $entries) { $entries = @{} }
    $pending = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $entries.Keys) {
        $entry = $entries[$k]
        if ($null -eq $entry -or [bool]$entry.Failed) { continue }
        $first = 0
        foreach ($r in @($entry.Rows)) {
            if ($null -eq $r) { continue }
            $n = [int]$r
            if ($first -eq 0 -or $n -lt $first) { $first = $n }
        }
        $pending.Add([pscustomobject]@{ Row = $first; Key = [string]$k; Entry = $entry })
    }
    $firstByIp = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($item in @($pending | Sort-Object -Property Row, Key -CaseSensitive)) {
        $name = [string]$item.Entry.TargetName
        $candidates = [System.Collections.Generic.List[object]]::new()
        foreach ($text in @($item.Entry.ResolvedAddresses)) {
            $parsed = $null
            if (-not [System.Net.IPAddress]::TryParse([string]$text, [ref]$parsed)) {
                Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: resolved address '{0}' for '{1}' does not parse." -f
                    (Get-PPSafeText -Text ([string]$text)), (Get-PPSafeText -Text $name))
            }
            $candidates.Add($parsed)
        }
        if ($item.Entry.TargetIp -is [System.Net.IPAddress]) { $candidates.Add($item.Entry.TargetIp) }
        foreach ($address in $candidates) {
            $verdict = $null
            if (-not $verdicts.TryGetValue($address.ToString(), [ref]$verdict)) {
                $verdict = Test-RefusedTargetClass -Address $address
                $verdicts[$address.ToString()] = $verdict
            }
            if ($verdict.Refused) { Invoke-PPClassRefusal -Address $address -Verdict $verdict -Row $item.Row -Name $name }
            $canonicalText = $verdict.Canonical.ToString()
            if (-not $firstByIp.ContainsKey($canonicalText)) { $firstByIp[$canonicalText] = @($item.Row, $name) }
        }
    }

    #    (b) Every ExecProbe about to be scheduled, whatever Entries says (the check does not depend
    #    on how Entries was built). Shape checks fail closed as an internal error. The admitted
    #    list carries the canonical address the predicate judged.
    $admitted = [System.Collections.Generic.List[object]]::new()
    foreach ($probe in $execProbes) {
        if ($probe.TargetIp -isnot [System.Net.IPAddress]) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: ExecProbe '{0}' carries no address." -f (Get-PPSafeText -Text ([string]$probe.ExecKey)))
        }
        $protocol = [string]$probe.Protocol
        $port = [int]$probe.Port
        if (($protocol -cne 'TCP' -and $protocol -cne 'UDP') -or $port -lt 1 -or $port -gt 65535) {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: ExecProbe '{0}' is not a TCP/UDP probe to port 1..65535." -f (Get-PPSafeText -Text ([string]$probe.ExecKey)))
        }
        $verdict = $null
        if (-not $verdicts.TryGetValue($probe.TargetIp.ToString(), [ref]$verdict)) {
            $verdict = Test-RefusedTargetClass -Address $probe.TargetIp
            $verdicts[$probe.TargetIp.ToString()] = $verdict
        }
        if ($verdict.Refused) {
            $ipText = $verdict.Canonical.ToString()
            $row = 0
            $name = $ipText
            if ($firstByIp.ContainsKey($ipText)) {
                $row = [int]$firstByIp[$ipText][0]
                $name = [string]$firstByIp[$ipText][1]
            }
            Invoke-PPClassRefusal -Address $probe.TargetIp -Verdict $verdict -Row $row -Name $name
        }
        $admitted.Add([pscustomobject][ordered]@{
                PSTypeName = 'PortProof.ExecProbe'
                ExecKey    = [string]$probe.ExecKey
                TargetIp   = $verdict.Canonical
                Port       = $port
                Protocol   = $protocol
                JitterMs   = 0
            })
    }

    # 3. ICMP: one echo per distinct TargetIp, appended after the TCP/UDP probes.
    $icmpCount = 0
    if ($Icmp) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($probe in @($admitted.ToArray())) {
            $ipText = $probe.TargetIp.ToString()
            if (-not $seen.Add($ipText)) { continue }
            $admitted.Add([pscustomobject][ordered]@{
                    PSTypeName = 'PortProof.ExecProbe'
                    ExecKey    = $ipText + '|0|ICMP'
                    TargetIp   = $probe.TargetIp
                    Port       = 0
                    Protocol   = 'ICMP'
                    JitterMs   = 0
                })
            $icmpCount++
        }
    }

    # 4. The one authoritative cap, over resolved probes with ICMP included.
    $total = $admitted.Count
    if ($total -gt $effectiveCap) {
        Invoke-PPRefusal -Code 'CapExceeded.Admitted' -Message ('{0} admitted probes exceed the cap of {1}; nothing was sent' -f
            $total.ToString($inv), $effectiveCap.ToString($inv))
    }

    # 5. Jitter, precomputed on this thread from one generator (no identical seeds across workers).
    $jitter = [int]$Schedule['JitterMs']
    if ($jitter -gt 0) {
        $random = [System.Random]::new()
        foreach ($probe in $admitted) { $probe.JitterMs = $random.Next(0, $jitter + 1) }
    }

    # 6. Admission is final: tell the caller, then schedule. The admitted list is frozen into an
    #    array first: the callback runs in a child scope of this function, so it can see this
    #    function's variables by name, and nothing it does may change what is scheduled. Its output
    #    is discarded.
    $requested = [string]$Schedule['ExecutionPath']
    if ([string]::IsNullOrEmpty($requested)) { $requested = 'Auto' }
    $executionPath = Get-PPExecutionPath -Requested $requested
    $scheduled = $admitted.ToArray()
    if ($null -ne $OnAdmitted) { $null = & $OnAdmitted $total }
    if ($scheduled.Count -ne $total) {
        Invoke-PPRefusal -Code 'InternalInvariant' -Message 'internal error: the admitted probe list changed during admission.'
    }

    $scheduleArgs = @{
        Probes        = $scheduled
        Adapters      = $Adapters
        Recorder      = $Recorder
        ExecutionPath = $executionPath
    }
    foreach ($name in @('Concurrency', 'MaxProbesPerSecond', 'TimeoutMs')) {
        if ($Schedule.ContainsKey($name) -and $null -ne $Schedule[$name]) { $scheduleArgs[$name] = [int]$Schedule[$name] }
    }
    $results = @(Invoke-ProbeSchedule @scheduleArgs)
    if ($total -eq 0) { $executionPath = 'None' }

    [pscustomobject][ordered]@{
        PSTypeName    = 'PortProof.GateResult'
        Results       = $results
        AdmittedCount = $total
        IcmpCount     = $icmpCount
        ExecutionPath = $executionPath
    }
}

function Invoke-PPClassRefusal {
    # Throws PortProof.RefusedTargetClass naming the row, the name as written, the address and the
    # class label.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [pscustomobject] $Verdict,
        [int] $Row,
        [AllowEmptyString()] [string] $Name
    )

    $message = "row {0} target '{1}' resolves to {2}: {3}; PortProof refuses this address class" -f
        $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $Name), $Address.ToString(), $Verdict.ClassLabel
    Invoke-PPRefusal -Code 'RefusedTargetClass' -Message $message -Row $Row -Detail @{
        Name = $Name; Address = $Address.ToString(); Class = [string]$Verdict.Class
    }
}
