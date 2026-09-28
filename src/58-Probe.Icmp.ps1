# PortProof ICMP adapter. Function definitions only.

function Invoke-IcmpProbe {
    # One zero-length ICMP echo through System.Net.NetworkInformation.Ping (no raw socket, no
    # administrator rights, no payload). Never throws. Worker set: calls no other function.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Port',
        Justification = 'Port is part of the one adapter signature the Scheduler calls for every protocol; an ICMP echo has no port, so the value (always 0) is accepted and not used.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [int] $Port = 0,
        [Parameter(Mandatory)] [int] $TimeoutMs
    )

    $state = ''
    $errorName = 'ProbeError'
    $ping = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send($Address, $TimeoutMs, [byte[]]::new(0))
        $stopwatch.Stop()
        $status = $reply.Status
        if ($status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $state = 'Reply'; $errorName = 'None' }
        elseif ($status -eq [System.Net.NetworkInformation.IPStatus]::TimedOut) { $state = 'NoReply'; $errorName = 'Timeout' }
        elseif ($status -eq [System.Net.NetworkInformation.IPStatus]::DestinationHostUnreachable -or
            $status -eq [System.Net.NetworkInformation.IPStatus]::DestinationNetworkUnreachable) { $state = 'NoReply'; $errorName = 'HostUnreachable' }
        else { $state = ''; $errorName = 'ProbeError' }
    }
    catch {
        $state = ''
        $errorName = 'ProbeError'
    }
    finally {
        $stopwatch.Stop()
        if ($null -ne $ping) {
            try { $ping.Dispose() } catch { $null = $_ }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.AdapterResult'
        State      = $state
        ErrorName  = $errorName
        LatencyMs  = [int][Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
    }
}
