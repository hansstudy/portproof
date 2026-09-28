# PortProof UDP adapter. The only file in src/ allowed to receive (AC16).
# Function definitions only.

function Invoke-UdpProbe {
    # One zero-length datagram on a connected UdpClient, then one receive bounded by ReceiveTimeout.
    # Connecting is what makes Windows surface an ICMP port-unreachable as SocketError
    # ConnectionReset on the receive. A received datagram is discarded unread: neither its contents
    # nor its length is kept. Silence is Open|Filtered, never Open (AC7). No local bind. Never
    # throws. Worker set: calls no other function.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [int] $TimeoutMs
    )

    $state = ''
    $errorName = 'ProbeError'
    $udp = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $wait = $TimeoutMs
        if ($wait -lt 1) { $wait = 1 }   # 0 would mean "wait forever"
        $any = [System.Net.IPAddress]::Any
        if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { $any = [System.Net.IPAddress]::IPv6Any }

        $udp = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
        $udp.Client.ReceiveTimeout = $wait
        $udp.Connect([System.Net.IPEndPoint]::new($Address, $Port))
        [void]$udp.Send([byte[]]::new(0), 0)
        $remote = [System.Net.IPEndPoint]::new($any, 0)
        try {
            [void]$udp.Receive([ref]$remote)
            $stopwatch.Stop()
            $state = 'Open'
            $errorName = 'None'
        }
        catch {
            $stopwatch.Stop()
            $code = ''
            $e = $_.Exception
            while ($null -ne $e) {
                if ($null -ne $e.SocketErrorCode) { $code = [string]$e.SocketErrorCode; break }
                $e = $e.InnerException
            }
            if ($code -ceq 'ConnectionReset') { $state = 'Closed'; $errorName = 'IcmpUnreachable' }
            elseif ($code -ceq 'TimedOut') { $state = 'Open|Filtered'; $errorName = 'NoResponse' }
            elseif ($code -ceq 'HostUnreachable' -or $code -ceq 'NetworkUnreachable') { $state = 'Closed'; $errorName = 'HostUnreachable' }
            # AccessDenied (WSAEACCES 10013) on this connect means a policy on this host refused the attempt
            # before any packet left (observed live: a VPN's DNS-leak filter denies every connect to port
            # 53, even to 127.0.0.x with a listener bound). It proves nothing about the path: State '' and
            # LocalPolicy, Outcome Inconclusive. Any other code stays ProbeError.
            elseif ($code -ceq 'AccessDenied') { $state = ''; $errorName = 'LocalPolicy' }
            else { $state = ''; $errorName = 'ProbeError' }
        }
    }
    catch {
        $state = ''
        $errorName = 'ProbeError'
    }
    finally {
        $stopwatch.Stop()
        if ($null -ne $udp) {
            try { $udp.Close() } catch { $null = $_ }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.AdapterResult'
        State      = $state
        ErrorName  = $errorName
        LatencyMs  = [int][Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
    }
}
