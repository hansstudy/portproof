# PortProof TCP adapter. Function definitions only.

function Invoke-TcpProbe {
    # One full connect via TcpClient.BeginConnect bounded by an explicit wait. On success the socket
    # is closed at once: no stream, nothing read or written, no local bind. Never throws: any
    # exception becomes State '' / ProbeError. Worker set: calls no other function.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [int] $Port,
        [Parameter(Mandatory)] [int] $TimeoutMs
    )

    $state = ''
    $errorName = 'ProbeError'
    $client = $null
    $pending = $null
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $client = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
        $pending = $client.BeginConnect($Address, $Port, $null, $null)
        if ($pending.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            try {
                $client.EndConnect($pending)
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
                if ($code -ceq 'ConnectionRefused') { $state = 'Closed'; $errorName = 'ConnectionRefused' }
                elseif ($code -ceq 'TimedOut') { $state = 'Unreachable'; $errorName = 'Timeout' }
                elseif ($code -ceq 'HostUnreachable' -or $code -ceq 'NetworkUnreachable') { $state = 'Unreachable'; $errorName = 'HostUnreachable' }
                # AccessDenied (WSAEACCES 10013) on this connect means a policy on this host refused the attempt
                # before any packet left (observed live: a VPN's DNS-leak filter denies every connect to port
                # 53, even to 127.0.0.x with a listener bound). It proves nothing about the path: State '' and
                # LocalPolicy, Outcome Inconclusive. Any other code stays ProbeError.
                elseif ($code -ceq 'AccessDenied') { $state = ''; $errorName = 'LocalPolicy' }
                else { $state = ''; $errorName = 'ProbeError' }
            }
        }
        else {
            $stopwatch.Stop()
            $state = 'Unreachable'
            $errorName = 'Timeout'
            $client.Close()
            try {
                $client.EndConnect($pending)
            }
            catch {
                # Releases the abandoned connect's async state only; the outcome is already Timeout.
                $null = $_
            }
        }
    }
    catch {
        $state = ''
        $errorName = 'ProbeError'
    }
    finally {
        $stopwatch.Stop()
        if ($null -ne $pending) {
            try { $pending.AsyncWaitHandle.Close() } catch { $null = $_ }
        }
        if ($null -ne $client) {
            try { $client.Close() } catch { $null = $_ }
        }
    }

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.AdapterResult'
        State      = $state
        ErrorName  = $errorName
        LatencyMs  = [int][Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
    }
}
