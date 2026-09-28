# PortProof test harness - loopback TCP/UDP listeners.
#
# Every listener binds one distinct 127.0.0.0/8 address (Get-PPLoopbackAddress in Harness.ps1) on
# port 0 (ephemeral, OS-assigned). Nothing here ever binds, connects to, or sends toward any
# address outside 127.0.0.0/8: each function throws if handed anything else. `TcpListener` is
# otherwise a prohibited token in src/ (AC28); it is explicitly allowed in tests/Harness (AC28
# scans src/ only - see Test-NoDeferredFeatures.ps1).

function Assert-PPLoopbackAddress {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Net.IPAddress] $Address)
    if ($Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $Address.GetAddressBytes()[0] -ne 127) {
        throw "PortProof test harness: '$Address' is not a 127.0.0.0/8 loopback address; refusing to bind or send."
    }
}

function Open-PPTcpListener {
    <#
        Starts a background accept loop on address:0. Mode Accept: every connection is accepted
        and closed at once, forever. Mode RefuseAfterOne: accepts exactly one connection, then
        stops listening, so a later connect to the same address:port is refused (nothing is bound
        there any more).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Address,
        [ValidateSet('Accept', 'RefuseAfterOne')] [string] $Mode = 'Accept'
    )

    $ip = [System.Net.IPAddress]::Parse($Address)
    Assert-PPLoopbackAddress -Address $ip

    $listener = [System.Net.Sockets.TcpListener]::new($ip, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port

    $events = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $stopSignal = [System.Threading.ManualResetEventSlim]::new($false)

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
    $rs.Open()
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs

    [void] $ps.AddScript({
        param($Listener, $Events, $StopSignal, $Mode)
        while (-not $StopSignal.IsSet) {
            try {
                $result = $Listener.BeginAcceptTcpClient($null, $null)
            } catch {
                break
            }
            $signalled = [System.Threading.WaitHandle]::WaitAny(@($result.AsyncWaitHandle, $StopSignal.WaitHandle))
            if ($signalled -ne 0) { break }
            try {
                $accepted = $Listener.EndAcceptTcpClient($result)
            } catch {
                break
            }
            $Events.Enqueue([System.Diagnostics.Stopwatch]::StartNew())
            $accepted.Close()
            if ($Mode -eq 'RefuseAfterOne') {
                $Listener.Stop()
                break
            }
        }
    }).AddArgument($listener).AddArgument($events).AddArgument($stopSignal).AddArgument($Mode)

    $asyncResult = $ps.BeginInvoke()

    [pscustomobject]@{
        PSTypeName  = 'PortProof.Test.TcpListener'
        Address     = $Address
        Port        = $port
        Mode        = $Mode
        Events      = $events
        Listener    = $listener
        Client      = $null
        PowerShell  = $ps
        Runspace    = $rs
        AsyncResult = $asyncResult
        StopSignal  = $stopSignal
    }
}

function Open-PPUdpListener {
    <#
        Starts a background receive loop on address:0. Counts each received datagram
        (unread beyond what EndReceive needs). With -Reply, sends one byte back to the sender
        after each datagram, giving AC7 a positive-response fixture.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Address,
        [switch] $Reply
    )

    $ip = [System.Net.IPAddress]::Parse($Address)
    Assert-PPLoopbackAddress -Address $ip

    $udp = [System.Net.Sockets.UdpClient]::new([System.Net.IPEndPoint]::new($ip, 0))
    $port = $udp.Client.LocalEndPoint.Port

    $events = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
    $stopSignal = [System.Threading.ManualResetEventSlim]::new($false)

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
    $rs = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($iss)
    $rs.Open()
    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $rs

    [void] $ps.AddScript({
        param($Udp, $Events, $StopSignal, $DoReply)
        while (-not $StopSignal.IsSet) {
            try {
                $result = $Udp.BeginReceive($null, $null)
            } catch {
                break
            }
            $signalled = [System.Threading.WaitHandle]::WaitAny(@($result.AsyncWaitHandle, $StopSignal.WaitHandle))
            if ($signalled -ne 0) { break }
            $remote = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
            try {
                [void] $Udp.EndReceive($result, [ref] $remote)
            } catch {
                continue
            }
            $Events.Enqueue([System.Diagnostics.Stopwatch]::StartNew())
            if ($DoReply) {
                [void] $Udp.Send([byte[]] @(1), 1, $remote)
            }
        }
    }).AddArgument($udp).AddArgument($events).AddArgument($stopSignal).AddArgument([bool] $Reply)

    $asyncResult = $ps.BeginInvoke()

    [pscustomobject]@{
        PSTypeName  = 'PortProof.Test.UdpListener'
        Address     = $Address
        Port        = $port
        Reply       = [bool] $Reply
        Events      = $events
        Listener    = $null
        Client      = $udp
        PowerShell  = $ps
        Runspace    = $rs
        AsyncResult = $asyncResult
        StopSignal  = $stopSignal
    }
}

function Get-PPUnboundPort {
    <#
        Returns a port on Address that nothing is listening on: binds a listener briefly to get an
        OS-assigned free port, then stops it. A connect to this address:port should observe
        ConnectionRefused.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Address)

    $ip = [System.Net.IPAddress]::Parse($Address)
    Assert-PPLoopbackAddress -Address $ip

    $probe = [System.Net.Sockets.TcpListener]::new($ip, 0)
    $probe.Start()
    $port = $probe.LocalEndpoint.Port
    $probe.Stop()
    return $port
}

function Close-PPListener {
    <#
        Stops the background loop, closes the socket, and disposes the runspace. Safe to call more
        than once and safe on either listener shape (TCP or UDP).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)] [pscustomobject] $Listener)
    process {
        if ($Listener.StopSignal -and -not $Listener.StopSignal.IsSet) { $Listener.StopSignal.Set() }
        try {
            if ($Listener.Listener) { $Listener.Listener.Stop() }
        } catch {
            # Best-effort teardown: the listener may already be stopped (RefuseAfterOne stops it
            # itself). $null = $_ satisfies PSAvoidUsingEmptyCatchBlock without masking anything -
            # there is nothing actionable left to do with a socket we are discarding anyway.
            $null = $_
        }
        try {
            if ($Listener.Client) { $Listener.Client.Close() }
        } catch {
            $null = $_
        }
        if ($Listener.AsyncResult -and $Listener.PowerShell) {
            try { [void] $Listener.PowerShell.EndInvoke($Listener.AsyncResult) } catch {
                $null = $_
            }
        }
        if ($Listener.PowerShell) { $Listener.PowerShell.Dispose() }
        if ($Listener.Runspace) {
            try { $Listener.Runspace.Close() } catch {
                $null = $_
            }
            $Listener.Runspace.Dispose()
        }
        if ($Listener.StopSignal) { $Listener.StopSignal.Dispose() }
    }
}
