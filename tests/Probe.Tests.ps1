# Adapter tests (AC7 unit half). Every probe goes to a
# distinct 127.0.0.0/8 address from the harness allocator (or 127.0.0.1 for ICMP), except the one
# TEST-NET case, which is skipped unless the operator opts in (AC6).
#
# Windows measurement (this host): a connect to an unbound loopback port is refused only after
# about 2 s, because the Windows TCP stack retries the SYN after an RST. The refused cases therefore
# use a 5 s timeout; at the tool's 2 s default the same port reports Unreachable/Timeout.

BeforeDiscovery {
    $script:OffHost = ($env:PORTPROOF_TEST_OFFHOST -eq '1') -or [bool]$env:PORTPROOF_TEST_TIMEOUT_TARGET
}

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    foreach ($part in @('05-Contract', '50-Probe.Tcp', '55-Probe.Udp', '58-Probe.Icmp')) {
        . (Join-Path $script:Root "src/$part.ps1")
    }
    . (Join-Path $PSScriptRoot 'Harness/Harness.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Listeners.ps1')

    function Wait-ListenerEvent {
        param([pscustomobject] $Listener, [int] $Count = 1)
        $deadline = [System.Diagnostics.Stopwatch]::StartNew()
        while ($Listener.Events.Count -lt $Count -and $deadline.ElapsedMilliseconds -lt 3000) { Start-Sleep -Milliseconds 25 }
        Start-Sleep -Milliseconds 200
    }

    function Test-AdapterResult {
        param($Result)
        $Result.PSObject.TypeNames[0] | Should -Be 'PortProof.AdapterResult'
        @($Result.PSObject.Properties.Name) | Should -Be @('State', 'ErrorName', 'LatencyMs')
        $Result.LatencyMs | Should -BeOfType ([int])
    }
}

Describe 'PortProof.Probe.Tcp' -Tag 'Windows' {

    It 'reports Open / None for a listening port and connects exactly once' {
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        try {
            $r = Invoke-TcpProbe -Address ([System.Net.IPAddress]::Parse($listener.Address)) -Port $listener.Port -TimeoutMs 3000
            Test-AdapterResult $r
            $r.State | Should -Be 'Open'
            $r.ErrorName | Should -Be 'None'
            Get-PPOutcome -Protocol 'TCP' -State $r.State -ErrorName $r.ErrorName | Should -Be 'Pass'
            Wait-ListenerEvent -Listener $listener
            $listener.Events.Count | Should -Be 1
        }
        finally { Close-PPListener -Listener $listener }
    }

    It 'reports Closed / ConnectionRefused for a listener that has stopped (refuse after one)' {
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode RefuseAfterOne
        try {
            $ip = [System.Net.IPAddress]::Parse($listener.Address)
            $first = Invoke-TcpProbe -Address $ip -Port $listener.Port -TimeoutMs 3000
            $first.State | Should -Be 'Open'
            Wait-ListenerEvent -Listener $listener
            $second = Invoke-TcpProbe -Address $ip -Port $listener.Port -TimeoutMs 5000
            $second.State | Should -Be 'Closed'
            $second.ErrorName | Should -Be 'ConnectionRefused'
            $listener.Events.Count | Should -Be 1
        }
        finally { Close-PPListener -Listener $listener }
    }

    It 'reports Closed / ConnectionRefused for an unbound port' {
        $address = Get-PPLoopbackAddress
        $port = Get-PPUnboundPort -Address $address
        $r = Invoke-TcpProbe -Address ([System.Net.IPAddress]::Parse($address)) -Port $port -TimeoutMs 5000
        Test-AdapterResult $r
        $r.State | Should -Be 'Closed'
        $r.ErrorName | Should -Be 'ConnectionRefused'
        Get-PPOutcome -Protocol 'TCP' -State $r.State -ErrorName $r.ErrorName | Should -Be 'Fail'
    }

    It 'never throws: an impossible port returns State '''' / ProbeError (no packet is sent)' {
        $r = Invoke-TcpProbe -Address ([System.Net.IPAddress]::Loopback) -Port 70000 -TimeoutMs 1000
        Test-AdapterResult $r
        $r.State | Should -Be ''
        $r.ErrorName | Should -Be 'ProbeError'
    }

    It 'reports Unreachable / Timeout within TimeoutMs + 250 for TEST-NET-1 (opt-in, off-host)' -Skip:(-not $script:OffHost) {
        $target = '192.0.2.1'
        if ($env:PORTPROOF_TEST_TIMEOUT_TARGET) { $target = $env:PORTPROOF_TEST_TIMEOUT_TARGET }
        $r = Invoke-TcpProbe -Address ([System.Net.IPAddress]::Parse($target)) -Port 443 -TimeoutMs 500
        $r.State | Should -Be 'Unreachable'
        $r.ErrorName | Should -Be 'Timeout'
        $r.LatencyMs | Should -BeLessOrEqual 750
    }
}

Describe 'PortProof.Probe.Udp (AC7 unit half)' -Tag 'Windows' {

    It 'reports Open / None when the target replies, and sends exactly one datagram' {
        $listener = Open-PPUdpListener -Address (Get-PPLoopbackAddress) -Reply
        try {
            $r = Invoke-UdpProbe -Address ([System.Net.IPAddress]::Parse($listener.Address)) -Port $listener.Port -TimeoutMs 2000
            Test-AdapterResult $r
            $r.State | Should -Be 'Open'
            $r.ErrorName | Should -Be 'None'
            Wait-ListenerEvent -Listener $listener
            $listener.Events.Count | Should -Be 1
        }
        finally { Close-PPListener -Listener $listener }
    }

    It 'reports Open|Filtered / NoResponse when a listener stays silent (never Open)' {
        $listener = Open-PPUdpListener -Address (Get-PPLoopbackAddress)
        try {
            $r = Invoke-UdpProbe -Address ([System.Net.IPAddress]::Parse($listener.Address)) -Port $listener.Port -TimeoutMs 500
            $r.State | Should -Be 'Open|Filtered'
            $r.ErrorName | Should -Be 'NoResponse'
            Get-PPOutcome -Protocol 'UDP' -State $r.State -ErrorName $r.ErrorName | Should -Be 'Inconclusive'
            Wait-ListenerEvent -Listener $listener
            $listener.Events.Count | Should -Be 1
        }
        finally { Close-PPListener -Listener $listener }
    }

    It 'reports Closed or Open|Filtered for a closed loopback port, never Open' {
        $address = Get-PPLoopbackAddress
        $port = Get-PPUnboundPort -Address $address
        $r = Invoke-UdpProbe -Address ([System.Net.IPAddress]::Parse($address)) -Port $port -TimeoutMs 1000
        Test-AdapterResult $r
        $r.State | Should -BeIn @('Closed', 'Open|Filtered')
        $r.State | Should -Not -Be 'Open'
        if ($r.State -eq 'Closed') { $r.ErrorName | Should -Be 'IcmpUnreachable' } else { $r.ErrorName | Should -Be 'NoResponse' }
    }

    It 'never throws: an impossible port returns State '''' / ProbeError' {
        $r = Invoke-UdpProbe -Address ([System.Net.IPAddress]::Loopback) -Port 70000 -TimeoutMs 1000
        Test-AdapterResult $r
        $r.State | Should -Be ''
        $r.ErrorName | Should -Be 'ProbeError'
    }
}

Describe 'PortProof.Probe.Icmp' -Tag 'Windows' {

    It 'reports Reply / None for 127.0.0.1' {
        $r = Invoke-IcmpProbe -Address ([System.Net.IPAddress]::Loopback) -Port 0 -TimeoutMs 2000
        Test-AdapterResult $r
        $r.State | Should -Be 'Reply'
        $r.ErrorName | Should -Be 'None'
        Get-PPOutcome -Protocol 'ICMP' -State $r.State -ErrorName $r.ErrorName | Should -Be 'Pass'
    }

    It 'never throws: an impossible timeout returns State '''' / ProbeError (no echo is sent)' {
        $r = Invoke-IcmpProbe -Address ([System.Net.IPAddress]::Loopback) -TimeoutMs -5
        Test-AdapterResult $r
        $r.State | Should -Be ''
        $r.ErrorName | Should -Be 'ProbeError'
    }
}

Describe 'PortProof.Probe.Signatures' -Tag 'Portable' {

    It '<Name> takes [IPAddress] (never a string host) and declares no Recorder' -ForEach @(
        @{ Name = 'Invoke-TcpProbe' }
        @{ Name = 'Invoke-UdpProbe' }
        @{ Name = 'Invoke-IcmpProbe' }
    ) {
        $command = Get-Command -CommandType Function -Name $Name
        $command.Parameters['Address'].ParameterType.FullName | Should -Be 'System.Net.IPAddress'
        $command.Parameters['Port'].ParameterType.FullName | Should -Be 'System.Int32'
        $command.Parameters['TimeoutMs'].ParameterType.FullName | Should -Be 'System.Int32'
        $command.Parameters.ContainsKey('Recorder') | Should -BeFalse
    }

    It 'the TCP adapter refuses a string that is not an address at binding time' {
        { Invoke-TcpProbe -Address 'localhost' -Port 80 -TimeoutMs 100 } | Should -Throw
    }
}

Describe 'PortProof.Probe.SocketErrorMapping (deterministic)' -Tag 'Portable' {
    # Runs each adapter's own classifying catch block, read from the source file by AST, against a
    # constructed exception chain shaped exactly like the real one (MethodInvocationException wrapping
    # a SocketException). No socket is opened. Background: a local firewall/VPN DNS-leak protection
    # that blocks outbound port 53 makes every TCP connect to port 53 fail at once
    # with AccessDenied (WSAEACCES 10013), even to 127.0.0.x with a listener bound there.

    BeforeAll {
        function Get-ClassifyingCatch {
            # The catch clause whose body inspects SocketErrorCode, inside $Function in $File, wrapped
            # as one self-contained block: it throws its argument and runs the real catch body on it.
            param([string] $File, [string] $Function)
            $functionName = $Function
            $tokens = $null
            $parseErrors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root "src/$File"), [ref]$tokens, [ref]$parseErrors)
            $func = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $functionName }, $true)
            $clause = @($func.FindAll({ param($n) $n -is [System.Management.Automation.Language.CatchClauseAst] -and $n.Body.Extent.Text -match 'SocketErrorCode' }, $true))
            $clause.Count | Should -Be 1
            $text = "param(`$Record)`n`$state = 'unset'`n`$errorName = 'unset'`n`$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()`n" +
                "try { throw `$Record }`ncatch " + $clause[0].Body.Extent.Text + "`n[pscustomobject]@{ State = `$state; ErrorName = `$errorName }"
            [scriptblock]::Create($text)
        }

        function Invoke-Classify {
            # Runs the wrapped catch body on an ErrorRecord shaped like the real one: a
            # MethodInvocationException wrapping SocketException($Code).
            param([scriptblock] $Body, [int] $Code)
            $inner = [System.Net.Sockets.SocketException]::new($Code)
            $wrapped = [System.Management.Automation.MethodInvocationException]::new('Exception calling "X"', $inner)
            $record = [System.Management.Automation.ErrorRecord]::new($wrapped, 'Probe.Mock', [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
            & $Body $record
        }

        $script:TcpCatch = Get-ClassifyingCatch -File '50-Probe.Tcp.ps1' -Function 'Invoke-TcpProbe'
        $script:UdpCatch = Get-ClassifyingCatch -File '55-Probe.Udp.ps1' -Function 'Invoke-UdpProbe'
    }

    It 'TCP maps SocketError <Code> to <State> / <ErrorName>' -ForEach @(
        @{ Code = 10061; State = 'Closed'; ErrorName = 'ConnectionRefused' }
        @{ Code = 10060; State = 'Unreachable'; ErrorName = 'Timeout' }
        @{ Code = 10065; State = 'Unreachable'; ErrorName = 'HostUnreachable' }
        @{ Code = 10051; State = 'Unreachable'; ErrorName = 'HostUnreachable' }
        @{ Code = 10013; State = ''; ErrorName = 'LocalPolicy' }
        @{ Code = 10048; State = ''; ErrorName = 'ProbeError' }
    ) {
        $r = Invoke-Classify -Body $script:TcpCatch -Code $Code
        $r.State | Should -Be $State
        $r.ErrorName | Should -Be $ErrorName
    }

    It 'UDP maps SocketError <Code> to <State> / <ErrorName>' -ForEach @(
        @{ Code = 10054; State = 'Closed'; ErrorName = 'IcmpUnreachable' }
        @{ Code = 10060; State = 'Open|Filtered'; ErrorName = 'NoResponse' }
        @{ Code = 10065; State = 'Closed'; ErrorName = 'HostUnreachable' }
        @{ Code = 10051; State = 'Closed'; ErrorName = 'HostUnreachable' }
        @{ Code = 10013; State = ''; ErrorName = 'LocalPolicy' }
    ) {
        $r = Invoke-Classify -Body $script:UdpCatch -Code $Code
        $r.State | Should -Be $State
        $r.ErrorName | Should -Be $ErrorName
    }

    It 'AccessDenied (10013) is LocalPolicy and Inconclusive, never Pass or Fail, for TCP and UDP' {
        foreach ($p in @(@{ Body = $script:TcpCatch; Protocol = 'TCP' }, @{ Body = $script:UdpCatch; Protocol = 'UDP' })) {
            $r = Invoke-Classify -Body $p.Body -Code 10013
            $r.ErrorName | Should -Be 'LocalPolicy'
            Get-PPOutcome -Protocol $p.Protocol -State $r.State -ErrorName $r.ErrorName | Should -Be 'Inconclusive'
        }
    }
}
