# Self-tests for every scanner in this folder. Each scanner is invoked as a real child
# script (via the call operator, never dot-sourced - every scanner ends with `exit 0/1`, which
# would tear down the Pester process if dot-sourced) against a synthetic fixture tree built fresh
# under $TestDrive, so nothing here depends on, or is broken by, what other units land in src/.
# Tagged Portable: no socket, no process spawn other than the scanner scripts themselves.

BeforeAll {
    $script:ScriptsDir = $PSScriptRoot

    function Invoke-PPScanner {
        <# Every scanner here takes exactly one of -Root or -Path; pass whichever it is as a
           hashtable so the call operator splats it as a NAMED argument (splatting an array, `@x`
           where $x is a string[], binds positionally instead - not what a `-Root <value>` /
           `-Path <value>` scanner signature needs). #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)] [string] $Name,
            [string] $Root,
            [string] $Path
        )
        $scriptPath = Join-Path $script:ScriptsDir $Name
        $namedArgs = @{}
        if ($PSBoundParameters.ContainsKey('Root')) { $namedArgs.Root = $Root }
        if ($PSBoundParameters.ContainsKey('Path')) { $namedArgs.Path = $Path }
        $output = & $scriptPath @namedArgs
        [pscustomobject]@{
            PSTypeName = 'PortProof.Test.ScanResult'
            Output     = @($output)
            ExitCode   = $LASTEXITCODE
        }
    }

    function Get-PPScanRoot {
        param([Parameter(Mandatory)] [string] $Name)
        $root = Join-Path $TestDrive $Name
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        $root
    }

    function Write-PPFile {
        param([Parameter(Mandatory)] [string] $Root, [Parameter(Mandatory)] [string] $Relative, [Parameter(Mandatory)] [string] $Content)
        $full = Join-Path $Root $Relative
        $dir = Split-Path -Parent $full
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllText($full, $Content, [System.Text.UTF8Encoding]::new($false))
        $full
    }
}

Describe 'PortProof.Static.ProbeProhibitions (AC16)' -Tag 'Portable' {

    It 'catches a raw socket construction planted in src/' {
        $root = Get-PPScanRoot 'ac16-raw'
        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    $s = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [SocketType]::Raw, [ProtocolType]::Tcp)
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'SocketType.*Raw'
    }

    It 'catches GetStream(/.Read( outside the UDP adapter' {
        $root = Get-PPScanRoot 'ac16-banner'
        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    $c = [System.Net.Sockets.TcpClient]::new()
    $stream = $c.GetStream()
    $stream.Read($buf, 0, 1)
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'GetStream'
    }

    It 'passes a clean TCP adapter with no banner grab or raw socket' {
        $root = Get-PPScanRoot 'ac16-clean'
        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $c = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $ar = $c.BeginConnect($Address, $Port, $null, $null)
    [void] $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
    $c.Dispose()
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'requires .ReceiveTimeout before .Receive( in 55-Probe.Udp.ps1, and catches its absence' {
        $root = Get-PPScanRoot 'ac16-udp-bad'
        Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-UdpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $u = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
    $u.Connect([System.Net.IPEndPoint]::new($Address, $Port))
    [void] $u.Send([byte[]]::new(0), 0)
    $remote = [System.Net.IPEndPoint]::new($Address, 0)
    [void] $u.Receive([ref] $remote)
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'ReceiveTimeout'
    }

    It 'allows .Receive( in 55-Probe.Udp.ps1 when a .ReceiveTimeout assignment precedes it in the same function' {
        $root = Get-PPScanRoot 'ac16-udp-good'
        Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-UdpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $u = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
    $u.Client.ReceiveTimeout = $TimeoutMs
    $u.Connect([System.Net.IPEndPoint]::new($Address, $Port))
    [void] $u.Send([byte[]]::new(0), 0)
    $remote = [System.Net.IPEndPoint]::new($Address, 0)
    [void] $u.Receive([ref] $remote)
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    Context 'dist/ parity, not a blanket ban' {

        It 'does not flag dist/PortProof.ps1 for exactly carrying 55-Probe.Udp.ps1''s own guarded .Receive(' {
            $root = Get-PPScanRoot 'ac16-r8-parity'
            $headerSource = "# header`n"
            $udpSource = @'
function Invoke-UdpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $u = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
    $u.Client.ReceiveTimeout = $TimeoutMs
    $u.Connect([System.Net.IPEndPoint]::new($Address, $Port))
    [void]$u.Send([byte[]]::new(0), 0)
    $remote = [System.Net.IPEndPoint]::new($Address, 0)
    [void]$u.Receive([ref] $remote)
}
'@
            # A real 2-part build/parts.txt + banner, so Get-PPDistPartMap
            # can build a part map for this fixture's dist/PortProof.ps1 - a real build never has a
            # single, un-bannered part, and this scanner now reports (not silently allows through)
            # when no such marker exists at all.
            Write-PPFile -Root $root -Relative 'build\parts.txt' -Content "src/00-Header.ps1`nsrc/55-Probe.Udp.ps1`n"
            Write-PPFile -Root $root -Relative 'src\00-Header.ps1' -Content $headerSource
            Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content $udpSource
            Write-PPFile -Root $root -Relative 'dist\PortProof.ps1' -Content ($headerSource + "# ---- src/55-Probe.Udp.ps1 ----`n" + $udpSource)
            $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
            $result.ExitCode | Should -Be 0
            $result.Output.Count | Should -Be 0
        }

        It 'catches dist/PortProof.ps1 carrying a banner-grab token beyond what 55-Probe.Udp.ps1 has' {
            $root = Get-PPScanRoot 'ac16-r8-mismatch'
            $headerSource = "# header`n"
            $udpSource = @'
function Invoke-UdpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $u = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
    $u.Client.ReceiveTimeout = $TimeoutMs
    [void]$u.Receive([ref] $null)
}
'@
            $distExtra = @'
function Invoke-TcpProbe {
    $s = [System.Net.Sockets.TcpClient]::new()
    $s.GetStream().Read($buf, 0, 1)
}
'@
            Write-PPFile -Root $root -Relative 'build\parts.txt' -Content "src/00-Header.ps1`nsrc/55-Probe.Udp.ps1`n"
            Write-PPFile -Root $root -Relative 'src\00-Header.ps1' -Content $headerSource
            Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content $udpSource
            Write-PPFile -Root $root -Relative 'dist\PortProof.ps1' -Content ($headerSource + "# ---- src/55-Probe.Udp.ps1 ----`n" + $udpSource + $distExtra)
            $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'DistCountMismatch'
        }
    }
}

Describe 'PortProof.Static.ResolverIsolation (AC11-4)' -Tag 'Portable' {

    It 'catches a resolving token outside 30-Resolver.ps1' {
        $root = Get-PPScanRoot 'ac11-token'
        Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content @'
function Import-PPProfile {
    Resolve-DnsName -Name 'example.com'
}
'@
        Write-PPFile -Root $root -Relative 'src\30-Resolver.ps1' -Content 'function Resolve-PPName { }'
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Resolve-DnsName'
    }

    It 'does not flag the same token inside 30-Resolver.ps1 itself' {
        $root = Get-PPScanRoot 'ac11-resolver-clean'
        Write-PPFile -Root $root -Relative 'src\30-Resolver.ps1' -Content @'
function Resolve-PPName {
    param([string] $Name)
    [System.Net.Dns]::GetHostAddresses($Name)
}
'@
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches a TcpClient constructed with a string-literal host outside the resolver' {
        $root = Get-PPScanRoot 'ac11-ctor'
        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    $c = [System.Net.Sockets.TcpClient]::new('10.0.0.5')
}
'@
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'StringHostConstructor'
    }

    It 'catches a .Connect( call whose first argument is a string literal' {
        $root = Get-PPScanRoot 'ac11-connect-string'
        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([int] $Port)
    $c = [System.Net.Sockets.TcpClient]::new()
    $c.Connect('192.168.1.1', $Port)
}
'@
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'UnapprovedHostArgument'
    }

    It 'allows .Connect($Address) and .Connect($Address.AddressFamily)-shaped calls' {
        $root = Get-PPScanRoot 'ac11-connect-clean'
        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port)
    $c = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $c.Connect($Address, $Port)
}
'@
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches a dist/ token count that does not match 30-Resolver.ps1' {
        $root = Get-PPScanRoot 'ac11-dist-mismatch'
        Write-PPFile -Root $root -Relative 'src\30-Resolver.ps1' -Content @'
function Resolve-PPName {
    [System.Net.Dns]::GetHostAddresses('x')
}
'@
        Write-PPFile -Root $root -Relative 'dist\PortProof.ps1' -Content @'
function Resolve-PPName {
    [System.Net.Dns]::GetHostAddresses('x')
    [System.Net.Dns]::GetHostAddresses('y')
}
'@
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'DistCountMismatch'
    }

    Context 'every host-touching argument shape, not just the first argument' {
        # Every case here passed an earlier, narrower scanner (first-argument-only check, no New-Object
        # support, no ConnectAsync, and the 4-argument Send/SendAsync overload's host sits at
        # position 2, not 0, so the old check inspected the [byte[]] buffer instead).

        It 'catches TcpClient::new($name, 80) - a variable in the host position' {
            $root = Get-PPScanRoot 'ac11-r2-01'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([string] $name)
    [System.Net.Sockets.TcpClient]::new($name, 80)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'StringHostConstructor'
        }

        It 'catches New-Object System.Net.Sockets.TcpClient($name, 80)' {
            $root = Get-PPScanRoot 'ac11-r2-02'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([string] $name)
    New-Object System.Net.Sockets.TcpClient($name, 80)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.NewObjectBanned'
        }

        It 'catches New-Object -TypeName UdpClient -ArgumentList "evil.test", 53' {
            $root = Get-PPScanRoot 'ac11-r2-03'
            Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-UdpProbe {
    New-Object -TypeName System.Net.Sockets.UdpClient -ArgumentList "evil.test", 53
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.NewObjectBanned'
        }

        It 'catches $c.ConnectAsync($name, 80)' {
            $root = Get-PPScanRoot 'ac11-r2-04'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [string] $name)
    $c = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $c.ConnectAsync($name, 80)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'UnapprovedHostArgument'
        }

        It 'catches the 4-argument Send(buffer, size, host, port) overload with a hostname variable' {
            $root = Get-PPScanRoot 'ac11-r2-05'
            Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-UdpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [string] $name)
    $u = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
    [void]$u.Send([byte[]]::new(0), 0, $name, 53)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'UnapprovedHostArgument'
        }

        It 'catches the 4-argument SendAsync(buffer, size, host, port) overload with a hostname variable' {
            $root = Get-PPScanRoot 'ac11-r2-06'
            Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-UdpProbe {
    param([string] $name)
    $u = [System.Net.Sockets.UdpClient]::new()
    [void]$u.SendAsync([byte[]]::new(0), 0, $name, 53)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'UnapprovedHostArgument'
        }

        It 'does not flag the legitimate TCP adapter shape (constructor by AddressFamily, BeginConnect by typed $Address)' {
            $root = Get-PPScanRoot 'ac11-r2-good-tcp'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $c = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $ar = $c.BeginConnect($Address, $Port, $null, $null)
    [void] $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
    $c.Dispose()
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 0
            $result.Output.Count | Should -Be 0
        }

        It 'does not flag the legitimate UDP adapter shape (IPEndPoint::new, [byte[]] buffer, 2-arg connected Send)' {
            $root = Get-PPScanRoot 'ac11-r2-good-udp'
            Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-UdpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $u = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
    $u.Client.ReceiveTimeout = $TimeoutMs
    $u.Connect([System.Net.IPEndPoint]::new($Address, $Port))
    [void]$u.Send([byte[]]::new(0), 0)
    $remote = [System.Net.IPEndPoint]::new($Address, 0)
    [void]$u.Receive([ref] $remote)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 0
            $result.Output.Count | Should -Be 0
        }

        It 'does not flag the legitimate ICMP adapter shape (Ping.Send(address, timeout, buffer), host at position 0)' {
            $root = Get-PPScanRoot 'ac11-r2-good-icmp'
            Write-PPFile -Root $root -Relative 'src\58-Probe.Icmp.ps1' -Content @'
function Invoke-IcmpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $p = [System.Net.NetworkInformation.Ping]::new()
    $r = $p.Send($Address, $TimeoutMs, [byte[]]::new(0))
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 0
            $result.Output.Count | Should -Be 0
        }
    }

    Context 'AC11 misses now caught by whole-construct-class posture bans' {
        # R01/R08/R09/R10 are four real AC11 misses an earlier, narrower check let through; each is
        # now caught by a whole-construct-class ban (New-Object outright, computed member, reflection)
        # rather than by inspecting the specific evasion's argument shape.

        It 'R01: catches a hostname via a hashtable splat into New-Object @p' {
            $root = Get-PPScanRoot 'ac11-r01-splat'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([string] $h)
    $p = @{ TypeName = 'System.Net.Sockets.TcpClient'; ArgumentList = @($h, 80) }
    New-Object @p
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.NewObjectBanned'
        }

        It 'R08: catches dynamic member-name dispatch, $client.$methodName($h, 80)' {
            $root = Get-PPScanRoot 'ac11-r08-dynmember'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [string] $h)
    $client = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $methodName = 'Connect'
    $client.$methodName($h, 80)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.ComputedMember'
        }

        It 'R09: catches a dynamic -TypeName variable on New-Object' {
            $root = Get-PPScanRoot 'ac11-r09-dyntype'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([string] $h)
    $tn = 'System.Net.Sockets.TcpClient'
    New-Object -TypeName $tn -ArgumentList $h, 80
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.NewObjectBanned'
        }

        It 'R10: catches reflection-based .GetMethod(''Connect'').Invoke(...)' {
            $root = Get-PPScanRoot 'ac11-r10-reflect'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address, [string] $h)
    $client = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $client.GetType().GetMethod('Connect').Invoke($client, @($h, 80))
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.Reflection'
        }

        It 'catches Socket construction (never allowed anywhere)' {
            $root = Get-PPScanRoot 'ac11-socket-never'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address)
    $s = [System.Net.Sockets.Socket]::new($Address.AddressFamily, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.ConstructionFileScope'
            ($result.Output -join "`n") | Should -Match 'Socket construction is allowed nowhere'
        }

        It 'catches TcpClient constructed in the wrong file (55-Probe.Udp.ps1, not its allowed 50-Probe.Tcp.ps1)' {
            $root = Get-PPScanRoot 'ac11-wrong-file'
            Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-TcpProbeMisplaced {
    param([System.Net.IPAddress] $Address)
    $c = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.ConstructionFileScope'
        }
    }

    Context 'type-via-a-variable evasions caught by the static-member and allowlist bans' {

        It "catches '...TcpClient' -as [type] then `$t::new(`$h,80)" {
            $root = Get-PPScanRoot 'ac11-typevar-b1'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function f {
    param([string] $h)
    $t = 'System.Net.Sockets.TcpClient' -as [type]
    $t::new($h, 80)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'AsTypeCast'
        }

        It "catches .Assembly.GetType('...TcpClient') then `$t2::new(`$h,80)" {
            $root = Get-PPScanRoot 'ac11-typevar-b2'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function f {
    param([string] $h)
    $t2 = $x.Assembly.GetType('System.Net.Sockets.TcpClient')
    $t2::new($h, 80)
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match '\.Assembly is banned'
        }

        It 'catches Set-Alias no2 New-Object; no2 -TypeName ... -ArgumentList $h,80' {
            $root = Get-PPScanRoot 'ac11-typevar-b3'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function f {
    param([string] $h)
    Set-Alias no2 New-Object
    no2 -TypeName System.Net.Sockets.TcpClient -ArgumentList $h, 80
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match "'no2' is not a src/-defined function or an allowlisted cmdlet"
        }

        It 'catches & (Get-Command New-Object) -TypeName ... -ArgumentList $h,80' {
            $root = Get-PPScanRoot 'ac11-typevar-b4'
            Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function f {
    param([string] $h)
    & (Get-Command New-Object) -TypeName System.Net.Sockets.TcpClient -ArgumentList $h, 80
}
'@
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }
    }

    Context 'allowlist rules: one fixture per rule showing a non-listed command/type is caught' {

        It 'catches a command that is neither a src/-defined function nor an allowlisted cmdlet' {
            $root = Get-PPScanRoot 'ac11-allowlist-command'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { Get-Random -Maximum 10 }'
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match "'Get-Random' is not a src/-defined function or an allowlisted cmdlet"
        }

        It 'catches a type that is on neither the General nor the Scoped allowlist' {
            $root = Get-PPScanRoot 'ac11-allowlist-type'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { param([System.Net.Sockets.NetworkStream] $s) }'
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'Posture.TypeAllowlist'
        }

        It 'allows a function defined elsewhere in src/ to be called (the (a) allowlist path)' {
            $root = Get-PPScanRoot 'ac11-allowlist-defined-fn'
            Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content 'function Import-PPProfile { param($Path) }'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { Import-PPProfile -Path $x }'
            $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
            $result.ExitCode | Should -Be 0
        }
    }
}

Describe 'PortProof.Static.NoCredentials (AC17)' -Tag 'Portable' {

    It 'catches Get-Credential planted in src/' {
        $root = Get-PPScanRoot 'ac17-bad'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPCred { Get-Credential }'
        $result = Invoke-PPScanner -Name 'Test-NoCredentials.ps1' -Root $root
        $result.ExitCode | Should -Be 1
    }

    It 'does not trigger on a credential token that appears only in a comment' {
        $root = Get-PPScanRoot 'ac17-comment'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
<#
This tool has no -Credential parameter, calls no Get-Credential, and never touches
ConvertTo-SecureString or PSCredential.
#>
function Get-PPClean { Write-Output 'ok' }
'@
        $result = Invoke-PPScanner -Name 'Test-NoCredentials.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'passes a clean file with no credential logic' {
        $root = Get-PPScanRoot 'ac17-clean'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPClean { Write-Output ''ok'' }'
        $result = Invoke-PPScanner -Name 'Test-NoCredentials.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }
}

Describe 'PortProof.Static.NoOutbound (AC18)' -Tag 'Portable' {

    It 'catches Invoke-WebRequest planted in src/' {
        $root = Get-PPScanRoot 'ac18-bad'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPUpdate { Invoke-WebRequest -Uri "https://example.com" }'
        $result = Invoke-PPScanner -Name 'Test-NoOutbound.ps1' -Root $root
        $result.ExitCode | Should -Be 1
    }

    It 'passes a clean file with no outbound calls' {
        $root = Get-PPScanRoot 'ac18-clean'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPClean { Write-Output ''ok'' }'
        $result = Invoke-PPScanner -Name 'Test-NoOutbound.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }
}

Describe 'PortProof.Static.NoDeferredFeatures (AC28)' -Tag 'Portable' {

    It 'catches Invoke-Command planted in src/' {
        $root = Get-PPScanRoot 'ac28-bad'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPRemote { Invoke-Command -ScriptBlock { 1 } }'
        $result = Invoke-PPScanner -Name 'Test-NoDeferredFeatures.ps1' -Root $root
        $result.ExitCode | Should -Be 1
    }

    It 'does not scan outside src/ (TcpListener in tests/Harness/ is not a finding)' {
        $root = Get-PPScanRoot 'ac28-harness'
        Write-PPFile -Root $root -Relative 'tests\Harness\Listeners.ps1' -Content 'function Open-PPTcpListener { [System.Net.Sockets.TcpListener]::new(0) }'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPClean { Write-Output ''ok'' }'
        $result = Invoke-PPScanner -Name 'Test-NoDeferredFeatures.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }
}

Describe 'PortProof.Static.NoDynamicEval (AC19)' -Tag 'Portable' {

    It 'catches a literal Invoke-Expression call' {
        $root = Get-PPScanRoot 'ac19-literal'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPBad { Invoke-Expression ''1+1'' }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match "banned command 'Invoke-Expression'"
    }

    It 'catches the iex alias' {
        $root = Get-PPScanRoot 'ac19-iex'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPBad { iex ''1+1'' }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match "banned command 'iex'"
    }

    It 'catches Invoke-Expression obfuscated with a mid-token backtick escape' {
        $root = Get-PPScanRoot 'ac19-backtick-mid'
        # Invoke`-Expression: the backtick before a non-special character is dropped by the
        # engine and the command resolves and RUNS as Invoke-Expression - verified empirically
        # (GetCommandName() folds this to the plain name); a raw per-line regex would miss it.
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Get-PPBad {
    Invoke`-Expression '1+1'
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match "banned command 'Invoke-Expression'"
    }

    It 'catches Invoke-Expression split across physical lines by a backtick line-continuation' {
        $root = Get-PPScanRoot 'ac19-backtick-lines'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Get-PPBad {
    Invoke-Expression `
        '1+1'
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match "banned command 'Invoke-Expression'"
    }

    It 'catches a command name built by literal string concatenation' {
        $root = Get-PPScanRoot 'ac19-concat'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Get-PPBad {
    $cmd = 'Invoke' + '-Expression'
    & $cmd '1+1'
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'string concatenation folds to'
    }

    It 'catches & (Get-Command ...) resolving to a banned name' {
        $root = Get-PPScanRoot 'ac19-gcm-full'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function Get-PPBad { & (Get-Command 'Invoke-Expression') '1+1' }"
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'resolves to banned command'
    }

    It 'catches & (gcm ...) resolving to a banned name' {
        $root = Get-PPScanRoot 'ac19-gcm-alias'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function Get-PPBad { & (gcm iex) '1+1' }"
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'resolves to banned command'
    }

    It 'catches [scriptblock]::Create directly' {
        $root = Get-PPScanRoot 'ac19-sb-direct'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPBad { [scriptblock]::Create(''1+1'') }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match '\[scriptblock\]::Create'
    }

    It 'catches [scriptblock]::Create invoked via a variable holding the type' {
        $root = Get-PPScanRoot 'ac19-sb-var'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Get-PPBad {
    $t = [scriptblock]
    $sb = $t::Create('1+1')
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match '\[scriptblock\]::Create \(via a variable\)'
    }

    It 'does not trigger on Invoke-Expression/iex/[scriptblock]::Create mentioned only in a comment' {
        $root = Get-PPScanRoot 'ac19-comment'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
<#
Never call Invoke-Expression, the iex alias, [scriptblock]::Create, or Add-Type: see AC19.
#>
function Get-PPClean { Write-Output 'ok' }
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'passes a clean file with no dynamic evaluation' {
        $root = Get-PPScanRoot 'ac19-clean'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPClean { Write-Output ''ok'' }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }

    Context 'dynamic-eval evasions caught beyond the literal-token layer' {
        # Each plant is its own It so a regression names the exact evasion that broke, not just
        # "AC19 failed". Every one of these escaped an earlier, narrower scanner (literal-token layer
        # only, AST layer with a narrow banned-name list and a single fixed argument position).

        It 'catches $ExecutionContext.InvokeCommand.NewScriptBlock(...)' {
            $root = Get-PPScanRoot 'ac19-r1-01'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $ExecutionContext.InvokeCommand.NewScriptBlock($x) }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches a module-qualified Invoke-Expression call' {
            $root = Get-PPScanRoot 'ac19-r1-02'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { Microsoft.PowerShell.Utility\Invoke-Expression $x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches Set-Alias/New-Alias targeting a banned command' {
            $root = Get-PPScanRoot 'ac19-r1-03'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { Set-Alias zz Invoke-Expression; zz $x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match "targets banned command 'Invoke-Expression'"
        }

        It 'catches $ExecutionContext.InvokeCommand.GetCommand("Invoke-Expression", ...)' {
            $root = Get-PPScanRoot 'ac19-r1-04'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $ExecutionContext.InvokeCommand.GetCommand("Invoke-Expression","Cmdlet") }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches a banned command name carried through a variable and invoked with &' {
            $root = Get-PPScanRoot 'ac19-r1-05'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $c = "Add-Type"; & $c -TypeDefinition $x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'resolves to banned command'
        }

        It 'catches a banned name folded from concatenation not in the old two-name list (Add-Type)' {
            $root = Get-PPScanRoot 'ac19-r1-06'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { & ("Add-" + "Type") -TypeDefinition $x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match "folds to 'Add-Type'"
        }

        It 'catches & (gcm <wildcard>) resolving to a banned name' {
            $root = Get-PPScanRoot 'ac19-r1-07a'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { & (gcm i*x) $x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches & (Get-Command <wildcard>) resolving to a banned name' {
            $root = Get-PPScanRoot 'ac19-r1-07b'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { & (Get-Command Invoke-Exp*) $x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches [scriptblock]::Create via a [type]"scriptblock" cast' {
            $root = Get-PPScanRoot 'ac19-r1-08a'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $t = [type]"scriptblock"
    $t::Create($x)
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches [scriptblock]::Create via a "...ScriptBlock" -as [type] cast' {
            $root = Get-PPScanRoot 'ac19-r1-08b'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $t = "System.Management.Automation.ScriptBlock" -as [type]
    $t::Create($x)
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches [scriptblock]::$m($x) where $m holds the member name "Create"' {
            $root = Get-PPScanRoot 'ac19-r1-09'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $m = "Create"
    [scriptblock]::$m($x)
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'member name via a variable'
        }

        It 'catches $ExecutionContext.InvokeCommand.InvokeScript(...)' {
            $root = Get-PPScanRoot 'ac19-r1-10a'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $ExecutionContext.InvokeCommand.InvokeScript($x) }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'catches [powershell]::Create().AddScript($x).Invoke()' {
            $root = Get-PPScanRoot 'ac19-r1-10b'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { [powershell]::Create().AddScript($x).Invoke() }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'AddScript'
        }

        It 'catches [runspacefactory]::CreateRunspace().CreatePipeline($x).Invoke()' {
            $root = Get-PPScanRoot 'ac19-r1-11'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { [runspacefactory]::CreateRunspace().CreatePipeline($x).Invoke() }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'CreatePipeline'
        }

        It 'catches a function: write reached through a variable path outside 40-Scheduler.ps1' {
            $root = Get-PPScanRoot 'ac19-r1-12'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $d = "function:zz"
    Set-Item -Path $d -Value $x
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'FunctionWriteScope'
        }

        It 'still catches Add-Type called with splatted arguments (previously-caught category)' {
            $root = Get-PPScanRoot 'ac19-r1-caught-splat'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $p = @{TypeDefinition = $x}; Add-Type @p }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'still catches iex used mid-pipe (previously-caught category)' {
            $root = Get-PPScanRoot 'ac19-r1-caught-pipe'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $x | iex }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
        }

        It 'does not flag a clean file that only mentions the banned tokens in a comment' {
            $root = Get-PPScanRoot 'ac19-r1-clean'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
<#
This file mentions Invoke-Expression, iex, Add-Type, NewScriptBlock and scriptblock Create
only in this comment (AC19), and never writes to the function: drive.
#>
function Get-PPClean {
    param([System.Net.IPAddress] $Address)
    Write-Output 'ok'
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 0
            $result.Output.Count | Should -Be 0
        }
    }

    Context 'AC19 misses now caught by whole-construct-class posture bans' {
        # N01-N06 are six real AC19 misses an earlier, narrower check let through. Each is now caught
        # by a whole-construct-class ban rather than by recognising this specific evasion.

        It 'N01: catches .Invoke() on a scriptblock obtained via -as [scriptblock] (never calls ::Create)' {
            $root = Get-PPScanRoot 'ac19-n01'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $sb = $x -as [scriptblock]; $sb.Invoke() }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'ScriptBlockConversion'
        }

        It 'N02: catches Start-Job -ScriptBlock fed a -as [scriptblock] cast' {
            $root = Get-PPScanRoot 'ac19-n02'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $sb = $x -as [scriptblock]; Start-Job -ScriptBlock $sb }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match "banned command 'Start-Job'"
        }

        It 'N03: catches Register-ObjectEvent -Action fed a -as [scriptblock] cast' {
            $root = Get-PPScanRoot 'ac19-n03'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $sb = $x -as [scriptblock]; Register-ObjectEvent -InputObject $t -EventName Elapsed -Action $sb }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match "'Register-ObjectEvent' with -Action"
        }

        It 'N04: catches [scriptblock].GetMethod(''Create'').Invoke(...) (reflection, non-static call shape)' {
            $root = Get-PPScanRoot 'ac19-n04'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function f { [scriptblock].GetMethod('Create').Invoke(`$null, @(`$x)) }"
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'is banned \(reflection/introspection\)'
        }

        It 'N05: catches & "$name-$name2" $x (interpolated dynamic command name)' {
            $root = Get-PPScanRoot 'ac19-n05'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { & "$name-$name2" $x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'DynamicCommand'
        }

        It 'N06: catches [scriptblock]::(''Create'')($x) - parenthesized computed member name' {
            $root = Get-PPScanRoot 'ac19-n06'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function f { [scriptblock]::('Create')(`$x) }"
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'ComputedMember'
        }

        It 'catches a direct [scriptblock]$x cast (banned class 2, not just the ::Create/-as forms)' {
            $root = Get-PPScanRoot 'ac19-cast-direct'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $sb = [scriptblock]$x }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'cast to scriptblock'
        }

        It 'catches .$x, .(expr) and .''literal'' member access (banned class 4, computed/quoted member)' {
            $root = Get-PPScanRoot 'ac19-computed-member'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $obj.$x
    $obj.("Cre" + "ate")
    $obj.'Create'
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            @($result.Output | Where-Object { $_ -match 'ComputedMember' }).Count | Should -Be 3
        }

        It 'does not flag ordinary bareword member access (.Create, .Connect(, .AddressFamily)' {
            $root = Get-PPScanRoot 'ac19-bareword-member'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    param([System.Net.IPAddress] $Address)
    $obj.Create
    $obj.Connect($Address, 80)
    $x = $Address.AddressFamily
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 0
        }

        It 'catches [Reflection.Assembly] / [Activator] type usage (banned class 3, reflection)' {
            $root = Get-PPScanRoot 'ac19-reflection-types'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    [Reflection.Assembly]::LoadFrom($x)
    [Activator]::CreateInstance($t)
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            @($result.Output | Where-Object { $_ -match 'is reflection' }).Count | Should -Be 2
        }

        It 'catches .GetType() even read-only, with no further invoke (unconditional ban, not only when chained)' {
            $root = Get-PPScanRoot 'ac19-gettype-alone'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $n = $x.GetType().Name }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match '\.GetType\( is banned'
        }

        It 'catches Start-ThreadJob and Invoke-Command banned outright (banned class 6)' {
            $root = Get-PPScanRoot 'ac19-outright-banned'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    Start-ThreadJob -ScriptBlock { 1 }
    Invoke-Command -ScriptBlock { 1 }
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            @($result.Output | Where-Object { $_ -match "banned command 'Start-ThreadJob'" }).Count | Should -Be 1
            @($result.Output | Where-Object { $_ -match "banned command 'Invoke-Command'" }).Count | Should -Be 1
        }

        It 'catches a generic -ScriptBlock parameter bound to a variable on a non-listed command' {
            $root = Get-PPScanRoot 'ac19-generic-scriptblock-param'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { Invoke-SomeCustomThing -ScriptBlock $sb }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'not bound to an inline scriptblock literal'
        }

        It 'does not flag an inline scriptblock literal passed to -ScriptBlock' {
            $root = Get-PPScanRoot 'ac19-inline-scriptblock-ok'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Invoke-SomeCustomThing { param($ScriptBlock) }
function f { Invoke-SomeCustomThing -ScriptBlock { 1 } }
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 0
        }
    }

    Context 'type-via-a-variable and reflection evasions caught by the posture bans' {

        It 'catches .Assembly.GetType(...) into a variable, then $t::Create($x)' {
            $root = Get-PPScanRoot 'ac19-dyncall-a1'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $t = $x.Assembly.GetType('System.Management.Automation.ScriptBlock')
    $t::Create($x)
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match '\.Assembly is banned'
        }

        It 'catches ForEach-Object -Process $blk (real parameter name, not -ScriptBlock)' {
            $root = Get-PPScanRoot 'ac19-dyncall-a2'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $blk = { 1 }; 1..3 | ForEach-Object -Process $blk }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'PipelineScriptBlock'
        }

        It 'catches Where-Object -FilterScript $filter (real parameter name, not -ScriptBlock)' {
            $root = Get-PPScanRoot 'ac19-dyncall-a3'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $filter = { $true }; 1..3 | Where-Object -FilterScript $filter }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'PipelineScriptBlock'
        }

        It 'catches Where-Object $filter (positional, no parameter name at all)' {
            $root = Get-PPScanRoot 'ac19-dyncall-a3b'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $filter = { $true }; 1..3 | Where-Object $filter }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'PipelineScriptBlock'
        }

        It 'catches (Get-Command $n).ScriptBlock.Invoke() - dispatch bypassing & and . entirely' {
            $root = Get-PPScanRoot 'ac19-dyncall-a4'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { (Get-Command $n).ScriptBlock.Invoke() }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match '\.ScriptBlock is banned'
            ($result.Output -join "`n") | Should -Match '\.Invoke\( is banned'
        }

        It 'catches -as [type] from a non-foldable concatenated string feeding ::Create' {
            $root = Get-PPScanRoot 'ac19-dyncall-a5'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $part1 = "Sys"
    $t = ($part1 + "tem.Management.Automation.ScriptBlock") -as [type]
    $t::Create($x)
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'AsTypeCast'
        }
    }

    Context 'the two 40-Scheduler.ps1 allowances' {

        It 'allows exactly one function: write inside -Parallel, fed only from Get-PPWorkerDefinition' {
            $root = Get-PPScanRoot 'ac19-allow-good'
            Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Get-PPWorkerDefinition { param([string[]] $Names) [ordered]@{} }
function Invoke-PPTargetQueue { param($Queue) }
function Invoke-ProbeSchedule {
    param($Queues, $Concurrency)
    $defs = Get-PPWorkerDefinition -Names @('Invoke-PPTargetQueue')
    $Queues | ForEach-Object -Parallel {
        foreach ($d in $using:defs.GetEnumerator()) {
            Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value
        }
        Invoke-PPTargetQueue
    } -ThrottleLimit $Concurrency
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 0
            $result.Output.Count | Should -Be 0
        }

        It 'allows SessionStateFunctionEntry inside 40-Scheduler.ps1 (the 5.1 path)' {
            $root = Get-PPScanRoot 'ac19-sfe-good'
            Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Get-PPWorkerDefinition { param([string[]] $Names) [ordered]@{} }
function Invoke-ProbeSchedule {
    $defs = Get-PPWorkerDefinition -Names @('Invoke-PPTargetQueue')
    $entries = foreach ($d in $defs.GetEnumerator()) {
        [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($d.Key, $d.Value)
    }
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 0
        }

        It 'catches a function: write outside 40-Scheduler.ps1' {
            $root = Get-PPScanRoot 'ac19-write-elsewhere'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function Get-PPBad { Set-Item -LiteralPath 'function:Foo' -Value { 1 } }"
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'FunctionWriteScope'
        }

        It 'catches SessionStateFunctionEntry outside 40-Scheduler.ps1' {
            $root = Get-PPScanRoot 'ac19-sfe-elsewhere'
            Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Get-PPBad { [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new(''Foo'', $null) }'
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'FunctionEntryScope'
        }

        It 'catches a second function: write inside 40-Scheduler.ps1' {
            $root = Get-PPScanRoot 'ac19-write-twice'
            Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-ProbeSchedule {
    param($Queues, $Concurrency)
    $defs = Get-PPWorkerDefinition -Names @('Invoke-PPTargetQueue')
    $Queues | ForEach-Object -Parallel {
        foreach ($d in $using:defs.GetEnumerator()) {
            Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value
        }
        Invoke-PPTargetQueue
    } -ThrottleLimit $Concurrency
    Set-Item -LiteralPath 'function:Extra' -Value { 1 }
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'FunctionWriteCount'
        }

        It 'catches a function: write inside 40-Scheduler.ps1 but outside the -Parallel block' {
            $root = Get-PPScanRoot 'ac19-write-outside-parallel'
            Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-ProbeSchedule {
    param($Queues)
    $defs = Get-PPWorkerDefinition -Names @('Invoke-PPTargetQueue')
    foreach ($d in $defs.GetEnumerator()) {
        Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value
    }
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'FunctionWriteSource|FunctionWriteLocation'
        }

        It 'catches $defs assigned from something other than Get-PPWorkerDefinition' {
            $root = Get-PPScanRoot 'ac19-bad-source'
            Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-ProbeSchedule {
    param($Queues, $Concurrency)
    $defs = @{ Foo = 'bar' }
    $Queues | ForEach-Object -Parallel {
        foreach ($d in $using:defs.GetEnumerator()) {
            Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value
        }
        Invoke-PPTargetQueue
    } -ThrottleLimit $Concurrency
}
'@
            $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
            $result.ExitCode | Should -Be 1
            ($result.Output -join "`n") | Should -Match 'FunctionWriteSource'
        }
    }
}

Describe 'PortProof.Static.CallSites (AC30)' -Tag 'Portable' {

    It 'catches Test-RefusedTargetClass called from a file other than 10-Parser.ps1/35-Gate.ps1' {
        $root = Get-PPScanRoot 'ac30-bad-predicate'
        Write-PPFile -Root $root -Relative 'src\20-Expander.ps1' -Content 'function Expand-PPGroupValue { Test-RefusedTargetClass -Address $x }'
        Write-PPFile -Root $root -Relative 'src\05-Contract.ps1' -Content 'function Test-RefusedTargetClass { param($Address) }'
        $result = Invoke-PPScanner -Name 'Test-CallSites.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Test-RefusedTargetClass'
    }

    It 'allows Test-RefusedTargetClass called from 10-Parser.ps1 and 35-Gate.ps1 only, and ignores the definition file' {
        $root = Get-PPScanRoot 'ac30-good-predicate'
        Write-PPFile -Root $root -Relative 'src\05-Contract.ps1' -Content 'function Test-RefusedTargetClass { param($Address) }'
        Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content 'function Import-PPProfile { Test-RefusedTargetClass -Address $x }'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content 'function Invoke-PPGate { Test-RefusedTargetClass -Address $y }'
        $result = Invoke-PPScanner -Name 'Test-CallSites.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches Invoke-ProbeSchedule called from a file other than 35-Gate.ps1' {
        $root = Get-PPScanRoot 'ac30-bad-schedule'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Invoke-PPMain { Invoke-ProbeSchedule -Probes $p }'
        $result = Invoke-PPScanner -Name 'Test-CallSites.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Invoke-ProbeSchedule'
    }
}

Describe 'PortProof.Static.HtmlSelfContained (AC14)' -Tag 'Portable' {

    It 'catches a remote script tag' {
        $path = Join-Path $TestDrive 'bad1.html'
        [System.IO.File]::WriteAllText($path, '<html><body><script src="https://evil.example/x.js"></script></body></html>')
        $result = Invoke-PPScanner -Name 'Test-HtmlSelfContained.ps1' -Path $path
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'forbidden tag'
    }

    It 'catches a remote href and a remote url( inside a style attribute' {
        $path = Join-Path $TestDrive 'bad2.html'
        [System.IO.File]::WriteAllText($path, '<html><head><style>body{background:url(https://evil.example/bg.png)}</style></head><body><a href="https://evil.example/">x</a></body></html>')
        $result = Invoke-PPScanner -Name 'Test-HtmlSelfContained.ps1' -Path $path
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'url'
        ($result.Output -join "`n") | Should -Match 'href'
    }

    It 'passes a self-contained document with an in-document anchor and a URL only as escaped Notes text' {
        $path = Join-Path $TestDrive 'good1.html'
        [System.IO.File]::WriteAllText($path, '<html><body><a href="#top">Top</a><table><tr><td>Notes</td><td>see http://example.com in the notes text, and the literal &lt;script src=&quot;x&quot;&gt; text</td></tr></table></body></html>')
        $result = Invoke-PPScanner -Name 'Test-HtmlSelfContained.ps1' -Path $path
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }
}

Describe 'PortProof.Static.TemplateTokens (AC38)' -Tag 'Portable' {
    # The marker text is built with '+' rather than written as a literal double-brace token
    # anywhere in this file: this file is itself part of the tree Test-TemplateTokens.ps1 -Root
    # would scan for real (AC38 excludes only .git/ and two named upstream files), so a literal
    # token here would be a genuine self-inflicted AC38 finding, not a fixture.

    It 'catches an unresolved template token' {
        $root = Get-PPScanRoot 'ac38-bad'
        $marker = '{{' + 'PRODUCT_NAME' + '}}'
        Write-PPFile -Root $root -Relative 'README.md' -Content "Hello $marker."
        $result = Invoke-PPScanner -Name 'Test-TemplateTokens.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'PRODUCT_NAME'
    }

    It 'excludes exactly the two verbatim upstream template copies' {
        $root = Get-PPScanRoot 'ac38-excluded'
        $marker = '{{' + 'ARTIFACT_KIND' + '}}'
        Write-PPFile -Root $root -Relative 'docs\RELEASE-CHECKLIST.md' -Content "artifact_kind: $marker"
        Write-PPFile -Root $root -Relative '.github\workflows\scripts\check-release-evidence.mjs' -Content "const kind = '$marker';"
        $result = Invoke-PPScanner -Name 'Test-TemplateTokens.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'excludes .git/' {
        $root = Get-PPScanRoot 'ac38-git'
        $marker = '{{' + 'NOT_A_REAL_TOKEN' + '}}'
        Write-PPFile -Root $root -Relative '.git\COMMIT_EDITMSG' -Content $marker
        $result = Invoke-PPScanner -Name 'Test-TemplateTokens.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }
}

Describe 'PortProof.Static.WorkerClosure' -Tag 'Portable' {

    It 'catches a call inside the worker set to a function outside the set' {
        $root = Get-PPScanRoot 'closure-bad'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-PPTargetQueue {
    param($Queue, $AdapterName)
    Get-PPContract
    Start-Sleep -Milliseconds 1
}
'@
        $result = Invoke-PPScanner -Name 'Test-WorkerClosure.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Get-PPContract'
    }

    It 'allows Invoke-PPTargetQueue to dynamically dispatch its own adapter-name parameter' {
        $root = Get-PPScanRoot 'closure-good-dynamic'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-PPTargetQueue {
    param($Queue, $AdapterName)
    Wait-PPRateSlot
    & $AdapterName
    Get-PPOutcome
    Start-Sleep -Milliseconds 1
}
function Wait-PPRateSlot { Start-Sleep -Milliseconds 1 }
'@
        Write-PPFile -Root $root -Relative 'src\05-Contract.ps1' -Content 'function Get-PPOutcome { }'
        $result = Invoke-PPScanner -Name 'Test-WorkerClosure.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches a dynamic call in Invoke-PPTargetQueue whose operand is not its own parameter' {
        $root = Get-PPScanRoot 'closure-bad-dynamic'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-PPTargetQueue {
    param($Queue, $AdapterName)
    $other = 'Invoke-TcpProbe'
    & $other
}
'@
        $result = Invoke-PPScanner -Name 'Test-WorkerClosure.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'UnapprovedDynamicCall'
    }

    It 'catches the same dynamic-call shape used in a different worker-set member' {
        $root = Get-PPScanRoot 'closure-bad-dynamic-other'
        Write-PPFile -Root $root -Relative 'src\05-Contract.ps1' -Content @'
function Get-PPOutcome {
    param($Name)
    & $Name
}
'@
        $result = Invoke-PPScanner -Name 'Test-WorkerClosure.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'UnapprovedDynamicCall'
    }
}

Describe 'PortProof.Static.InvokeLint (AC3 / lint_command)' -Tag 'Portable' {

    BeforeAll {
        # Invoke-Lint.ps1 reads its settings file relative to its own $PSScriptRoot, so the two
        # failure-path checks (missing '# reason:' comment, empty Justification) need a private
        # copy of this whole folder rather than a fixture passed in through -Root.
        $script:LintCopyRoot = Join-Path $TestDrive 'lintcopy'
        New-Item -ItemType Directory -Path (Join-Path $script:LintCopyRoot 'tests\Static\settings') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:ScriptsDir 'StaticScan.ps1') -Destination (Join-Path $script:LintCopyRoot 'tests\Static\StaticScan.ps1')
        Copy-Item -LiteralPath (Join-Path $script:ScriptsDir 'Invoke-Lint.ps1') -Destination (Join-Path $script:LintCopyRoot 'tests\Static\Invoke-Lint.ps1')
    }

    It 'fails when an ExcludeRules entry lacks a # reason: comment' {
        $repo = Join-Path $script:LintCopyRoot 'norease'
        New-Item -ItemType Directory -Path (Join-Path $repo 'tests\Static\settings') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\StaticScan.ps1') -Destination (Join-Path $repo 'tests\Static\StaticScan.ps1')
        Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\Invoke-Lint.ps1') -Destination (Join-Path $repo 'tests\Static\Invoke-Lint.ps1')
        Set-Content -LiteralPath (Join-Path $repo 'tests\Static\settings\PSScriptAnalyzerSettings.psd1') -Encoding utf8 -Value @'
@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
    Rules = @{}
}
'@
        New-Item -ItemType Directory -Path (Join-Path $repo 'src') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $repo 'src\Clean.ps1') -Encoding utf8 -Value 'function Get-PPClean { Write-Output ''ok'' }'

        $lintPath = Join-Path $repo 'tests\Static\Invoke-Lint.ps1'
        $output = & $lintPath -Root $repo *>&1
        $LASTEXITCODE | Should -Be 1
        ($output -join "`n") | Should -Match "reason"
    }

    It 'fails when a SuppressMessageAttribute has an empty Justification' {
        $repo = Join-Path $script:LintCopyRoot 'emptyjust'
        New-Item -ItemType Directory -Path (Join-Path $repo 'tests\Static\settings') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\StaticScan.ps1') -Destination (Join-Path $repo 'tests\Static\StaticScan.ps1')
        Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\Invoke-Lint.ps1') -Destination (Join-Path $repo 'tests\Static\Invoke-Lint.ps1')
        Set-Content -LiteralPath (Join-Path $repo 'tests\Static\settings\PSScriptAnalyzerSettings.psd1') -Encoding utf8 -Value @'
@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @()
    Rules = @{}
}
'@
        New-Item -ItemType Directory -Path (Join-Path $repo 'src') -Force | Out-Null
        # Built with the attribute's own name kept out of a literal '<name>(' shape in THIS file's
        # source: this file is itself under tests/ and would otherwise trip Invoke-Lint's own
        # empty-Justification scan on its own text when the real lint run reaches tests/Static/.
        $attrName = 'SuppressMessageAttribute'
        $badContent = "function Get-PPBad {`n    [Diagnostics.CodeAnalysis.$attrName('PSAvoidUsingWriteHost', '', Justification = '')]`n    param()`n    Write-Output 'ok'`n}`n"
        Set-Content -LiteralPath (Join-Path $repo 'src\Bad.ps1') -Encoding utf8 -Value $badContent

        $lintPath = Join-Path $repo 'tests\Static\Invoke-Lint.ps1'
        $output = & $lintPath -Root $repo *>&1
        $LASTEXITCODE | Should -Be 1
        ($output -join "`n") | Should -Match 'Justification'
    }

    Context 'AST-based suppression parsing' {

        It 'catches the short form SuppressMessage(...) with no Justification at all (finding 3a)' {
            $repo = Join-Path $script:LintCopyRoot 'shortform'
            New-Item -ItemType Directory -Path (Join-Path $repo 'tests\Static\settings') -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\StaticScan.ps1') -Destination (Join-Path $repo 'tests\Static\StaticScan.ps1')
            Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\Invoke-Lint.ps1') -Destination (Join-Path $repo 'tests\Static\Invoke-Lint.ps1')
            Set-Content -LiteralPath (Join-Path $repo 'tests\Static\settings\PSScriptAnalyzerSettings.psd1') -Encoding utf8 -Value @'
@{
    Severity = @('Error', 'Warning')
    ExcludeRules = @()
    Rules = @{}
}
'@
            New-Item -ItemType Directory -Path (Join-Path $repo 'src') -Force | Out-Null
            # Built the same indirect way as the sibling test above, so this file's own source text
            # never contains a literal 'SuppressMessage(' for Invoke-Lint's real tree-wide run to
            # trip over.
            $attrName = 'SuppressMessage'
            $badContent = "function Get-PPBad {`n    [Diagnostics.CodeAnalysis.$attrName('PSAvoidUsingWriteHost', '')]`n    param()`n    Write-Output 'ok'`n}`n"
            Set-Content -LiteralPath (Join-Path $repo 'src\ShortForm.ps1') -Encoding utf8 -Value $badContent

            $lintPath = Join-Path $repo 'tests\Static\Invoke-Lint.ps1'
            $output = & $lintPath -Root $repo *>&1
            $LASTEXITCODE | Should -Be 1
            ($output -join "`n") | Should -Match 'Justification'
        }

        It 'does not false-fail when a Justification contains a ) (finding 3b)' {
            $repo = Join-Path $script:LintCopyRoot 'parenjust'
            New-Item -ItemType Directory -Path (Join-Path $repo 'tests\Static\settings') -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\StaticScan.ps1') -Destination (Join-Path $repo 'tests\Static\StaticScan.ps1')
            Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\Invoke-Lint.ps1') -Destination (Join-Path $repo 'tests\Static\Invoke-Lint.ps1')
            Copy-Item -LiteralPath (Join-Path $script:ScriptsDir 'settings\PSScriptAnalyzerSettings.psd1') -Destination (Join-Path $repo 'tests\Static\settings\PSScriptAnalyzerSettings.psd1')
            New-Item -ItemType Directory -Path (Join-Path $repo 'src') -Force | Out-Null
            $attrName = 'SuppressMessageAttribute'
            $badContent = "function Get-PPOk {`n    [Diagnostics.CodeAnalysis.$attrName('PSAvoidUsingWriteHost', '', Justification = 'Kept (see note) for tests.')]`n    param()`n    Write-Host 'hi'`n}`n"
            Set-Content -LiteralPath (Join-Path $repo 'src\ParenJust.ps1') -Encoding utf8 -Value $badContent

            $lintPath = Join-Path $repo 'tests\Static\Invoke-Lint.ps1'
            & $lintPath -Root $repo *>&1 | Out-Null
            $LASTEXITCODE | Should -Be 0
        }
    }

    It 'passes a clean isolated repo with default settings' {
        $repo = Join-Path $script:LintCopyRoot 'clean'
        New-Item -ItemType Directory -Path (Join-Path $repo 'tests\Static\settings') -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\StaticScan.ps1') -Destination (Join-Path $repo 'tests\Static\StaticScan.ps1')
        Copy-Item -LiteralPath (Join-Path $script:LintCopyRoot 'tests\Static\Invoke-Lint.ps1') -Destination (Join-Path $repo 'tests\Static\Invoke-Lint.ps1')
        Copy-Item -LiteralPath (Join-Path $script:ScriptsDir 'settings\PSScriptAnalyzerSettings.psd1') -Destination (Join-Path $repo 'tests\Static\settings\PSScriptAnalyzerSettings.psd1')
        New-Item -ItemType Directory -Path (Join-Path $repo 'src') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $repo 'src\Clean.ps1') -Encoding utf8 -Value @'
function Get-PPClean {
    [CmdletBinding()]
    param()
    Write-Output 'ok'
}
'@

        $lintPath = Join-Path $repo 'tests\Static\Invoke-Lint.ps1'
        $output = & $lintPath -Root $repo *>&1
        $LASTEXITCODE | Should -Be 0
        $output.Count | Should -Be 0
    }
}

Describe 'PortProof.Static.DeclaredFunctions (the forward-reference list cannot go stale)' -Tag 'Portable' {
    # settings/DeclaredFunctions.psd1 is a safety net for a forward reference from 90-Main.ps1 to a
    # function defined elsewhere in src/. Once dist/ exists (built by AC33), every one of those names
    # must be real - a name still only in this file at that point means either the signature changed
    # and the entry is stale, or the function was never written. This test is the only thing that
    # would ever notice.

    BeforeAll {
        . (Join-Path $script:ScriptsDir 'StaticScan.ps1')
        $script:RealRoot = Get-PPStaticRepoRoot
    }

    It 'every DeclaredFunctions.psd1 entry cites the file that defines it (sanity check on the list itself)' {
        $declared = Import-PowerShellDataFile -LiteralPath (Join-Path $script:ScriptsDir 'settings\DeclaredFunctions.psd1')
        $declared.Keys.Count | Should -BeGreaterThan 0
        foreach ($name in $declared.Keys) {
            $declared[$name] | Should -Match '\.ps1'
        }
    }

    It 'fails if dist/PortProof.ps1 exists and a declared function is still not defined anywhere in src/or dist/' {
        $distPath = Join-Path $script:RealRoot 'dist\PortProof.ps1'
        if (-not (Test-Path -LiteralPath $distPath)) {
            Set-ItResult -Skipped -Because 'dist/ does not exist yet; nothing to check yet.'
            return
        }
        $declared = Import-PowerShellDataFile -LiteralPath (Join-Path $script:ScriptsDir 'settings\DeclaredFunctions.psd1')
        $realNames = Get-PPDefinedFunctionName -Root $script:RealRoot
        $stale = @($declared.Keys | Where-Object { -not $realNames.Contains($_) })
        if ($stale.Count -gt 0) {
            throw "settings/DeclaredFunctions.psd1 is stale now that dist/ exists - never defined: $($stale -join ', ')"
        }
        $stale.Count | Should -Be 0
    }

    It 'a declared-but-not-yet-defined function does not block the command allowlist (the bridge itself works)' {
        $root = Join-Path $TestDrive 'declared-bridge'
        New-Item -ItemType Directory -Path (Join-Path $root 'src') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $root 'src\90-Main.ps1') -Encoding utf8 -Value 'function f { Import-PPProfile -Path $x }'
        & (Join-Path $script:ScriptsDir 'Test-ResolverIsolation.ps1') -Root $root | Out-Null
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'PortProof.Static.GetTypeNameAllowance (catch/trap-only .GetType().Name/.FullName)' -Tag 'Portable' {

    It 'allows $_.Exception.GetType().FullName as a terminal read inside a catch, in 90-Main.ps1' {
        $root = Get-PPScanRoot 'o6-gettype-allowed'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Invoke-PortProof {
    try {
        Write-Output 'ok'
    } catch {
        $message = 'PortProof: internal error: {0}: {1}' -f $_.Exception.GetType().FullName, $_.Message
        Write-Error -Message $message
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches $_.GetType().Name outside a catch/trap, even in 90-Main.ps1' {
        $root = Get-PPScanRoot 'o6-gettype-outside-catch'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { $n = $_.GetType().Name }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match '\.GetType\( is banned'
    }

    It 'catches .GetType().GetMethod( inside a catch, in 90-Main.ps1 (reflection stays banned)' {
        $root = Get-PPScanRoot 'o6-gettype-getmethod'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    try {} catch {
        $m = $_.GetType().GetMethod('Foo')
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match '\.GetMethod\( is banned'
    }

    It 'catches .GetType().Assembly inside a catch, in 90-Main.ps1 (not a terminal Name/FullName read)' {
        $root = Get-PPScanRoot 'o6-gettype-assembly'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    try {} catch {
        $a = $_.GetType().Assembly
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match '\.Assembly is banned'
    }

    It 'catches the same allowed shape outside 90-Main.ps1 (the allowance is file-scoped)' {
        $root = Get-PPScanRoot 'o6-gettype-wrong-file'
        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function f {
    try {} catch {
        $n = $_.Exception.GetType().FullName
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match '\.GetType\( is banned'
    }
}

Describe 'PortProof.Static.ScopedTypeAllowlists (Start-Sleep/Write-Warning, Monitor, Random)' -Tag 'Portable' {

    It 'allows Start-Sleep and Write-Warning anywhere' {
        $root = Get-PPScanRoot 'o7-cmds-allowed'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Wait-PPRateSlot {
    Start-Sleep -Milliseconds 1
    Write-Warning -Message 'ok'
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }

    It 'allows System.Threading.Monitor only in 40-Scheduler.ps1' {
        $root = Get-PPScanRoot 'o7-monitor-good'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Wait-PPRateSlot {
    param([hashtable] $Rate)
    [System.Threading.Monitor]::Enter($Rate.SyncRoot)
    try {} finally { [System.Threading.Monitor]::Exit($Rate.SyncRoot) }
}
'@
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches System.Threading.Monitor outside 40-Scheduler.ps1' {
        $root = Get-PPScanRoot 'o7-monitor-bad'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { [System.Threading.Monitor]::Enter($x) }'
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.TypeAllowlist'
    }

    It 'allows System.Random only in 35-Gate.ps1' {
        $root = Get-PPScanRoot 'o7-random-good'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content 'function Invoke-PPGate { $r = [System.Random]::new(); $r.Next(0, 5) }'
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches System.Random outside 35-Gate.ps1' {
        $root = Get-PPScanRoot 'o7-random-bad'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { [System.Random]::new() }'
        $result = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.TypeAllowlist'
    }
}

Describe 'PortProof.Static.ScriptBlockParameterConstraint ([scriptblock] only on Invoke-PPGate''s $OnAdmitted)' -Tag 'Portable' {

    It 'allows [scriptblock] as the TypeConstraintAst on Invoke-PPGate''s $OnAdmitted parameter' {
        $root = Get-PPScanRoot 'o7-sb-param-good'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content 'function Invoke-PPGate { param([scriptblock] $OnAdmitted) }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches [scriptblock] as a type constraint on a different parameter of Invoke-PPGate' {
        $root = Get-PPScanRoot 'o7-sb-param-wrongparam'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content 'function Invoke-PPGate { param([scriptblock] $SomethingElse) }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.TypeAllowlist'
    }

    It 'catches [scriptblock] as a type constraint on OnAdmitted in a different function' {
        $root = Get-PPScanRoot 'o7-sb-param-wrongfunc'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content 'function Invoke-PPOther { param([scriptblock] $OnAdmitted) }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.TypeAllowlist'
    }

    It 'catches [scriptblock] as a type constraint on OnAdmitted in a different file' {
        $root = Get-PPScanRoot 'o7-sb-param-wrongfile'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function Invoke-PPGate { param([scriptblock] $OnAdmitted) }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.TypeAllowlist'
    }

    It 'catches a [scriptblock] cast, never allowed regardless of file (Find-PPScriptBlockConversionFinding, unaffected by the new allowance)' {
        $root = Get-PPScanRoot 'o7-sb-param-cast'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content 'function Invoke-PPGate { $x = [scriptblock]$y }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'ScriptBlockConversion'
    }

    It 'catches $x -as [scriptblock], never allowed regardless of file' {
        $root = Get-PPScanRoot 'o7-sb-param-as'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content 'function Invoke-PPGate { $x = $y -as [scriptblock] }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'ScriptBlockConversion|AsTypeCast'
    }

    It 'proves PowerShell does not convert a string argument to a [scriptblock] parameter (why the allowance is safe)' {
        # A functional check, not a static scan: demonstrates the design assumption behind the
        # narrow [scriptblock]-on-$OnAdmitted allowance actually holds at runtime.
        function Test-PPO7ScriptBlockParam { param([scriptblock] $OnAdmitted) $OnAdmitted }
        { Test-PPO7ScriptBlockParam -OnAdmitted 'Write-Output pwned' } | Should -Throw
        { [scriptblock] 'Write-Output pwned' } | Should -Throw
    }
}

Describe 'PortProof.Static.DynamicCommandAllowances (& $Resolver.Resolve, & $OnAdmitted)' -Tag 'Portable' {

    It 'allows & $Resolver.Resolve inside Resolve-PPProbeList in 30-Resolver.ps1' {
        $root = Get-PPScanRoot 'o7-resolver-dispatch-good'
        Write-PPFile -Root $root -Relative 'src\30-Resolver.ps1' -Content @'
function Resolve-PPProbeList {
    param([Parameter(Mandatory)] [pscustomobject] $Resolver)
    $returned = @(& $Resolver.Resolve 'name')
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches & $Resolver.Resolve outside Resolve-PPProbeList' {
        $root = Get-PPScanRoot 'o7-resolver-dispatch-wrongfunc'
        Write-PPFile -Root $root -Relative 'src\30-Resolver.ps1' -Content @'
function Get-PPOther {
    param([pscustomobject] $Resolver)
    & $Resolver.Resolve 'name'
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'DynamicCommand'
    }

    It 'catches & $Resolver.Resolve outside 30-Resolver.ps1' {
        $root = Get-PPScanRoot 'o7-resolver-dispatch-wrongfile'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Resolve-PPProbeList {
    param([pscustomobject] $Resolver)
    & $Resolver.Resolve 'name'
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'DynamicCommand'
    }

    It 'catches & $Resolver.SomethingElse (member must be literally .Resolve)' {
        $root = Get-PPScanRoot 'o7-resolver-dispatch-wrongmember'
        Write-PPFile -Root $root -Relative 'src\30-Resolver.ps1' -Content @'
function Resolve-PPProbeList {
    param([pscustomobject] $Resolver)
    & $Resolver.SomethingElse 'name'
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'DynamicCommand'
    }

    It 'allows & $OnAdmitted inside Invoke-PPGate in 35-Gate.ps1' {
        $root = Get-PPScanRoot 'o7-gate-dispatch-good'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content @'
function Invoke-PPGate {
    param($OnAdmitted)
    if ($null -ne $OnAdmitted) { $null = & $OnAdmitted 5 }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches & $OnAdmitted outside Invoke-PPGate' {
        $root = Get-PPScanRoot 'o7-gate-dispatch-wrongfunc'
        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content @'
function Get-PPOther {
    param($OnAdmitted)
    & $OnAdmitted 5
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'DynamicCommand'
    }

    It 'catches & $OnAdmitted outside 35-Gate.ps1' {
        $root = Get-PPScanRoot 'o7-gate-dispatch-wrongfile'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Invoke-PPGate {
    param($OnAdmitted)
    & $OnAdmitted 5
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'DynamicCommand'
    }

    It 'catches Invoke-PPGate called with -OnAdmitted bound to a variable instead of an inline literal' {
        $root = Get-PPScanRoot 'o7-gate-callsite-variable'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $cb = { param($n) }
    Invoke-PPGate -Resolution $r -Cap $c -Schedule $s -Adapters $a -OnAdmitted $cb
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match '-OnAdmitted on Invoke-PPGate not bound to an inline scriptblock literal'
    }

    It 'allows Invoke-PPGate called with -OnAdmitted as an inline literal' {
        $root = Get-PPScanRoot 'o7-gate-callsite-inline'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { Invoke-PPGate -Resolution $r -Cap $c -Schedule $s -Adapters $a -OnAdmitted { param($n) } }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }

    It 'allows Invoke-PPGate called without -OnAdmitted at all' {
        $root = Get-PPScanRoot 'o7-gate-callsite-omitted'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content 'function f { Invoke-PPGate -Resolution $r -Cap $c -Schedule $s -Adapters $a }'
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
    }
}

Describe 'PortProof.Static.AdapterNameSource (tightened adapter dispatch)' -Tag 'Portable' {

    It 'allows $AdapterName = [string]$item.AdapterName where $item loops over the function''s own $Queue parameter (the shape actually used)' {
        $root = Get-PPScanRoot 'o7-adaptername-itemshape'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-PPTargetQueue {
    param([object[]] $Queue, [string] $AdapterName)
    foreach ($item in $Queue) {
        $AdapterName = [string]$item.AdapterName
        & $AdapterName
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'allows $AdapterName = $Adapters[...] where $Adapters is the function''s own parameter (the literal index-access shape)' {
        $root = Get-PPScanRoot 'o7-adaptername-adapterindex'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-PPTargetQueue {
    param([object[]] $Queue, [hashtable] $Adapters, [string] $AdapterName)
    foreach ($item in $Queue) {
        $AdapterName = $Adapters[$item.Protocol]
        & $AdapterName
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches $AdapterName assigned from an untraced source' {
        $root = Get-PPScanRoot 'o7-adaptername-bad'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-PPTargetQueue {
    param([object[]] $Queue, [string] $AdapterName, [string] $Hint)
    foreach ($item in $Queue) {
        $AdapterName = $Hint
        & $AdapterName
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.AdapterNameSource'
    }

    It 'catches $AdapterName assigned from a loop over a parameter other than the function''s own' {
        $root = Get-PPScanRoot 'o7-adaptername-wrongloop'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Invoke-PPTargetQueue {
    param([object[]] $Queue, [string] $AdapterName)
    $other = @($Queue)
    foreach ($item in $other) {
        $AdapterName = [string]$item.AdapterName
        & $AdapterName
    }
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.AdapterNameSource'
    }
}

Describe 'PortProof.Static.ProviderDriveWriteTightening (Set-Item provider drives, System.Comparison casts)' -Tag 'Portable' {

    It 'catches Set-Item targeting the variable: drive' {
        $root = Get-PPScanRoot 'o7-drive-variable'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function f { Set-Item -Path 'variable:x' -Value 1 }"
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.ProviderDriveWrite'
    }

    It 'catches New-Item targeting the alias: drive' {
        $root = Get-PPScanRoot 'o7-drive-alias'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function f { New-Item -Path 'alias:zz' -Value 'Invoke-Expression' }"
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.ProviderDriveWrite'
    }

    It 'catches Set-Item targeting the env: drive' {
        $root = Get-PPScanRoot 'o7-drive-env'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content "function f { Set-Item -Path 'env:PATH' -Value 'x' }"
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.ProviderDriveWrite'
    }

    It 'still allows the one scoped function: drive write inside 40-Scheduler.ps1 (unaffected by the new provider-drive ban)' {
        $root = Get-PPScanRoot 'o7-drive-function-still-ok'
        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Get-PPWorkerDefinition { param([string[]] $Names) [ordered]@{} }
function Invoke-PPTargetQueue { param($Queue) }
function Invoke-ProbeSchedule {
    param($Queues, $Concurrency)
    $defs = Get-PPWorkerDefinition -Names @('Invoke-PPTargetQueue')
    $Queues | ForEach-Object -Parallel {
        foreach ($d in $using:defs.GetEnumerator()) {
            Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value
        }
        Invoke-PPTargetQueue
    } -ThrottleLimit $Concurrency
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'allows a [System.Comparison[object]] cast of an inline scriptblock literal' {
        $root = Get-PPScanRoot 'o7-comparison-good'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $rows = @()
    $rows.Sort([System.Comparison[object]] { param($a, $b) 0 })
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches a [System.Comparison[object]] cast of a variable' {
        $root = Get-PPScanRoot 'o7-comparison-bad'
        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function f {
    $cmp = { param($a, $b) 0 }
    $rows = @()
    $rows.Sort([System.Comparison[object]] $cmp)
}
'@
        $result = Invoke-PPScanner -Name 'Test-NoDynamicEval.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Posture.ComparisonCast'
    }
}

Describe 'PortProof.Static.ReadReceiverScope (.Read( scoped to a FileStream receiver in 10-Parser.ps1)' -Tag 'Portable' {

    It 'allows a FileStream-typed .Read( inside src/10-Parser.ps1 (the bounded profile read)' {
        $root = Get-PPScanRoot 'o8-read-parser-good'
        Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content @'
function Read-PPProfileText {
    param([System.IO.FileStream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $total = 0
    while ($total -lt $Limit) {
        $read = $Stream.Read($buffer, $total, $Limit - $total)
        if ($read -le 0) { break }
        $total += $read
    }
    $buffer
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'catches a NetworkStream-typed .Read( anywhere, including inside 10-Parser.ps1 (no exception for socket-backed streams)' {
        $root = Get-PPScanRoot 'o8-read-networkstream-bad'
        Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content @'
function Read-PPProfileText {
    param([System.Net.Sockets.NetworkStream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $read = $Stream.Read($buffer, 0, $Limit)
    $buffer
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'AC16\.BannerGrab'
        ($result.Output -join "`n") | Should -Match 'NetworkStream'
    }

    It 'catches a FileStream-typed .Read( in a file other than 10-Parser.ps1' {
        $root = Get-PPScanRoot 'o8-read-wrongfile-bad'
        Write-PPFile -Root $root -Relative 'src\77-Other.ps1' -Content @'
function Read-PPSomethingElse {
    param([System.IO.FileStream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $read = $Stream.Read($buffer, 0, $Limit)
    $buffer
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match "matched '\.Read\("
    }

    It 'catches .BeginRead(/.EndRead( on a Stream-typed receiver outside the adapters and outside 10-Parser.ps1 (instruction 3 gap-check)' {
        $root = Get-PPScanRoot 'o8-beginread-outside-bad'
        Write-PPFile -Root $root -Relative 'src\77-Other.ps1' -Content @'
function Read-PPSomethingElse {
    param([System.IO.Stream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $ar = $Stream.BeginRead($buffer, 0, $Limit, $null, $null)
    $read = $Stream.EndRead($ar)
    $buffer
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'BeginRead'
        ($result.Output -join "`n") | Should -Match 'EndRead'
    }

    It 'catches .BeginRead(/.EndRead( on a NetworkStream receiver even inside 10-Parser.ps1 (no adapter/parser exception for the async pair)' {
        $root = Get-PPScanRoot 'o8-beginread-parser-bad'
        Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content @'
function Read-PPProfileText {
    param([System.Net.Sockets.NetworkStream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $ar = $Stream.BeginRead($buffer, 0, $Limit, $null, $null)
    $read = $Stream.EndRead($ar)
    $buffer
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'BeginRead'
        ($result.Output -join "`n") | Should -Match 'EndRead'
    }
}

Describe 'PortProof.Static.DistPartMapping (dist/ line -> src file mapping)' -Tag 'Portable' {

    BeforeAll {
        # The real repo root (two levels up from tests/Static) and the real build script - not a
        # copy: build/Build-PortProof.ps1 is parameterized by -Root/-PartsFile/-OutFile, so it can
        # build a synthetic tree exactly as it builds the real one. This test never writes to
        # build/; it only reads/executes the script that already lives there.
        $script:DistMapRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
        $script:DistMapBuildScript = Join-Path $script:DistMapRepoRoot 'build\Build-PortProof.ps1'
        $script:DistMapScanners = @(
            'Test-ProbeProhibitions.ps1', 'Test-ResolverIsolation.ps1', 'Test-NoCredentials.ps1',
            'Test-NoOutbound.ps1', 'Test-NoDeferredFeatures.ps1', 'Test-NoDynamicEval.ps1',
            'Test-CallSites.ps1', 'Test-TemplateTokens.ps1', 'Test-WorkerClosure.ps1'
        )
    }

    It 'builds a real dist/PortProof.ps1 from a multi-part src/ tree and passes all 9 scanners with zero findings' {
        $root = Get-PPScanRoot 'distpartmap-dist-build'

        # A minimal but multi-file src/ tree exercising every file-scoped allowance the three
        # affected scanners own (Test-ProbeProhibitions, Test-ResolverIsolation, Test-NoDynamicEval):
        # SHA256/UnicodeEncoding/FileStream .Read( in 10-Parser.ps1; Dns + & $Resolver.Resolve in
        # 30-Resolver.ps1; Random + [scriptblock] $OnAdmitted + & $OnAdmitted in 35-Gate.ps1; Monitor
        # + Get-PPWorkerDefinition/SessionStateFunctionEntry + the function: write + & $AdapterName
        # dispatch in 40-Scheduler.ps1; the three adapters' scoped constructor types; and the
        # catch-only GetType().FullName read in 90-Main.ps1.
        Write-PPFile -Root $root -Relative 'build\parts.txt' -Content (@(
            'src/00-Header.ps1', 'src/10-Parser.ps1', 'src/30-Resolver.ps1', 'src/35-Gate.ps1',
            'src/40-Scheduler.ps1', 'src/50-Probe.Tcp.ps1', 'src/55-Probe.Udp.ps1',
            'src/58-Probe.Icmp.ps1', 'src/90-Main.ps1'
        ) -join "`n")

        Write-PPFile -Root $root -Relative 'src\00-Header.ps1' -Content "# header (dist-part-mapping fixture)`n"

        Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content @'
function Read-PPProfileText {
    param([System.IO.FileStream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $total = 0
    while ($total -lt $Limit) {
        $read = $Stream.Read($buffer, $total, $Limit - $total)
        if ($read -le 0) { break }
        $total += $read
    }
    $buffer
}

function Get-PPSha256Hex {
    param([byte[]] $Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
    } finally {
        $sha.Dispose()
    }
    $sb = [System.Text.StringBuilder]::new()
    foreach ($b in $hash) { [void] $sb.Append($b.ToString('x2')) }
    $sb.ToString()
}

function ConvertFrom-PPUtf16Text {
    param([byte[]] $Bytes)
    $enc = [System.Text.UnicodeEncoding]::new($false, $true)
    $enc.GetString($Bytes)
}
'@

        Write-PPFile -Root $root -Relative 'src\30-Resolver.ps1' -Content @'
function Resolve-PPName {
    param([string] $Name)
    [System.Net.Dns]::GetHostAddresses($Name)
}

function Resolve-PPProbeList {
    param([Parameter(Mandatory)] [pscustomobject] $Resolver)
    $returned = @(& $Resolver.Resolve 'name')
}
'@

        Write-PPFile -Root $root -Relative 'src\35-Gate.ps1' -Content @'
function Invoke-PPGate {
    param($Resolution, $Cap, $Schedule, $Adapters, [scriptblock] $OnAdmitted)
    $rand = [System.Random]::new()
    $jitter = $rand.Next(0, 5)
    if ($null -ne $OnAdmitted) { $null = & $OnAdmitted 5 }
}
'@

        Write-PPFile -Root $root -Relative 'src\40-Scheduler.ps1' -Content @'
function Wait-PPRateSlot {
    param([hashtable] $Rate)
    [System.Threading.Monitor]::Enter($Rate.SyncRoot)
    try {} finally { [System.Threading.Monitor]::Exit($Rate.SyncRoot) }
}

function Get-PPWorkerDefinition {
    param([string[]] $Names)
    [ordered]@{}
}

function Invoke-PPTargetQueue {
    param([object[]] $Queue, [string] $AdapterName)
    foreach ($item in $Queue) {
        $AdapterName = [string]$item.AdapterName
        & $AdapterName
    }
}

function Invoke-ProbeSchedule {
    param($Queues, $Concurrency)
    $defs = Get-PPWorkerDefinition -Names @('Invoke-PPTargetQueue')
    $entries = foreach ($d in $defs.GetEnumerator()) {
        [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($d.Key, $d.Value)
    }
    $Queues | ForEach-Object -Parallel {
        foreach ($d in $using:defs.GetEnumerator()) {
            Set-Item -LiteralPath ('function:' + $d.Key) -Value $d.Value
        }
        Invoke-PPTargetQueue
    } -ThrottleLimit $Concurrency
}
'@

        Write-PPFile -Root $root -Relative 'src\50-Probe.Tcp.ps1' -Content @'
function Invoke-TcpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $c = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
    $ar = $c.BeginConnect($Address, $Port, $null, $null)
    [void] $ar.AsyncWaitHandle.WaitOne($TimeoutMs)
    $c.Dispose()
}
'@

        Write-PPFile -Root $root -Relative 'src\55-Probe.Udp.ps1' -Content @'
function Invoke-UdpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $u = [System.Net.Sockets.UdpClient]::new($Address.AddressFamily)
    $u.Client.ReceiveTimeout = $TimeoutMs
    $u.Connect([System.Net.IPEndPoint]::new($Address, $Port))
    [void]$u.Send([byte[]]::new(0), 0)
    $remote = [System.Net.IPEndPoint]::new($Address, 0)
    [void]$u.Receive([ref] $remote)
}
'@

        Write-PPFile -Root $root -Relative 'src\58-Probe.Icmp.ps1' -Content @'
function Invoke-IcmpProbe {
    param([System.Net.IPAddress] $Address, [int] $Port, [int] $TimeoutMs)
    $p = [System.Net.NetworkInformation.Ping]::new()
    $r = $p.Send($Address, $TimeoutMs, [byte[]]::new(0))
}
'@

        Write-PPFile -Root $root -Relative 'src\90-Main.ps1' -Content @'
function Invoke-PortProof {
    Invoke-PPGate -Resolution $r -Cap $c -Schedule $s -Adapters $a -OnAdmitted { param($n) }
    try {
        Write-Output 'ok'
    } catch {
        $message = 'PortProof: internal error: {0}: {1}' -f $_.Exception.GetType().FullName, $_.Message
        Write-Error -Message $message
    }
}
'@

        $buildOutput = & $script:DistMapBuildScript -Root $root
        $buildExit = $LASTEXITCODE
        $buildExit | Should -Be 0 -Because "Build-PortProof.ps1 should build this fixture cleanly (output: $buildOutput)"
        (Join-Path $root 'dist\PortProof.ps1') | Should -Exist

        foreach ($name in $script:DistMapScanners) {
            $result = Invoke-PPScanner -Name $name -Root $root
            $result.ExitCode | Should -Be 0 -Because "$name should have zero findings against this compliant built dist/ (output: $($result.Output -join '; '))"
            $result.Output.Count | Should -Be 0
        }

        # --- planted-violation check: a banned construct appended into the ALREADY-BUILT dist/
        # copy must still be caught - proves the new per-part scoping narrows the old blanket dist/
        # exemption, it does not turn into a new one. ---
        $distPath = Join-Path $root 'dist\PortProof.ps1'
        $builtText = [System.IO.File]::ReadAllText($distPath)
        $planted = $builtText + "`nfunction Invoke-EvilProbe { `$s = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, [SocketType]::Raw, [ProtocolType]::Tcp) }`n"
        [System.IO.File]::WriteAllText($distPath, $planted, [System.Text.UTF8Encoding]::new($false))

        $probeResult = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $probeResult.ExitCode | Should -Be 1
        ($probeResult.Output -join "`n") | Should -Match 'AC16.RawSocket'

        $resolverResult = Invoke-PPScanner -Name 'Test-ResolverIsolation.ps1' -Root $root
        $resolverResult.ExitCode | Should -Be 1
        ($resolverResult.Output -join "`n") | Should -Match 'NewObjectBanned|TypeAllowlist'
    }

    It 'reports Static.DistPartMapMissing (not a silent allow) when dist/PortProof.ps1 has no build/parts.txt or banner at all' {
        $root = Get-PPScanRoot 'distpartmap-dist-nomap'
        # No build/parts.txt at all, and dist/PortProof.ps1 with no '# ---- src/... ----' banner -
        # exactly the "no reliable marker" case that is reported, not guessed through.
        Write-PPFile -Root $root -Relative 'src\10-Parser.ps1' -Content @'
function Read-PPProfileText {
    param([System.IO.FileStream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $read = $Stream.Read($buffer, 0, $Limit)
    $buffer
}
'@
        Write-PPFile -Root $root -Relative 'dist\PortProof.ps1' -Content @'
function Read-PPProfileText {
    param([System.IO.FileStream] $Stream, [int] $Limit)
    $buffer = [byte[]]::new($Limit)
    $read = $Stream.Read($buffer, 0, $Limit)
    $buffer
}
'@
        $result = Invoke-PPScanner -Name 'Test-ProbeProhibitions.ps1' -Root $root
        $result.ExitCode | Should -Be 1
        ($result.Output -join "`n") | Should -Match 'Static.DistPartMapMissing'
        # The FileStream .Read( in this un-mapped dist/ copy is ALSO still denied (falls back to the
        # dist leaf itself, which matches no scoped file name) and reported as its own
        # AC16.BannerGrab finding, on top of the missing-marker finding above - "report" never means
        # "and also silently allow through" for the rest of the scan.
        ($result.Output -join "`n") | Should -Match "AC16\.BannerGrab"
    }
}

Describe 'PortProof.Static.DistDriftGate (dist/PortProof.ps1 must be exactly a fresh build of src/)' -Tag 'Portable' {
    # AC2 calls dist/PortProof.ps1 "drift-gated" against src/, but nothing ever compared the
    # committed bytes to a real rebuild - only Build.Tests.ps1 (synthetic parts) and the
    # ProbeProhibitions/ResolverIsolation token-count-parity checks (one pattern's count, not the
    # whole file) touched this at all. This test closes that gap directly: it re-runs the real
    # build/Build-PortProof.ps1 against the real, current src/ tree (writing to a $TestDrive-scoped
    # temp path via an absolute -OutFile - never dist/ itself, and never build/) and byte-compares
    # the result to the committed dist/PortProof.ps1.
    # Skipped only when dist/ does not exist yet. This is expected to
    # fail while a src/ change and the committed dist/ are momentarily out of step
    # (e.g. before the next build); that is exactly what the test exists to surface, not a
    # bug in the test itself.

    BeforeAll {
        $script:DriftGateRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
        $script:DriftGateDistPath = Join-Path $script:DriftGateRepoRoot 'dist\PortProof.ps1'
        $script:DriftGateBuildScript = Join-Path $script:DriftGateRepoRoot 'build\Build-PortProof.ps1'
    }

    It 'byte-compares a fresh build of the real, current src/ to the committed dist/PortProof.ps1' {
        if (-not (Test-Path -LiteralPath $script:DriftGateDistPath -PathType Leaf)) {
            Set-ItResult -Skipped -Because 'dist/PortProof.ps1 does not exist yet; nothing to drift-check yet.'
            return
        }

        $freshOut = Join-Path $TestDrive 'fresh-build\PortProof.ps1'
        $buildOutput = & $script:DriftGateBuildScript -Root $script:DriftGateRepoRoot -OutFile $freshOut
        $buildExit = $LASTEXITCODE
        $buildExit | Should -Be 0 -Because "a fresh build of the real, current src/ tree should succeed (output: $buildOutput)"

        $freshBytes = [System.IO.File]::ReadAllBytes($freshOut)
        $committedBytes = [System.IO.File]::ReadAllBytes($script:DriftGateDistPath)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $freshHash = ([System.BitConverter]::ToString($sha256.ComputeHash($freshBytes))).Replace('-', '')
            $committedHash = ([System.BitConverter]::ToString($sha256.ComputeHash($committedBytes))).Replace('-', '')
        } finally {
            $sha256.Dispose()
        }
        $freshHash | Should -Be $committedHash -Because 'dist/PortProof.ps1 must always be exactly what build/Build-PortProof.ps1 produces from the current src/ (AC2 "drift-gated") - a mismatch means src/ changed since dist/ was last built and committed'
    }
}
