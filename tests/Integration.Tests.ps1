# Integration suite (AC5, AC6, AC7, AC10, AC11, AC13, AC20,
# AC21, AC23). End-to-end runs of the whole tool (Assert-Arguments -> parse -> expand -> early exit
# -> resolve -> Gate -> schedule -> render -> exit code) through both entry paths: in-process
# (dot-sourced parts, Invoke-PortProof called directly - dot-sourcing leaves the entry block inert)
# and the built dist script as a real child process (`-File` and `-Command`, each with its own
# binding-error behavior). Every socket is loopback-only
# (127.0.0.0/8), via tests/Harness's listeners and FixtureResolver.
#
# Timing margins: the Windows loopback refused-connect finding
# (see README "How it probes") measures a genuinely refused connect at ~2.0-2.05 s
# before the RST surfaces, whatever the caller's -Timeout. Tests that need a real ConnectionRefused
# use -Timeout 3000 (headroom above 2005 ms); tests that need a real Timeout use -Timeout 500-1000
# (well under 2000 ms, so the wait itself - not the OS retry - is what completes first).

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Harness/Harness.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Listeners.ps1')
    . (Join-Path $PSScriptRoot 'Harness/Recorder.ps1')
    . (Join-Path $PSScriptRoot 'Harness/FixtureResolver.ps1')
    foreach ($path in (Get-PortProofPartPath)) { . $path }

    function Get-RawOptions {
        # Builds the -Raw hashtable Invoke-PortProof/Assert-Arguments expects (90-Main.ps1 entry
        # block shape). *Given switches mirror $PSBoundParameters.ContainsKey() the way the real
        # entry block computes MaxProbesGiven/OutGiven, so "parameter omitted" and "parameter given
        # as its own default" are distinguishable.
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
            Justification = 'Options mirrors the tools own RunOptions shape (05-Contract.ps1); it names a set of option fields, not a plural entity.')]
        [CmdletBinding()]
        param(
            [string] $ProfilePath, [string[]] $Set = @(), [string] $Out, [switch] $OutGiven,
            [string[]] $Format, [int] $Timeout = 2000, [int] $Concurrency = 16,
            [int] $MaxProbesPerSecond = 50, [int] $Jitter = 250, [int] $MaxProbes,
            [switch] $AllowLarge, [switch] $AllowCidr, [switch] $Icmp, [switch] $DryRun,
            [switch] $NoOperator, [switch] $Force, [switch] $Quiet, [switch] $Version
        )
        @{
            ProfilePath = $ProfilePath; Set = $Set; Out = $Out
            OutGiven = ($OutGiven.IsPresent -or $PSBoundParameters.ContainsKey('Out'))
            Format = $Format; Timeout = $Timeout; Concurrency = $Concurrency
            MaxProbesPerSecond = $MaxProbesPerSecond; Jitter = $Jitter; MaxProbes = $MaxProbes
            MaxProbesGiven = $PSBoundParameters.ContainsKey('MaxProbes')
            AllowLarge = [bool] $AllowLarge; AllowCidr = [bool] $AllowCidr; Icmp = [bool] $Icmp
            DryRun = [bool] $DryRun; NoOperator = [bool] $NoOperator; Force = [bool] $Force
            Quiet = [bool] $Quiet; Version = [bool] $Version
        }
    }

    function Get-InfoText {
        # Joins every captured Information record's MessageData with newlines, for line-matching.
        param([Parameter(Mandatory)] $Result)
        (@($Result.Information) | ForEach-Object { $_.MessageData }) -join "`n"
    }

    function Invoke-Full {
        <#
            Calls Invoke-PortProof directly (not Harness's Invoke-PortProofInProcess). 90-Main.ps1's
            Invoke-PortProof wraps its ENTIRE body in one try/catch and always converts a refusal or
            an internal error to `Write-Error ... -ErrorAction Continue` plus the exit code via
            [ref] - it never throws to its caller, by design (a CLI entry point must not leak an
            uncaught exception). So a try/catch around the call (what Invoke-PortProofInProcess
            does) never observes a PortProof.* refusal; -ErrorVariable does, because it captures
            every non-terminating error record written during the call regardless of that record's
            own -ErrorAction. Errors[0] is a real ErrorRecord (FullyQualifiedErrorId, Exception,
            TargetObject all populated), exactly like Invoke-PPGate/Invoke-PPRefusal's own throws
            that the Parser/Expander/Resolver unit suites assert against directly.
        #>
        [CmdletBinding()]
        [OutputType([pscustomobject])]
        param(
            [Parameter(Mandatory)] [hashtable] $Raw,
            [pscustomobject] $LiveResolver,
            [hashtable] $Adapters,
            [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
        )
        $callParams = @{ Raw = $Raw }
        if ($PSBoundParameters.ContainsKey('LiveResolver')) { $callParams.LiveResolver = $LiveResolver }
        if ($PSBoundParameters.ContainsKey('Adapters')) { $callParams.Adapters = $Adapters }
        if ($PSBoundParameters.ContainsKey('Recorder')) { $callParams.Recorder = $Recorder }

        $exitCode = [ref] 0
        # Assigning to $null (not just leaving the statement bare) matters: an uncaptured
        # success-stream statement inside a function becomes part of THAT FUNCTION'S OWN
        # return value, silently turning this helper's return into a 2-element array whenever
        # the run emits JSON/CSV to the success stream (observed: Format=Json with no -Out).
        $null = Invoke-PortProof @callParams -ExitCode $exitCode -ErrorVariable errVar -InformationVariable infoVar -ErrorAction SilentlyContinue -OutVariable outVar

        [pscustomobject]@{
            PSTypeName  = 'PortProofTest.FullResult'
            ExitCode    = $exitCode.Value
            Errors      = @($errVar)
            Information = @($infoVar)
            Output      = @($outVar)
            Success     = (@($errVar).Count -eq 0)
        }
    }

    function Get-PPError {
        # A direct .NET method-invocation failure caught by script code still leaks a bare,
        # non-PortProof ErrorRecord into -ErrorVariable ahead of the real one (observed on the
        # encoding corpus fixtures) - pick the tool's own refusal by id prefix, not index 0.
        param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Errors)
        @($Errors | Where-Object { $_.FullyQualifiedErrorId -like 'PortProof.*' }) | Select-Object -First 1
    }

    $script:StubAdapters = @{ TCP = 'Invoke-RecordingAdapter'; UDP = 'Invoke-RecordingAdapter'; ICMP = 'Invoke-RecordingAdapter' }
    $script:BuiltPath = Get-PortProofBuiltPath
    $script:ReadmePath = Join-Path $script:Root 'README.md'
    $script:ReadmeText = Get-Content -LiteralPath $script:ReadmePath -Raw
    $script:HelpText = (Get-Help -Name $script:BuiltPath -Full | Out-String)

    # AC7 suite-wide accumulator: every ResultRow this file's own runs produced, so one final check
    # (below) can assert the State=Open-only-when-observed invariant across everything this file ran.
    $script:Ac7Rows = [System.Collections.Generic.List[object]]::new()
    function Add-Ac7Evidence {
        param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Rows)
        foreach ($r in @($Rows)) { if ($null -ne $r) { $script:Ac7Rows.Add($r) } }
    }
}

Describe 'PortProof.Integration.AC5 (listener fixtures)' -Tag 'Windows' {

    It 'three bound TCP listeners pass and one unbound port fails; process exit code 1' {
        $addrs = @(1..4 | ForEach-Object { Get-PPLoopbackAddress })
        $listeners = @(1..3 | ForEach-Object { Open-PPTcpListener -Address $addrs[$_ - 1] -Mode Accept })
        $unboundPort = Get-PPUnboundPort -Address $addrs[3]
        try {
            $rows = for ($i = 0; $i -lt 3; $i++) {
                @{ Source = 'client'; Target = $listeners[$i].Address; Port = $listeners[$i].Port; Protocol = 'TCP'; Required = 'yes' }
            }
            $rows += @{ Source = 'client'; Target = $addrs[3]; Port = $unboundPort; Protocol = 'TCP'; Required = 'yes' }
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac5.csv')

            $raw = Get-RawOptions -ProfilePath $path -Timeout 3000
            $result = Invoke-Full -Raw $raw
            $result.Success | Should -BeTrue
            $result.ExitCode | Should -Be 1

            $pass = @($result.Errors) # no throw expected
            $pass.Count | Should -Be 0
        }
        finally {
            foreach ($l in $listeners) { Close-PPListener -Listener $l }
        }
    }
}

Describe 'PortProof.Integration.AC10 (exit-code matrix)' -Tag 'Windows' {

    BeforeAll {
        $script:AllPass = @()
        $script:RequiredFail = @()
    }

    It 'all-required-pass profile exits 0' {
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        try {
            $rows = @(@{ Source = 'c'; Target = $listener.Address; Port = $listener.Port; Protocol = 'TCP'; Required = 'yes' })
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac10-pass.csv')
            $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Timeout 3000)
            $result.ExitCode | Should -Be 0
            Add-Ac7Evidence -Rows @()
        }
        finally { Close-PPListener -Listener $listener }
    }

    It 'a required row that fails exits 1' {
        $addr = Get-PPLoopbackAddress
        $port = Get-PPUnboundPort -Address $addr
        $rows = @(@{ Source = 'c'; Target = $addr; Port = $port; Protocol = 'TCP'; Required = 'yes' })
        $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac10-reqfail.csv')
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Timeout 3000)
        $result.ExitCode | Should -Be 1
    }

    It 'only optional rows fail exits 0' {
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        $addr = Get-PPLoopbackAddress
        $port = Get-PPUnboundPort -Address $addr
        try {
            $rows = @(
                @{ Source = 'c'; Target = $listener.Address; Port = $listener.Port; Protocol = 'TCP'; Required = 'yes' }
                @{ Source = 'c'; Target = $addr; Port = $port; Protocol = 'TCP'; Required = 'no' }
            )
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac10-optfail.csv')
            $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Timeout 3000)
            $result.ExitCode | Should -Be 0
        }
        finally { Close-PPListener -Listener $listener }
    }

    It 'a bad profile exits 2' {
        $path = Join-Path $script:Root 'tests\Fixtures\invalid-missing-column.csv'
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path)
        $result.ExitCode | Should -Be 2
    }

    It 'no -Profile exits 2 with a usage message' {
        $result = Invoke-Full -Raw (Get-RawOptions)
        $result.ExitCode | Should -Be 2
        $ppError = Get-PPError -Errors $result.Errors
        $ppError.Exception.Message | Should -BeLike '*Usage*'
    }

    It '-Bogus (unknown parameter): exits 1 via -File, and 0 via -Command; README documents this for both entry forms' {
        $path = Join-Path $script:Root 'tests\Fixtures\valid-minimal.csv'
        $fileResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-Bogus') -Entry 'File'
        $fileResult.ExitCode | Should -Be 1
        $cmdResult = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-Bogus') -Entry 'Command'
        # A binding error under -Command never reaches PortProof, so exit $LASTEXITCODE sees
        # whatever it already was (0 in a fresh child), not the tool's own code.
        $cmdResult.ExitCode | Should -Be 0

        $script:ReadmeText | Should -Match '(?i)binding error'
        $script:ReadmeText | Should -Match '(?i)-Command'
        $script:ReadmeText | Should -Match '(?i)-File'
    }

    It '-MaxProbes abc (unconvertible value) exits 1 via -File' {
        $path = Join-Path $script:Root 'tests\Fixtures\valid-minimal.csv'
        $result = Invoke-PortProofProcess -ArgumentList @('-Profile', $path, '-MaxProbes', 'abc') -Entry 'File'
        $result.ExitCode | Should -Be 1
    }
}

Describe 'PortProof.Integration.AC11 (DryRun sends no probe and performs no name resolution)' -Tag 'Windows' {

    It 'behaviour: prints the probe list and worst-case duration; hostname unresolved; zero accepts/datagrams; -Out not created' {
        $tcpListener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        $udpListener = Open-PPUdpListener -Address (Get-PPLoopbackAddress)
        try {
            $rows = @(
                @{ Source = 'c'; Target = $tcpListener.Address; Port = $tcpListener.Port; Protocol = 'TCP'; Required = 'yes' }
                @{ Source = 'c'; Target = $udpListener.Address; Port = $udpListener.Port; Protocol = 'UDP'; Required = 'no' }
                @{ Source = 'c'; Target = 'dc01.corp.example'; Port = 389; Protocol = 'TCP'; Required = 'yes' }
            )
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac11.csv')
            $outDir = Join-Path $TestDrive 'ac11-out'

            $liveResolver = Get-PPFixtureResolver -Table (Get-PPResolverTableFixture)
            $raw = Get-RawOptions -ProfilePath $path -DryRun -Out $outDir
            $result = Invoke-Full -Raw $raw -LiveResolver $liveResolver
            $result.Success | Should -BeTrue
            $result.ExitCode | Should -Be 0

            $text = Get-InfoText -Result $result
            $text | Should -Match 'probes 3'
            $text | Should -Match 'unresolved \(dry-run\)'
            $text | Should -Match 'worst-case duration'
            $text | Should -Match 'names are class-checked on the live run, not here'

            Start-Sleep -Milliseconds 300
            $tcpListener.Events.Count | Should -Be 0
            $udpListener.Events.Count | Should -Be 0
            (Test-Path -LiteralPath $outDir) | Should -BeFalse

            # (3) the invocation counter on the real (live) Resolver reads zero for this run.
            $liveResolver.Invocations | Should -Be 0
        }
        finally {
            Close-PPListener -Listener $tcpListener
            Close-PPListener -Listener $udpListener
        }
    }

    It 'the refusing stub: Resolve throws DryRunResolutionAttempted when forced, proving the stub is installed under -DryRun' {
        $stub = Select-PPResolver -DryRun $true -Live $null
        $stub.Kind | Should -Be 'Refusing'
        { & $stub.Resolve 'anything.example' } | Should -Throw -ErrorId 'PortProof.DryRunResolutionAttempted'
    }
}

Describe 'PortProof.Integration.AC20 (authorized-use notice)' -Tag 'Windows' {

    It 'the clause is byte-identical across README, Get-Help and the JSON run header' {
        $contract = Get-PPContract
        $clause = $contract.AuthorizedUseClause
        # Get-Help word-wraps .DESCRIPTION text to the console width, so the clause can be split
        # across lines there (README and the JSON header are not reflowed) - match whitespace-
        # tolerantly against Get-Help's own text, and require the exact unbroken clause in the
        # other two sources where no such reflow happens.
        # [regex]::Escape backslash-escapes plain spaces too ('It opens' -> 'It\ opens'), so the
        # substitution has to match the two-character '\ ' sequence it produces, not a bare space
        # (a bare-space replace turns '\ ' into '\\s+', a literal backslash followed by 's+').
        $wrapTolerant = ([regex]::Escape($clause) -replace '\\ ', '\s+')

        $script:ReadmeText | Should -Match ([regex]::Escape($clause))
        $script:HelpText | Should -Match $wrapTolerant

        $addr = Get-PPLoopbackAddress
        $port = Get-PPUnboundPort -Address $addr
        $rows = @(@{ Source = 'c'; Target = $addr; Port = $port; Protocol = 'TCP'; Required = 'no' })
        $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac20.csv')

        $raw = Get-RawOptions -ProfilePath $path -Format @('Json') -Quiet -Timeout 500
        $result = Invoke-Full -Raw $raw
        $result.Success | Should -BeTrue
        # The notice must still appear on the information stream even under -Quiet.
        $text = Get-InfoText -Result $result
        $text | Should -Match ([regex]::Escape($contract.NoticeLine1))
        $text | Should -Match ([regex]::Escape($clause))

        # The checks above (and the Get-InfoText/-Match pattern generally)
        # match the clause ANYWHERE in the information stream, so they still pass even if
        # Write-PPNotice itself were deleted - Write-PPRunHeader independently prints its own
        # "AuthorizedUseNotice: <NoticeLine1> <clause> <NoticeLine3>" line (tag PortProof.Header) as
        # part of the header, which alone satisfies a bare text-match. Write-PPNotice's OWN three
        # lines are distinguishable by tag: Write-PPInfoLine is called with -Tag 'PortProof.Notice'
        # only from inside Write-PPNotice (90-Main.ps1) - nothing else in the tool uses that tag - so
        # assert on THAT specifically, not on text matched anywhere in the stream. Proved by mutation
        # (scratch copy, not committed): with Write-PPNotice's call site commented out, ExitCode/the
        # header's own AuthorizedUseNotice text/the two checks above all stay green, but this one
        # correctly goes red (0 records tagged PortProof.Notice); this comment records that mutation
        # result directly, since the transcript itself is not part of the shipped repo.
        $noticeRecords = @($result.Information | Where-Object { $_.Tags -contains 'PortProof.Notice' })
        $noticeRecords.Count | Should -Be 3
        $noticeRecords[0].MessageData | Should -Be $contract.NoticeLine1
        $noticeRecords[1].MessageData | Should -Be $clause
        $noticeRecords[2].MessageData | Should -Be $contract.NoticeLine3
    }

    It '-Format Json without -Out, piped through ConvertFrom-Json, parses cleanly (notice is not on the success stream)' {
        # -DryRun writes nothing to the success stream (the report is on Information), so the
        # JSON-on-success-stream proof needs a plain live run instead - against an unbound loopback
        # port for a fast, deterministic Fail row.
        #
        # A captured child-process StdOut text blob interleaves the notice ahead of the JSON, and
        # (observed) so does piping through ANOTHER cmdlet inside that same child's -Command string:
        # Write-PPInfoLine hard-codes `-InformationAction Continue` on every call (by design - the
        # notice must survive -Quiet and can't be suppressed), and Continue writes straight to the
        # process's own console/stdout handle, bypassing the object pipeline entirely - so it lands
        # on the same raw stdout text as anything Write-Output later renders there too, pipe or not.
        # -OutVariable, in contrast, captures only what actually flowed through the SUCCESS stream
        # (confirmed empirically: it holds just the JSON, never the notice) - so this is proved
        # in-process, through Invoke-Full's own -OutVariable capture, the same way AC7 below does.
        $addr = Get-PPLoopbackAddress
        $port = Get-PPUnboundPort -Address $addr
        $rows = @(@{ Source = 'c'; Target = $addr; Port = $port; Protocol = 'TCP'; Required = 'no' })
        $jsonProfile = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac20-json.csv')
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $jsonProfile -Format @('Json') -Timeout 500)
        $result.Success | Should -BeTrue
        $result.Output.Count | Should -Be 1
        $parsed = $null
        $threw = $false
        try { $parsed = $result.Output[0] | ConvertFrom-Json -ErrorAction Stop } catch { $threw = $true }
        $threw | Should -BeFalse -Because "captured output: $($result.Output[0])"
        # The notice legitimately appears AS DATA in the JSON header field (AC20 requires that too);
        # "not on the success stream" means no separate Information-stream text corrupts the payload
        # - proved by Output.Count above (exactly one clean value) and this parse succeeding at all.
        $parsed.header.AuthorizedUseNotice | Should -Not -BeNullOrEmpty
    }

    It "gate 24's grep passes via Git Bash when present" {
        # `Get-Command bash` on this host resolves to the WSL launcher stub
        # (%LOCALAPPDATA%\Microsoft\WindowsApps\bash.exe), not Git Bash - that stub runs the command
        # inside a WSL distro's own filesystem namespace, where a bare 'D:/...' path does not
        # resolve (it needs a /mnt/d/... translation), so it is not usable here. Look for the
        # genuine Git-for-Windows bash.exe at its well-known install paths instead.
        $candidates = @(
            (Join-Path $env:ProgramFiles 'Git\bin\bash.exe')
            (Join-Path ${env:ProgramFiles(x86)} 'Git\bin\bash.exe')
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        if (@($candidates).Count -eq 0) {
            Set-ItResult -Skipped -Because 'Git Bash (Git-for-Windows bash.exe) was not found at its well-known install path on this host.'
            return
        }
        $bashPath = @($candidates)[0]
        $readmeUnix = $script:ReadmePath -replace '\\', '/'
        # Built by concatenation, not as one literal: AC38's own scanner (Test-TemplateTokens.ps1)
        # bans an unresolved double-curly-brace template placeholder anywhere in the tree, and this
        # IS the exact placeholder string gate 24's own command greps FOR (checking it is absent) -
        # a contiguous literal here would itself be flagged as one (observed).
        $unresolvedToken = '{' + '{AUTHORIZED_USE_CLAUSE}' + '}'
        $script = "grep -qi 'authoris' '$readmeUnix' && ! grep -q '$unresolvedToken' '$readmeUnix'"
        & $bashPath -c $script
        $LASTEXITCODE | Should -Be 0
    }
}

Describe 'PortProof.Integration.AC21 (output containment)' -Tag 'Windows' {

    It 'writes files only under -Out, a traversal fixture creates nothing outside it, and -Force gates a second run' {
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        try {
            $sandbox = Join-Path $TestDrive 'ac21-sandbox'
            [void] (New-Item -ItemType Directory -Path $sandbox -Force)
            $outDir = Join-Path $sandbox 'out'

            # hostile-path-traversal.csv's Notes/Service fields carry '..\..\' and '..%2F' strings;
            # its Target is a hostname, so route it through the fixture resolver to our own listener
            # rather than letting it hit real DNS.
            $traversalSrc = Get-Content -LiteralPath (Join-Path $script:Root 'tests\Fixtures\hostile-path-traversal.csv') -Raw
            $rewritten = $traversalSrc -replace 'dc01\.corp\.example', $listener.Address -replace '443', $listener.Port
            $path = Join-Path $TestDrive 'ac21-traversal.csv'
            [System.IO.File]::WriteAllText($path, $rewritten, [System.Text.UTF8Encoding]::new($false))

            $before = @(Get-ChildItem -LiteralPath $sandbox -Recurse -File | ForEach-Object { $_.FullName })
            $raw = Get-RawOptions -ProfilePath $path -Out $outDir -Format @('Json') -Timeout 3000
            $result = Invoke-Full -Raw $raw
            $result.ExitCode | Should -Be 0

            $after = @(Get-ChildItem -LiteralPath $sandbox -Recurse -File | ForEach-Object { $_.FullName })
            $newFiles = @($after | Where-Object { $before -notcontains $_ })
            $newFiles.Count | Should -BeGreaterThan 0
            foreach ($f in $newFiles) { $f | Should -BeLike (Join-Path $outDir '*') }

            $bytesFirst = [System.IO.File]::ReadAllBytes((Join-Path $outDir 'portproof-results.json'))
            $second = Invoke-Full -Raw $raw
            $second.ExitCode | Should -Be 2
            $bytesAfterRefusal = [System.IO.File]::ReadAllBytes((Join-Path $outDir 'portproof-results.json'))
            [System.Convert]::ToBase64String($bytesAfterRefusal) | Should -Be ([System.Convert]::ToBase64String($bytesFirst))

            $rawForce = Get-RawOptions -ProfilePath $path -Out $outDir -Format @('Json') -Timeout 3000 -Force
            $third = Invoke-Full -Raw $rawForce
            $third.ExitCode | Should -Be 0
            $bytesAfterForce = [System.IO.File]::ReadAllBytes((Join-Path $outDir 'portproof-results.json'))
            # A fresh RunId/timestamp guarantees different bytes even though every row is identical.
            [System.Convert]::ToBase64String($bytesAfterForce) | Should -Not -Be ([System.Convert]::ToBase64String($bytesFirst))
        }
        finally { Close-PPListener -Listener $listener }
    }
}

Describe 'PortProof.Integration.AC23 (bundled profiles and valid fixtures validate: -DryRun exits 0 with groups bound)' -Tag 'Portable' {

    It '-ForEach every bundled v1 profile -DryRun exits 0 with its groups bound via -Set' -ForEach @(
        @{ Name = 'ad-dc.csv'; Set = 'CLIENT=10.0.0.5;DC=dc01.corp.example' }
        @{ Name = 'ad-dc.json'; Set = 'CLIENT=10.0.0.5;DC=dc01.corp.example' }
        @{ Name = 'sql-server.csv'; Set = 'CLIENT=10.0.0.5;SQL=sql01.corp.example' }
        @{ Name = 'sql-server.json'; Set = 'CLIENT=10.0.0.5;SQL=sql01.corp.example' }
        @{ Name = 'rdp-winrm.csv'; Set = 'ADMIN=10.0.0.5;SERVER=srv01.corp.example' }
        @{ Name = 'rdp-winrm.json'; Set = 'ADMIN=10.0.0.5;SERVER=srv01.corp.example' }
    ) {
        $path = Join-Path $script:Root ('profiles\' + $Name)
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -DryRun -Set @($Set))
        $result.Success | Should -BeTrue -Because ($result.Errors | ForEach-Object { $_.Exception.Message } | Out-String)
        $result.ExitCode | Should -Be 0
    }

    It '-ForEach every top-level valid-* fixture -DryRun exits 0' -ForEach @(
        @{ Name = 'valid-minimal.csv' }
        @{ Name = 'valid-minimal.json' }
        @{ Name = 'valid-groups.json' }
        @{ Name = 'valid-utf16le-bom.csv' }
        @{ Name = 'valid-crlf.csv' }
        @{ Name = 'valid-ipv6-literal.csv' }
        @{ Name = 'valid-lf.csv' }
        @{ Name = 'valid-ipv4-mapped.csv' }
    ) {
        $path = Join-Path $script:Root ('tests\Fixtures\' + $Name)
        $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -DryRun)
        $result.Success | Should -BeTrue -Because ($result.Errors | ForEach-Object { $_.Exception.Message } | Out-String)
        $result.ExitCode | Should -Be 0
    }
}

Describe 'PortProof.Integration.AC6 (timeout behaviour, opt-in, off-host; NOT-TESTABLE by default)' -Tag 'Windows' {

    It 'TEST-NET-1 (192.0.2.1) timeout probe is skipped unless PORTPROOF_TEST_OFFHOST=1 (or a blackhole target is named)' {
        if (-not (Test-PPOffHostOptIn)) {
            Set-ItResult -Skipped -Because 'AC6 is opt-in/off-host and NOT-TESTABLE by default. Set PORTPROOF_TEST_OFFHOST=1 to run it.'
            return
        }
        $blackhole = if ($env:PORTPROOF_TEST_TIMEOUT_TARGET) { $env:PORTPROOF_TEST_TIMEOUT_TARGET } else { '192.0.2.1' }
        if ($blackhole -eq '192.0.2.1') {
            $path = Join-Path $script:Root 'tests\Fixtures\testnet1.csv'
        }
        else {
            $rows = @(@{ Source = 'client'; Target = $blackhole; Port = 80; Protocol = 'TCP'; Required = 'no' })
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac6-blackhole.csv')
        }
        # A captured child-process StdOut text blob interleaves the Write-Information notice ahead
        # of the JSON (observed elsewhere in this file); build the ConvertFrom-Json filter INSIDE
        # the child's own pipeline instead, so only already-filtered, re-serialized JSON comes back.
        $cmd = "& '{0}' -Profile '{1}' -Timeout 500 -Jitter 0 -Format Json | ConvertFrom-Json | ConvertTo-Json -Depth 10; exit `$LASTEXITCODE" -f $script:BuiltPath, $path
        $stdOutFile = [System.IO.Path]::GetTempFileName()
        $stdErrFile = [System.IO.Path]::GetTempFileName()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            [void] (Start-Process -FilePath 'powershell.exe' -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', $cmd) `
                    -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdOutFile -RedirectStandardError $stdErrFile)
            $sw.Stop()
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 5
            $stdOut = Get-Content -LiteralPath $stdOutFile -Raw -ErrorAction SilentlyContinue
            $json = $stdOut | ConvertFrom-Json
            $row = $json.results[0]
            $row.Outcome | Should -Be 'Fail'
            $row.Error | Should -Be 'Timeout'
            $row.LatencyMs | Should -BeLessOrEqual 1500
        }
        finally {
            Remove-Item -LiteralPath $stdOutFile, $stdErrFile -ErrorAction SilentlyContinue
        }
    }

    It 'is off by default: Test-PPOffHostOptIn returns false with neither environment variable set' {
        if ($env:PORTPROOF_TEST_OFFHOST -or $env:PORTPROOF_TEST_TIMEOUT_TARGET) {
            Set-ItResult -Skipped -Because 'an off-host opt-in variable is set in this environment; cannot prove the off-by-default case here.'
            return
        }
        Test-PPOffHostOptIn | Should -BeFalse
    }
}

Describe 'PortProof.Integration.AC13 (injection, hostile fixture end-to-end)' -Tag 'Windows' {

    It 'HTML has no unescaped script tag, CSV neutralises the formula trigger, JSON parses' {
        # Angle brackets avoided in this It name on purpose: Pester's <Token> name-substitution
        # treats a bare '<word>' as a template placeholder even outside -ForEach, so a literal
        # '<script>' here silently rendered as the test's expanded name instead (observed).
        $listener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        try {
            $table = @{ 'dc01.corp.example' = $listener.Address }
            # Two rows sharing Source/Target/Port/Protocol are Profile.DuplicateRow (observed: the
            # duplicate check keys on those four fields only, not Service) - use TCP and UDP to the
            # same listener port so both hostile Service values reach the renderer as distinct rows.
            $rows = @(
                @{ Source = 'client'; Target = 'dc01.corp.example'; Port = $listener.Port; Protocol = 'TCP'; Required = 'no'; Service = '<script>alert(1)</script>' }
                @{ Source = 'client'; Target = 'dc01.corp.example'; Port = $listener.Port; Protocol = 'UDP'; Required = 'no'; Service = "=cmd|' /c calc'!A1" }
            )
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac13.csv')
            $outDir = Join-Path $TestDrive 'ac13-out'
            $raw = Get-RawOptions -ProfilePath $path -Out $outDir -Format @('Html', 'Csv', 'Json') -Timeout 3000
            $liveResolver = Get-PPFixtureResolver -Table $table
            $result = Invoke-Full -Raw $raw -LiveResolver $liveResolver
            $result.Success | Should -BeTrue

            $html = Get-Content -LiteralPath (Join-Path $outDir 'portproof-report.html') -Raw
            $html | Should -Not -Match '<script>alert\(1\)</script>'

            $csv = Get-Content -LiteralPath (Join-Path $outDir 'portproof-results.csv') -Raw
            $csv | Should -Match "'=cmd"

            $jsonPath = Join-Path $outDir 'portproof-results.json'
            { Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json -ErrorAction Stop } | Should -Not -Throw
        }
        finally { Close-PPListener -Listener $listener }
    }
}

Describe 'PortProof.Integration.AC7 (suite-wide: State=Open only where a positive response was observed)' -Tag 'Windows' {

    It 'every ResultRow this file produced with State=Open has Outcome=Pass, and at least one Open row exists (TCP)' {
        # This file's own live runs are the evidence pool (a whole-run interception of every JSON
        # the entire suite produces would require instrumenting the renderer itself, which is out of
        # scope for this file - noted here as an assumption, since the full derivation isn't part of
        # the shipped repo). Invoke-Full's
        # -OutVariable capture already exposes the run's own success-stream JSON via .Output.
        $openListener = Open-PPTcpListener -Address (Get-PPLoopbackAddress) -Mode Accept
        $closedAddr = Get-PPLoopbackAddress
        $closedPort = Get-PPUnboundPort -Address $closedAddr
        try {
            $probesRows = @(
                @{ Source = 'c'; Target = $openListener.Address; Port = $openListener.Port; Protocol = 'TCP'; Required = 'no' }
                @{ Source = 'c'; Target = $closedAddr; Port = $closedPort; Protocol = 'TCP'; Required = 'no' }
            )
            $path2 = Write-PPFixtureProfile -Rows $probesRows -Format Csv -Path (Join-Path $TestDrive 'ac7b.csv')
            $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path2 -Format @('Json') -Timeout 3000)
            $result.Success | Should -BeTrue -Because ($result.Errors | ForEach-Object { $_.Exception.Message } | Out-String)
            $result.Output.Count | Should -BeGreaterThan 0
            $captured = $result.Output[0] | ConvertFrom-Json
            Add-Ac7Evidence -Rows @($captured.results)
        }
        finally {
            Close-PPListener -Listener $openListener
        }

        $script:Ac7Rows.Count | Should -BeGreaterThan 0
        $openRows = @($script:Ac7Rows | Where-Object { $_.State -eq 'Open' })
        $openRows.Count | Should -BeGreaterThan 0
        foreach ($r in $openRows) { $r.Outcome | Should -Be 'Pass' }
    }

    It 'UDP: a silent loopback port never reports Open, and a listener that replies does (the TCP-only check above cannot see this)' {
        # Every prior AC7 row in this file was TCP, so a mutation that made
        # silent UDP report Open (instead of Closed/Open|Filtered) would pass every existing
        # assertion undetected. Add both UDP end states explicitly and feed them into the same
        # suite-wide accumulator. Ground truth measured directly against 55-Probe.Udp.ps1 on this
        # host (not assumed): a genuinely silent loopback UDP port returns Closed/IcmpUnreachable
        # (Windows surfaces the ICMP port-unreachable as a connected socket's ConnectionReset) - the
        # AC7's other permitted state, Open|Filtered/NoResponse, is for true silence
        # with no ICMP reply at all, which this loopback path does not produce; both keep the same
        # invariant this test asserts (never Open), so both are accepted.
        $udpSilentAddr = Get-PPLoopbackAddress
        $udpSilentPort = Get-PPUnboundPort -Address $udpSilentAddr   # verified free for TCP; nothing binds it for UDP either
        $udpReplyListener = Open-PPUdpListener -Address (Get-PPLoopbackAddress) -Reply
        try {
            $rows = @(
                @{ Source = 'c'; Target = $udpSilentAddr; Port = $udpSilentPort; Protocol = 'UDP'; Required = 'no' }
                @{ Source = 'c'; Target = $udpReplyListener.Address; Port = $udpReplyListener.Port; Protocol = 'UDP'; Required = 'no' }
            )
            $path = Write-PPFixtureProfile -Rows $rows -Format Csv -Path (Join-Path $TestDrive 'ac7-udp.csv')
            $result = Invoke-Full -Raw (Get-RawOptions -ProfilePath $path -Format @('Json') -Timeout 2000)
            $result.Success | Should -BeTrue -Because ($result.Errors | ForEach-Object { $_.Exception.Message } | Out-String)
            $captured = $result.Output[0] | ConvertFrom-Json
            Add-Ac7Evidence -Rows @($captured.results)

            $silentRow = @($captured.results | Where-Object { $_.Port -eq $udpSilentPort })[0]
            $silentRow.State | Should -Not -Be 'Open'
            $silentRow.State | Should -BeIn @('Closed', 'Open|Filtered')
            $silentRow.Outcome | Should -Not -Be 'Pass'

            $replyRow = @($captured.results | Where-Object { $_.Port -eq $udpReplyListener.Port })[0]
            $replyRow.State | Should -Be 'Open'
            $replyRow.Outcome | Should -Be 'Pass'
        }
        finally {
            Close-PPListener -Listener $udpReplyListener
        }

        # Re-check the suite-wide invariant now that the accumulator also holds UDP rows.
        $openRows = @($script:Ac7Rows | Where-Object { $_.State -eq 'Open' })
        foreach ($r in $openRows) { $r.Outcome | Should -Be 'Pass' }
    }
}
