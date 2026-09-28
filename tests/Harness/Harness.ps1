# PortProof test harness - shared helper functions.
#
# Dot-sourced by every test file. Defines functions only; no top-level side effects other than
# the module-scoped loopback-address counter below (state, not an action). Loopback only: nothing
# in this file resolves a name, opens a socket, or reads any address outside 127.0.0.0/8.
#
# Get-PortProofPartPath and Get-PortProofBuiltPath are
# coded to the build/parts.txt format and Build-PortProof.ps1's -OutFile/
# -PartsFile/-Root signature, and throw a clear error if those files are ever missing; every other
# function here has no dependency on src/ at all.

$script:PPLoopbackCounter = 1

function Get-PPRepoRoot {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    (Resolve-Path (Join-Path $PSScriptRoot '..\..')).ProviderPath
}

function Get-PortProofPartPath {
    <#
        Reads build/parts.txt and returns the full paths it lists, in order, so
        tests dot-source the same set the build does. Blank and '#' lines are skipped. -Exclude
        takes leaf file names (e.g. '90-Main.ps1') to omit from the returned list.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([string[]] $Exclude = @())

    $root = Get-PPRepoRoot
    $partsFile = Join-Path $root 'build\parts.txt'
    if (-not (Test-Path -LiteralPath $partsFile)) {
        throw "PortProof test harness: build/parts.txt not found at '$partsFile'."
    }

    $relative = foreach ($line in (Get-Content -LiteralPath $partsFile)) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { continue }
        $trimmed
    }

    $relative |
        Where-Object { $Exclude -notcontains (Split-Path -Leaf $_) } |
        ForEach-Object { Join-Path $root ($_ -replace '/', '\') }
}

function Get-PortProofBuiltPath {
    <#
        Builds the tool once per test process (via build/Build-PortProof.ps1) to
        $env:TEMP\portproof-test-<pid>\PortProof.ps1, caching the path in
        $env:PORTPROOF_TEST_BUILT so repeated calls within the same process do not rebuild.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($env:PORTPROOF_TEST_BUILT -and (Test-Path -LiteralPath $env:PORTPROOF_TEST_BUILT)) {
        return $env:PORTPROOF_TEST_BUILT
    }

    $root = Get-PPRepoRoot
    $buildScript = Join-Path $root 'build\Build-PortProof.ps1'
    if (-not (Test-Path -LiteralPath $buildScript)) {
        throw "PortProof test harness: build/Build-PortProof.ps1 not found at '$buildScript'."
    }

    $outDir = Join-Path $env:TEMP ('portproof-test-{0}' -f $PID)
    if (-not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $outFile = Join-Path $outDir 'PortProof.ps1'

    & $buildScript -OutFile $outFile -Root $root | Out-Null
    if (-not (Test-Path -LiteralPath $outFile)) {
        throw "PortProof test harness: build did not produce '$outFile'."
    }

    $env:PORTPROOF_TEST_BUILT = $outFile
    return $outFile
}

function Invoke-PortProofInProcess {
    <#
        Calls Invoke-PortProof (05-Contract/90-Main) after the caller has already
        dot-sourced the parts it needs in its own BeforeAll (tests dot-source
        the returned paths themselves, never from inside a function, so Pester's scoping keeps the
        functions visible to `It` blocks).
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
    if ($PSBoundParameters.ContainsKey('Adapters'))     { $callParams.Adapters = $Adapters }
    if ($PSBoundParameters.ContainsKey('Recorder'))     { $callParams.Recorder = $Recorder }

    $exitCode = [ref] 0
    $success = $true
    $caught = @()
    try {
        Invoke-PortProof @callParams -ExitCode $exitCode -InformationVariable ppInfo -ErrorAction Stop
    } catch {
        $success = $false
        $caught = @($_)
    }

    [pscustomobject]@{
        PSTypeName  = 'PortProof.Test.InvocationResult'
        Success     = $success
        Information = @($ppInfo)
        Errors      = $caught
        ExitCode    = $exitCode.Value
    }
}

function Invoke-PortProofProcess {
    <#
        Runs the built dist script in a child process, either as `-File` or as
        `-Command "& ...; exit $LASTEXITCODE"` (Windows-tagged tests only: this starts a real
        process and is not a Portable-safe call).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string[]] $ArgumentList,
        [Parameter(Mandatory)] [ValidateSet('File', 'Command')] [string] $Entry,
        [ValidateSet('powershell', 'pwsh')] [string] $Shell = 'powershell'
    )

    $builtPath = Get-PortProofBuiltPath
    $exe = if ($Shell -eq 'pwsh') { 'pwsh' } else { 'powershell.exe' }

    switch ($Entry) {
        'File' {
            $procArgs = @('-NoProfile', '-NonInteractive', '-File', $builtPath) + $ArgumentList
        }
        'Command' {
            # A flag token (a bare '-Name' parameter name, e.g. '-Profile', '-AllowLarge') must
            # reach PowerShell unquoted: 90-Main.ps1's PositionalBinding = $false means a quoted
            # '-Profile' is just a string value, which then tries (and fails) to bind positionally,
            # so the -Command entry path only ever produced a binding error. Only
            # value tokens are single-quoted, with an embedded ' doubled to ''.
            $tokens = $ArgumentList | ForEach-Object {
                if ($_ -match '^-[A-Za-z_][A-Za-z0-9_]*$') {
                    $_
                } else {
                    "'" + ($_ -replace "'", "''") + "'"
                }
            }
            $cmd = "& '$builtPath' $($tokens -join ' '); exit `$LASTEXITCODE"
            $procArgs = @('-NoProfile', '-NonInteractive', '-Command', $cmd)
        }
    }

    $stdOutFile = [System.IO.Path]::GetTempFileName()
    $stdErrFile = [System.IO.Path]::GetTempFileName()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $proc = Start-Process -FilePath $exe -ArgumentList $procArgs -NoNewWindow -Wait -PassThru `
            -RedirectStandardOutput $stdOutFile -RedirectStandardError $stdErrFile
        $sw.Stop()
        [pscustomobject]@{
            PSTypeName = 'PortProof.Test.ProcessResult'
            StdOut     = (Get-Content -LiteralPath $stdOutFile -Raw -ErrorAction SilentlyContinue)
            StdErr     = (Get-Content -LiteralPath $stdErrFile -Raw -ErrorAction SilentlyContinue)
            ExitCode   = $proc.ExitCode
            ElapsedMs  = [int] $sw.Elapsed.TotalMilliseconds
        }
    } finally {
        Remove-Item -LiteralPath $stdOutFile, $stdErrFile -ErrorAction SilentlyContinue
    }
}

function Write-PPFixtureProfile {
    <#
        Writes a profile to disk from in-memory rows, for tests whose targets are ephemeral
        (listener ports cannot live in committed files). Row keys are matched case-insensitively
        against Source/Target/Port/Protocol/Required/Service/Notes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [hashtable[]] $Rows,
        [Parameter(Mandatory)] [ValidateSet('Csv', 'Json')] [string] $Format,
        [hashtable] $Groups,
        [Parameter(Mandatory)] [string] $Path
    )

    $columns = 'Source', 'Target', 'Port', 'Protocol', 'Required', 'Service', 'Notes'

    if ($Format -eq 'Csv') {
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add(($columns -join ','))
        foreach ($row in $Rows) {
            $fields = foreach ($col in $columns) {
                $key = $row.Keys | Where-Object { $_ -ieq $col } | Select-Object -First 1
                $value = if ($key) { [string] $row[$key] } else { '' }
                if ($value -match '[",\r\n]') { '"' + ($value -replace '"', '""') + '"' } else { $value }
            }
            $lines.Add(($fields -join ','))
        }
        $text = ($lines -join "`r`n") + "`r`n"
        [System.IO.File]::WriteAllText($Path, $text, [System.Text.UTF8Encoding]::new($false))
    } else {
        $rowObjects = foreach ($row in $Rows) {
            $ordered = [ordered]@{}
            foreach ($col in $columns) {
                $key = $row.Keys | Where-Object { $_ -ieq $col } | Select-Object -First 1
                if ($null -eq $key) { continue }
                $lower = $col.ToLowerInvariant()
                $ordered[$lower] = if ($col -eq 'Port') { [int] $row[$key] } else { [string] $row[$key] }
            }
            [pscustomobject] $ordered
        }
        $doc = [ordered]@{ schema = 'portproof-profile/1'; name = 'fixture' }
        if ($Groups) {
            $g = [ordered]@{}
            foreach ($k in $Groups.Keys) { $g[$k] = [string] $Groups[$k] }
            $doc.groups = $g
        }
        $doc.rows = @($rowObjects)
        $json = $doc | ConvertTo-Json -Depth 10
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
    }

    return $Path
}

function Write-PPOversizeGroupProfile {
    <#
        Writes a JSON profile whose one group value has more than MaxGroupItems (8192) comma
        items, for the oversize-group hostile case (Group.TooLarge). Generated at run time rather
        than committed: at the default item count this is only the item boundary itself, kept
        small and deterministic instead of shipping a much larger static blob than necessary.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [int] $ItemCount = 8193
    )

    $items = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $ItemCount; $i++) {
        if ($i -gt 0) { [void] $items.Append(',') }
        [void] $items.Append('h')
    }

    $doc = [ordered]@{
        schema = 'portproof-profile/1'
        name   = 'oversize-group'
        groups = [ordered]@{ BIG = $items.ToString() }
        rows   = @(
            [pscustomobject]@{
                source   = '%BIG%'
                target   = '127.0.0.1'
                port     = 80
                protocol = 'TCP'
                required = 'no'
            }
        )
    }
    $json = $doc | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
    return $Path
}

function Get-PPLoopbackAddress {
    <#
        Hands out distinct 127.0.0.2 .. 127.0.0.250 per test run (one call per listener/target
        needed; the pool is process-wide so parallel test files must not collide by design - each
        test file requests its own addresses at BeforeAll time).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $script:PPLoopbackCounter++
    if ($script:PPLoopbackCounter -gt 250) {
        throw 'PortProof test harness: loopback address pool (127.0.0.2-127.0.0.250) exhausted for this run.'
    }
    '127.0.0.{0}' -f $script:PPLoopbackCounter
}

function Test-PPOffHostOptIn {
    <#
        AC6: off-host, local-only timeout probes are opt-in and NOT-TESTABLE by
        default. True only when the operator explicitly asked for them.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    ($env:PORTPROOF_TEST_OFFHOST -eq '1') -or [bool] $env:PORTPROOF_TEST_TIMEOUT_TARGET
}
