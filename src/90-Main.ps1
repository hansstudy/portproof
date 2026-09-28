# PortProof entry point: argument checks, orchestration, run header, DryRun report, output files,
# summary and exit code. Function definitions, then the guarded
# entry block, which is the last statement of the built script.

function Assert-Arguments {
    # Checks run in table order; the first failure throws PortProof.Argument.* /
    # PortProof.Output.NeedsOut (exit 2). Returns PortProof.RunOptions.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Name kept fixed on purpose; other functions call it by this exact name.')]
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [hashtable] $Raw, [Parameter(Mandatory)] [hashtable] $Contract)

    $inv = [cultureinfo]::InvariantCulture

    # 1. -Profile present.
    $profilePath = [string]$Raw['ProfilePath']
    if ([string]::IsNullOrWhiteSpace($profilePath)) {
        Invoke-PPRefusal -Code 'Argument.Missing' -Message ('-Profile is required. Usage: PortProof.ps1 -Profile <profile.csv|profile.json> ' +
            "[-Set 'NAME=VALUE;NAME=VALUE'] [-Out <directory>] [-Format Html,Csv,Json] [-DryRun]")
    }

    # 2. Extension.
    if ($profilePath -cnotmatch '\.([Cc][Ss][Vv]|[Jj][Ss][Oo][Nn])\z') {
        Invoke-PPRefusal -Code 'Argument.Set' -Message ("-Profile '{0}' must be a .csv or .json file." -f (Get-PPSafeText -Text $profilePath))
    }

    # 3. Format: comma lists, trimmed, closed set, duplicates collapse, canonical casing and order.
    $formatGiven = $false
    $requested = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    if ($null -ne $Raw['Format']) {
        foreach ($element in @($Raw['Format'])) {
            $formatGiven = $true
            foreach ($piece in ([string]$element).Split(',')) {
                $value = $piece.Trim()
                $match = $null
                foreach ($known in $Contract.Formats) {
                    if ($value -cmatch '\A[A-Za-z]+\z' -and [string]::Equals($value.ToLowerInvariant(), $known.ToLowerInvariant(), [System.StringComparison]::Ordinal)) { $match = $known }
                }
                if ($null -eq $match) {
                    Invoke-PPRefusal -Code 'Argument.Set' -Message ("-Format '{0}' is not one of Html, Csv, Json." -f (Get-PPSafeText -Text $value))
                }
                $requested[$match] = $true
            }
        }
    }
    $formats = [string[]]@($Contract.Formats | Where-Object { $requested.ContainsKey($_) })

    # 4. Ranges.
    $units = @{ Timeout = 'ms'; Concurrency = 'targets in flight'; MaxProbesPerSecond = 'probes per second'; Jitter = 'ms' }
    $values = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($name in @('Timeout', 'Concurrency', 'MaxProbesPerSecond', 'Jitter')) {
        $value = $Raw[$name]
        if ($null -eq $value) { $value = $Contract.Defaults[$name] }
        $value = [int]$value
        $lo = $Contract.Ranges[$name][0]
        $hi = $Contract.Ranges[$name][1]
        if ($value -lt $lo -or $value -gt $hi) {
            Invoke-PPRefusal -Code 'Argument.Range' -Message ('-{0} {1} is out of range; permitted {2}..{3} ({4}).' -f $name,
                $value.ToString($inv), $lo.ToString($inv), $hi.ToString($inv), $units[$name])
        }
        $values[$name] = $value
    }

    # 5. Ceiling and -MaxProbes.
    $allowLarge = [bool]$Raw['AllowLarge']
    $absolute = [int]$Contract.AbsoluteProbeCeiling
    $ceiling = if ($allowLarge) { $absolute } else { [int]$Contract.DefaultCeiling }
    $effectiveCap = $ceiling
    if ([bool]$Raw['MaxProbesGiven']) {
        $maxProbes = [int]$Raw['MaxProbes']
        if ($maxProbes -gt $absolute) {
            Invoke-PPRefusal -Code 'Argument.Cap' -Message ('-MaxProbes {0} exceeds the ceiling in force ({1}); no parameter raises it.' -f
                $maxProbes.ToString($inv), $absolute.ToString($inv))
        }
        if ($maxProbes -gt $ceiling) {
            Invoke-PPRefusal -Code 'Argument.Cap' -Message ('-MaxProbes {0} exceeds the ceiling in force ({1}); -AllowLarge raises the ceiling to {2}.' -f
                $maxProbes.ToString($inv), $ceiling.ToString($inv), $absolute.ToString($inv))
        }
        if ($maxProbes -lt 1) {
            Invoke-PPRefusal -Code 'Argument.Cap' -Message ('-MaxProbes {0} is out of range; permitted 1..{1}.' -f
                $maxProbes.ToString($inv), $ceiling.ToString($inv))
        }
        $effectiveCap = $maxProbes
    }

    # 6. -Set syntax (the value grammar belongs to the Expander).
    $bindings = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    if ($null -ne $Raw['Set']) {
        foreach ($element in @($Raw['Set'])) {
            foreach ($piece in ([string]$element).Split(';')) {
                if ($piece.Length -eq 0) { continue }
                if ($piece -cnotmatch '\A[A-Za-z][A-Za-z0-9_]{0,31}=.+\z') {
                    Invoke-PPRefusal -Code 'Argument.SetSyntax' -Message ("-Set '{0}' is not NAME=VALUE." -f (Get-PPSafeText -Text $piece))
                }
                $bindingName = $piece.Substring(0, $piece.IndexOf('=')).ToUpperInvariant()
                if ($seen.ContainsKey($bindingName)) {
                    Invoke-PPRefusal -Code 'Argument.SetSyntax' -Message ('-Set binds {0} twice.' -f $bindingName)
                }
                $seen[$bindingName] = $true
                $bindings.Add($piece)
            }
        }
    }

    # 7. Output combination (not under -DryRun, which writes nothing).
    # OutGiven comes from $PSBoundParameters in the entry block, so -Out '' / -Out "" (both entry
    # paths bind an empty string, measured on 5.1) is "given but empty" and hits row 8. In-process
    # callers without the key fall back to "non-empty means given".
    $outRaw = [string]$Raw['Out']
    if ($Raw.ContainsKey('OutGiven')) { $outGiven = [bool]$Raw['OutGiven'] } else { $outGiven = -not [string]::IsNullOrEmpty($outRaw) }
    $dryRun = [bool]$Raw['DryRun']
    if (-not $dryRun -and -not $outGiven -and $formatGiven -and ($formats -ccontains 'Html' -or $formats.Count -gt 1)) {
        Invoke-PPRefusal -Code 'Output.NeedsOut' -Message 'Html and multi-format output need -Out.'
    }

    # 8. -Out given but blank.
    if ($outGiven -and [string]::IsNullOrWhiteSpace($outRaw)) {
        Invoke-PPRefusal -Code 'Argument.Missing' -Message '-Out is empty.'
    }

    if ($outGiven) {
        if (-not $formatGiven) { $formats = [string[]]@($Contract.Formats) }
        $emit = 'Files'
        $outValue = $outRaw
    }
    else {
        $outValue = $null
        if ($formats.Count -eq 1 -and ($formats[0] -ceq 'Csv' -or $formats[0] -ceq 'Json')) { $emit = 'Stream' } else { $emit = 'None' }
    }

    [pscustomobject][ordered]@{
        PSTypeName         = 'PortProof.RunOptions'
        ProfilePath        = $profilePath
        Bindings           = [string[]]$bindings.ToArray()
        Out                = $outValue
        Formats            = $formats
        Emit               = $emit
        TimeoutMs          = $values['Timeout']
        Concurrency        = $values['Concurrency']
        MaxProbesPerSecond = $values['MaxProbesPerSecond']
        JitterMs           = $values['Jitter']
        Ceiling            = $ceiling
        EffectiveCap       = $effectiveCap
        AllowLarge         = $allowLarge
        AllowCidr          = [bool]$Raw['AllowCidr']
        Icmp               = [bool]$Raw['Icmp']
        DryRun             = $dryRun
        NoOperator         = [bool]$Raw['NoOperator']
        Force              = [bool]$Raw['Force']
        Quiet              = [bool]$Raw['Quiet']
    }
}

function Select-PPResolver {
    # -DryRun always gets the refusing stub, whatever -Live is.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([bool] $DryRun, [pscustomobject] $Live)

    if ($DryRun) { return Get-PPRefusingResolver }
    return $Live
}

function Write-PPInfoLine {
    # One line to the information stream, forced on, tagged; text passed through Get-PPSafeText.
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $Line, [Parameter(Mandatory)] [string] $Tag)

    Write-Information -MessageData (Get-PPSafeText -Text $Line -Max 4096) -InformationAction Continue -Tags $Tag
}

function Write-PPNotice {
    # The three authorized-use lines, information stream, tag PortProof.Notice.
    [CmdletBinding()]
    param()

    foreach ($line in (Get-PPAuthorizedUseNotice)) {
        Write-PPInfoLine -Line $line -Tag 'PortProof.Notice'
    }
}

function Resolve-PPFileSystemPath {
    # Resolves like the current PowerShell
    # location does (wildcards literal); a missing drive, an unknown provider or a non-FileSystem
    # provider is refused with $Code.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Code, [Parameter(Mandatory)] [string] $What)

    $provider = $null
    $drive = $null
    $full = $null
    $failure = $null
    try {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive)
    }
    catch {
        $failure = $_.Exception.GetType().Name
    }
    if ($null -ne $failure) {
        Invoke-PPRefusal -Code $Code -Message ("{0} '{1}' cannot be resolved to a file-system path (drive or provider not found)." -f $What, (Get-PPSafeText -Text $Path))
    }
    if ($null -eq $provider -or $provider.Name -cne 'FileSystem') {
        Invoke-PPRefusal -Code $Code -Message ("{0} '{1}' is not a file-system path." -f $What, (Get-PPSafeText -Text $Path))
    }
    return $full
}

function Measure-PPWorstCase {
    # Upper-bound estimate in whole seconds. Probes carry Target (pre-resolution)
    # or TargetIp (ExecProbe); ICMP is one extra probe per target.
    [CmdletBinding()]
    [OutputType([long])]
    param([AllowEmptyCollection()] [object[]] $Probes, [int] $IcmpTargets, $Options)

    $perProbeMs = [double]($Options.TimeoutMs + $Options.JitterMs)
    $counts = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $hostnames = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($probe in @($Probes)) {
        if ($null -eq $probe) { continue }
        $key = [string]$probe.Target
        if ($key.Length -eq 0) { $key = [string]$probe.TargetIp }
        if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
        if ([string]$probe.TargetKind -ceq 'Hostname') { $hostnames[$key] = $true }
    }
    $n = 0
    $sum = 0.0
    $max = 0.0
    foreach ($key in @($counts.Keys)) {
        $nt = $counts[$key]
        if ($IcmpTargets -gt 0) { $nt++ }
        $w = $nt * $perProbeMs
        $n += $nt
        $sum += $w
        if ($w -gt $max) { $max = $w }
    }
    $d = [double]$hostnames.Count * [double](Get-PPContract).ResolveTimeoutMs
    $rateMs = [double]$n * 1000.0 / [double]$Options.MaxProbesPerSecond
    $poolMs = ($sum / [double]$Options.Concurrency) + $max
    $totalMs = $d + [Math]::Max($rateMs, $poolMs)
    return [long][Math]::Ceiling($totalMs / 1000.0)
}

function ConvertTo-PPDuration {
    # Seconds -> hh:mm:ss (hours may exceed 24), invariant culture.
    [CmdletBinding()]
    [OutputType([string])]
    param([long] $Seconds)

    $h = [long][Math]::Floor($Seconds / 3600)
    $m = [long][Math]::Floor(($Seconds % 3600) / 60)
    $s = $Seconds % 60
    [string]::Format([cultureinfo]::InvariantCulture, '{0:00}:{1:00}:{2:00}', $h, $m, $s)
}

function Get-PPRunHeader {
    # PortProof.RunHeader, field order normative.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param($Options, $ProfileDocument, $Expansion, [int] $ProbeCount, [string] $Basis, [string] $ExecutionPath,
        [datetime] $StartedUtc, [string] $RunId, [long] $WorstCaseSeconds = 0)

    $contract = Get-PPContract
    $inv = [cultureinfo]::InvariantCulture
    if ($Options.NoOperator) {
        $user = 'redacted'
        $hostName = 'redacted'
    }
    else {
        $user = [Environment]::UserDomainName + '\' + [Environment]::UserName
        $hostName = [Environment]::MachineName
    }
    $utc = [datetime]::SpecifyKind($StartedUtc, [DateTimeKind]::Utc)
    # Under -NoOperator the local UTC offset is a location hint, so
    # StartedLocal takes the StartedUtc form ('Z').
    if ($Options.NoOperator) {
        $startedLocal = $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)
    }
    else {
        $startedLocal = $utc.ToLocalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffzzz', $inv)
    }
    $overrides = @()
    if ($null -ne $Expansion -and $null -ne $Expansion.GroupOverrides) { $overrides = @($Expansion.GroupOverrides) }
    $flags = [pscustomobject][ordered]@{
        PSTypeName         = 'PortProof.Flags'
        AllowLarge         = [bool]$Options.AllowLarge
        AllowCidr          = [bool]$Options.AllowCidr
        Icmp               = [bool]$Options.Icmp
        DryRun             = [bool]$Options.DryRun
        NoOperator         = [bool]$Options.NoOperator
        Force              = [bool]$Options.Force
        Quiet              = [bool]$Options.Quiet
        Ceiling            = [int]$Options.Ceiling
        EffectiveCap       = [int]$Options.EffectiveCap
        TimeoutMs          = [int]$Options.TimeoutMs
        Concurrency        = [int]$Options.Concurrency
        MaxProbesPerSecond = [int]$Options.MaxProbesPerSecond
        JitterMs           = [int]$Options.JitterMs
        GroupOverrides     = [string[]]$overrides
        ExecutionPath      = $ExecutionPath
    }
    $ignored = @()
    if ($null -ne $ProfileDocument.IgnoredColumns) { $ignored = @($ProfileDocument.IgnoredColumns) }
    [pscustomobject][ordered]@{
        PSTypeName          = 'PortProof.RunHeader'
        ToolVersion         = $contract.ToolVersion
        ProfileName         = [string]$ProfileDocument.Name
        ProfileVersion      = [string]$ProfileDocument.Version
        ProfileSha256       = [string]$ProfileDocument.Sha256
        RunId               = $RunId
        StartedUtc          = $utc.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)
        StartedLocal        = $startedLocal
        OperatorUser        = $user
        OperatorHost        = $hostName
        ProbeCount          = $ProbeCount
        Flags               = $flags
        IgnoredColumns      = [string[]]$ignored
        AuthorizedUseNotice = ((Get-PPAuthorizedUseNotice) -join ' ')
        OriginNote          = [string]::Format($inv, $contract.OriginNoteFormat, $hostName)
        ProbeCountBasis     = $Basis
        WorstCaseSeconds    = $WorstCaseSeconds
    }
}

function ConvertTo-PPInfoValue {
    # Header value -> one line of text: arrays joined with '; ', booleans lowercase, invariant numbers.
    [CmdletBinding()]
    [OutputType([string])]
    param($Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [array]) { return ((@($Value) | ForEach-Object { ConvertTo-PPInfoValue -Value $_ }) -join '; ') }
    if ($Value -is [System.IFormattable]) { return $Value.ToString($null, [cultureinfo]::InvariantCulture) }
    return [string]$Value
}

function Write-PPRunHeader {
    # Information stream, tag PortProof.Header; one "Field: value" line per field, Flags flattened.
    [CmdletBinding()]
    param($Header)

    # Literal member access only: no computed member names. The order is the
    # RunHeader and Flags field order of Get-PPShapeFields; Contract.Tests asserts they agree.
    $flags = $Header.Flags
    $pairs = @(
        @{ Name = 'ToolVersion'; Value = $Header.ToolVersion }
        @{ Name = 'ProfileName'; Value = $Header.ProfileName }
        @{ Name = 'ProfileVersion'; Value = $Header.ProfileVersion }
        @{ Name = 'ProfileSha256'; Value = $Header.ProfileSha256 }
        @{ Name = 'RunId'; Value = $Header.RunId }
        @{ Name = 'StartedUtc'; Value = $Header.StartedUtc }
        @{ Name = 'StartedLocal'; Value = $Header.StartedLocal }
        @{ Name = 'OperatorUser'; Value = $Header.OperatorUser }
        @{ Name = 'OperatorHost'; Value = $Header.OperatorHost }
        @{ Name = 'ProbeCount'; Value = $Header.ProbeCount }
        @{ Name = 'Flags.AllowLarge'; Value = $flags.AllowLarge }
        @{ Name = 'Flags.AllowCidr'; Value = $flags.AllowCidr }
        @{ Name = 'Flags.Icmp'; Value = $flags.Icmp }
        @{ Name = 'Flags.DryRun'; Value = $flags.DryRun }
        @{ Name = 'Flags.NoOperator'; Value = $flags.NoOperator }
        @{ Name = 'Flags.Force'; Value = $flags.Force }
        @{ Name = 'Flags.Quiet'; Value = $flags.Quiet }
        @{ Name = 'Flags.Ceiling'; Value = $flags.Ceiling }
        @{ Name = 'Flags.EffectiveCap'; Value = $flags.EffectiveCap }
        @{ Name = 'Flags.TimeoutMs'; Value = $flags.TimeoutMs }
        @{ Name = 'Flags.Concurrency'; Value = $flags.Concurrency }
        @{ Name = 'Flags.MaxProbesPerSecond'; Value = $flags.MaxProbesPerSecond }
        @{ Name = 'Flags.JitterMs'; Value = $flags.JitterMs }
        @{ Name = 'Flags.GroupOverrides'; Value = $flags.GroupOverrides }
        @{ Name = 'Flags.ExecutionPath'; Value = $flags.ExecutionPath }
        @{ Name = 'IgnoredColumns'; Value = $Header.IgnoredColumns }
        @{ Name = 'AuthorizedUseNotice'; Value = $Header.AuthorizedUseNotice }
        @{ Name = 'OriginNote'; Value = $Header.OriginNote }
        @{ Name = 'ProbeCountBasis'; Value = $Header.ProbeCountBasis }
        @{ Name = 'WorstCaseSeconds'; Value = $Header.WorstCaseSeconds }
    )
    foreach ($pair in $pairs) {
        Write-PPInfoLine -Line ('{0}: {1}' -f $pair.Name, (ConvertTo-PPInfoValue -Value $pair.Value)) -Tag 'PortProof.Header'
    }
}

function Write-PPDryRunReport {
    # Header block, one line per ExpandedRow, then the counts and estimates.
    [CmdletBinding()]
    param($Options, $ProfileDocument, $Expansion, $Header)

    $inv = [cultureinfo]::InvariantCulture
    $tag = 'PortProof.DryRun'
    Write-PPRunHeader -Header $Header
    Write-PPInfoLine -Line ("dry run of profile '{0}' ({1}); nothing is resolved or sent" -f (Get-PPSafeText -Text ([string]$ProfileDocument.Name)),
        (Get-PPSafeText -Text ([string]$ProfileDocument.FileName))) -Tag $tag

    $probeByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($probe in @($Expansion.Probes)) { if ($null -ne $probe) { $probeByKey[[string]$probe.ProbeKey] = $probe } }
    foreach ($row in @($Expansion.Rows)) {
        if ($null -eq $row) { continue }
        $probe = $probeByKey[[string]$row.ProbeKey]
        $where = 'unresolved (dry-run)'
        if ($null -ne $probe -and $null -ne $probe.Address) {
            $where = (ConvertTo-CanonicalAddress -Address $probe.Address).ToString()
        }
        $line = 'row {0}  {1} -> {2}  {3}/{4}  {5}  {6}' -f ([int]$row.Row).ToString($inv), (Get-PPSafeText -Text ([string]$row.SourceName)),
            (Get-PPSafeText -Text ([string]$row.TargetName)), $row.Protocol, ([int]$row.Port).ToString($inv), $row.Required, $where
        Write-PPInfoLine -Line $line -Tag $tag
    }

    $nPre = @($Expansion.Probes | Where-Object { $null -ne $_ }).Count
    Write-PPInfoLine -Line ('probes {0} (one connection attempt each; name coalescing may lower this on a live run)' -f $nPre.ToString($inv)) -Tag $tag
    $icmp = 0
    if ($Options.Icmp) {
        $icmp = [int]$Expansion.DistinctTargets
        Write-PPInfoLine -Line ('icmp echoes {0} (upper bound)' -f $icmp.ToString($inv)) -Tag $tag
    }
    $names = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($probe in @($Expansion.Probes)) { if ($null -ne $probe -and $probe.TargetKind -ceq 'Hostname') { $names[[string]$probe.Target] = $true } }
    $resolveMs = [long](Get-PPContract).ResolveTimeoutMs
    $resolveSeconds = [long][Math]::Ceiling(($names.Count * $resolveMs) / 1000.0)
    Write-PPInfoLine -Line ('name resolution up to {0} ({1} names x {2} ms, included below)' -f (ConvertTo-PPDuration -Seconds $resolveSeconds),
        $names.Count.ToString($inv), $resolveMs.ToString($inv)) -Tag $tag
    Write-PPInfoLine -Line ('worst-case duration {0} (estimate)' -f (ConvertTo-PPDuration -Seconds ([long]$Header.WorstCaseSeconds))) -Tag $tag
    Write-PPInfoLine -Line 'names are class-checked on the live run, not here' -Tag $tag
}

function Test-PPReparsePoint {
    # True when $Path exists as a reparse point (symlink or junction, dangling or not). The
    # attributes are those of the link itself; nothing is followed.
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Path)

    # No exception on the normal path: a caught .NET exception still lands in a caller's
    # -ErrorVariable. The entry is looked up in its parent directory listing (which does not
    # follow links, so a dangling link is found); then File.GetAttributes reads the entry's own
    # attributes (0x400 = FileAttributes.ReparsePoint).
    $trimmed = $Path.TrimEnd([char]'\', [char]'/')
    if ($trimmed.Length -eq 0) { return $false }
    $parent = [System.IO.Path]::GetDirectoryName($trimmed)
    $leaf = [System.IO.Path]::GetFileName($trimmed)
    if ([string]::IsNullOrEmpty($parent) -or [string]::IsNullOrEmpty($leaf)) { return $false }
    if (-not [System.IO.Directory]::Exists($parent)) { return $false }
    if (@([System.IO.Directory]::GetFileSystemEntries($parent, $leaf)).Count -eq 0) { return $false }
    $attributes = [int][System.IO.File]::GetAttributes($trimmed)
    return (($attributes -band 0x400) -ne 0)
}

function Assert-PPNoReparsePoint {
    # A symlink or junction planted in -Out would redirect the write.
    # Refuses -Out itself or an output path that is a reparse point; writes nothing.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $What)

    if (Test-PPReparsePoint -Path $Path) {
        Invoke-PPRefusal -Code 'Output.ReparsePoint' -Message ("{0} '{1}' is a symbolic link or junction; PortProof does not write through reparse points. Remove it or choose another -Out." -f
            $What, (Get-PPSafeText -Text $Path))
    }
}

function Test-PPOutputPreflight {
    # Creates nothing. Returns the resolved directory and file paths.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param($Options)

    $contract = Get-PPContract
    $directory = Resolve-PPFileSystemPath -Path $Options.Out -Code 'Output.NotDirectory' -What '-Out'
    Assert-PPNoReparsePoint -Path $directory -What '-Out'
    if ([System.IO.File]::Exists($directory)) {
        Invoke-PPRefusal -Code 'Output.NotDirectory' -Message ("-Out '{0}' exists and is not a directory." -f (Get-PPSafeText -Text $directory))
    }
    $files = [ordered]@{}
    foreach ($format in @($Options.Formats)) {
        $path = [System.IO.Path]::Combine($directory, $contract.OutputFileNames[$format])
        Assert-PPNoReparsePoint -Path $path -What 'output file'
        if ([System.IO.Directory]::Exists($path)) {
            Invoke-PPRefusal -Code 'Output.Collision' -Message ("'{0}' exists as a directory; remove it or choose another -Out." -f (Get-PPSafeText -Text $path))
        }
        if ([System.IO.File]::Exists($path) -and -not $Options.Force) {
            Invoke-PPRefusal -Code 'Output.Collision' -Message ("'{0}' already exists; use -Force to overwrite it or choose another -Out." -f (Get-PPSafeText -Text $path))
        }
        $files[$format] = $path
    }
    [pscustomobject][ordered]@{ PSTypeName = 'PortProof.OutputPlan'; Directory = $directory; Files = $files }
}

function Write-PPOutputFile {
    # UTF-8, BOM only when asked (CSV). CreateNew unless -Force.
    [CmdletBinding()]
    param([string] $Path, [string] $Text, [bool] $Bom, [bool] $Force)

    # Re-checked here, immediately before the open, for the file and its parent (-Out).
    Assert-PPNoReparsePoint -Path ([System.IO.Path]::GetDirectoryName($Path)) -What '-Out'
    Assert-PPNoReparsePoint -Path $Path -What 'output file'
    $encoding = [System.Text.UTF8Encoding]::new($false)
    $body = $encoding.GetBytes($Text)
    $mode = if ($Force) { [System.IO.FileMode]::Create } else { [System.IO.FileMode]::CreateNew }
    $stream = [System.IO.File]::Open($Path, $mode, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        if ($Bom) { $stream.Write([byte[]](0xEF, 0xBB, 0xBF), 0, 3) }
        $stream.Write($body, 0, $body.Length)
    }
    finally {
        $stream.Dispose()
    }
}

function Join-PPResults {
    # ProbeResult -> ResultRow. One row per ExpandedRow; DnsFailure entries become
    # rows with State '' and Error 'DnsFailure'; ICMP rows last. Rows are never dropped.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'Name kept fixed on purpose; other functions call it by this exact name.')]
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param($Expansion, $Resolution, $GateResult, [string] $RunId, [string] $ResolvedTimestamp = '')

    $byExecKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($result in @($GateResult.Results)) { if ($null -ne $result) { $byExecKey[[string]$result.ExecKey] = $result } }

    $rows = [System.Collections.Generic.List[object]]::new()
    $firstNameByIp = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($row in @($Expansion.Rows)) {
        if ($null -eq $row) { continue }
        $entry = $Resolution.Entries[[string]$row.ProbeKey]
        $targetIp = ''
        $resolved = [string[]]@()
        $state = ''
        $errorName = 'ProbeError'
        $latency = $null
        $timestamp = $ResolvedTimestamp
        if ($null -ne $entry -and $entry.Failed) {
            $errorName = 'DnsFailure'
        }
        elseif ($null -ne $entry -and $null -ne $entry.TargetIp) {
            $targetIp = $entry.TargetIp.ToString()
            $resolved = [string[]]@($entry.ResolvedAddresses)
            if (-not $firstNameByIp.ContainsKey($targetIp)) { $firstNameByIp[$targetIp] = [string]$row.TargetName }
            $execKey = '{0}|{1}|{2}' -f $targetIp, ([int]$row.Port).ToString([cultureinfo]::InvariantCulture), $row.Protocol
            $result = $byExecKey[$execKey]
            if ($null -ne $result) {
                $state = [string]$result.State
                $errorName = [string]$result.ErrorName
                $latency = $result.LatencyMs
                $timestamp = [string]$result.Timestamp
            }
        }
        $rows.Add([pscustomobject][ordered]@{
                PSTypeName        = 'PortProof.ResultRow'
                RunId             = $RunId
                Timestamp         = $timestamp
                SourceName        = [string]$row.SourceName
                SourceIp          = [string]$row.SourceIp
                TargetName        = [string]$row.TargetName
                TargetIp          = $targetIp
                ResolvedAddresses = $resolved
                Port              = [int]$row.Port
                Protocol          = [string]$row.Protocol
                Service           = [string]$row.Service
                Required          = [string]$row.Required
                Outcome           = (Get-PPOutcome -Protocol ([string]$row.Protocol) -State $state -ErrorName $errorName)
                State             = $state
                LatencyMs         = $latency
                Error             = $errorName
                ProfileRow        = [int]$row.Row
                SourceGroup       = [string]$row.SourceGroup
                TargetGroup       = [string]$row.TargetGroup
                Notes             = [string]$row.Notes
            })
    }

    $icmpRows = [System.Collections.Generic.List[object]]::new()
    foreach ($result in @($GateResult.Results)) {
        if ($null -eq $result -or $result.Protocol -cne 'ICMP') { continue }
        $ip = [string]$result.TargetIp
        $icmpRows.Add([pscustomobject][ordered]@{
                PSTypeName        = 'PortProof.ResultRow'
                RunId             = $RunId
                Timestamp         = [string]$result.Timestamp
                SourceName        = '(operator host)'
                SourceIp          = ''
                TargetName        = [string]$firstNameByIp[$ip]
                TargetIp          = $ip
                ResolvedAddresses = [string[]]@($ip)
                Port              = 0
                Protocol          = 'ICMP'
                Service           = 'ICMP echo'
                Required          = 'no'
                Outcome           = [string]$result.Outcome
                State             = [string]$result.State
                LatencyMs         = $result.LatencyMs
                Error             = [string]$result.ErrorName
                ProfileRow        = 0
                SourceGroup       = ''
                TargetGroup       = ''
                Notes             = ''
            })
    }

    $rows.Sort([System.Comparison[object]] {
            param($a, $b)
            $c = $a.ProfileRow.CompareTo($b.ProfileRow)
            if ($c -eq 0) { $c = [string]::CompareOrdinal($a.SourceName, $b.SourceName) }
            if ($c -eq 0) { $c = [string]::CompareOrdinal($a.TargetName, $b.TargetName) }
            if ($c -eq 0) { $c = $a.Port.CompareTo($b.Port) }
            if ($c -eq 0) { $c = [string]::CompareOrdinal($a.Protocol, $b.Protocol) }
            return $c
        })
    $icmpRows.Sort([System.Comparison[object]] { param($a, $b) [string]::CompareOrdinal($a.TargetIp, $b.TargetIp) })
    $all = [System.Collections.Generic.List[object]]::new()
    $all.AddRange($rows)
    $all.AddRange($icmpRows)
    return , $all.ToArray()
}

function Get-PPSummary {
    # PortProof.Summary from the result rows.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([AllowEmptyCollection()] [object[]] $Rows, [long] $ElapsedMs)

    $pass = 0; $fail = 0; $inconclusive = 0; $requiredTotal = 0; $requiredNotPassed = 0
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        switch -CaseSensitive ($row.Outcome) {
            'Pass' { $pass++ }
            'Fail' { $fail++ }
            default { $inconclusive++ }
        }
        if ($row.Required -ceq 'yes') {
            $requiredTotal++
            if ($row.Outcome -cne 'Pass') { $requiredNotPassed++ }
        }
    }
    [pscustomobject][ordered]@{
        PSTypeName        = 'PortProof.Summary'
        Total             = @($Rows | Where-Object { $null -ne $_ }).Count
        Pass              = $pass
        Fail              = $fail
        Inconclusive      = $inconclusive
        RequiredTotal     = $requiredTotal
        RequiredNotPassed = $requiredNotPassed
        ExitCode          = (Get-PPExitCode -Rows @($Rows | Where-Object { $null -ne $_ }))
        ElapsedMs         = $ElapsedMs
    }
}

function Write-PPSummary {
    # Information stream, tag PortProof.Summary. Profile-derived text through Get-PPSafeText.
    [CmdletBinding()]
    param($ResultSet)

    $inv = [cultureinfo]::InvariantCulture
    $tag = 'PortProof.Summary'
    $s = $ResultSet.Summary
    Write-PPInfoLine -Line ('total {0}  pass {1}  fail {2}  inconclusive {3}' -f $s.Total.ToString($inv), $s.Pass.ToString($inv),
        $s.Fail.ToString($inv), $s.Inconclusive.ToString($inv)) -Tag $tag
    Write-PPInfoLine -Line ('required {0}  required not passed {1}' -f $s.RequiredTotal.ToString($inv), $s.RequiredNotPassed.ToString($inv)) -Tag $tag
    foreach ($row in @($ResultSet.Rows)) {
        if ($null -eq $row -or $row.Required -cne 'yes' -or $row.Outcome -ceq 'Pass') { continue }
        $line = 'not passed: row {0}  {1} -> {2}  {3}/{4}  {5}  {6}  {7}' -f ([int]$row.ProfileRow).ToString($inv),
            (Get-PPSafeText -Text $row.SourceName), (Get-PPSafeText -Text $row.TargetName), $row.Protocol,
            ([int]$row.Port).ToString($inv), $row.Outcome, $row.State, $row.Error
        Write-PPInfoLine -Line $line -Tag $tag
    }
    Write-PPInfoLine -Line ('exit code {0}' -f $s.ExitCode.ToString($inv)) -Tag $tag
}

function Invoke-PortProof {
    # Success output flows uncaptured; the exit code travels through [ref].
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Raw,
        [Parameter(Mandatory)] [ref] $ExitCode,
        [pscustomobject] $LiveResolver,
        [hashtable] $Adapters,
        [System.Collections.Concurrent.ConcurrentQueue[object]] $Recorder
    )

    $ErrorActionPreference = 'Stop'
    $ExitCode.Value = 2
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $quiet = [bool]$Raw['Quiet']
    try {
        $contract = Get-PPContract

        # 1. -Version: nothing else runs, nothing on the information stream.
        if ([bool]$Raw['Version']) {
            Write-Output $contract.ToolVersion
            $ExitCode.Value = 0
            return
        }

        # 2-4.
        $options = Assert-Arguments -Raw $Raw -Contract $contract
        Write-PPNotice
        if ($null -eq $LiveResolver -and -not $options.DryRun) { $LiveResolver = Get-PPDnsResolver -TimeoutMs $contract.ResolveTimeoutMs }
        $resolver = Select-PPResolver -DryRun $options.DryRun -Live $LiveResolver
        if ($null -eq $Adapters) { $Adapters = $contract.DefaultAdapters }

        # 5. Profile path (FileSystem only), then the parser.
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Status 'Reading the profile' }
        $profileFull = Resolve-PPFileSystemPath -Path $options.ProfilePath -Code 'Profile.NotFound' -What 'profile'
        if (-not [System.IO.File]::Exists($profileFull)) {
            Invoke-PPRefusal -Code 'Profile.NotFound' -Message ("profile '{0}' was not found." -f (Get-PPSafeText -Text $options.ProfilePath))
        }
        $profileDocument = Import-PPProfile -Path $profileFull -Contract $contract

        # 6. Expansion and the pre-resolution early exit (all three parameters together).
        # The pass-1 expansion limit follows the run's effective cap.
        $expansion = Expand-PPProfile -ProfileDocument $profileDocument -Bindings $options.Bindings -AllowCidr:$options.AllowCidr `
            -EffectiveCap $options.EffectiveCap -Contract $contract
        $nPre = @($expansion.Probes | Where-Object { $null -ne $_ }).Count
        Assert-PPPreResolutionCount -Count $nPre -Cap $options.EffectiveCap -Ceiling $options.Ceiling

        $startedUtc = [datetime]::UtcNow
        $runId = [guid]::NewGuid().ToString()

        # 7. -DryRun: report and return. Nothing after this block runs under -DryRun.
        if ($options.DryRun) {
            $icmpTargets = 0
            if ($options.Icmp) { $icmpTargets = [int]$expansion.DistinctTargets }
            $total = $nPre + $icmpTargets
            if ($total -gt $options.EffectiveCap) {
                Invoke-PPRefusal -Code 'CapExceeded.PreResolution' -Message ('{0} probes exceed the cap of {1} (before name resolution; nothing was resolved or sent)' -f
                    $total.ToString([cultureinfo]::InvariantCulture), ([int]$options.EffectiveCap).ToString([cultureinfo]::InvariantCulture))
            }
            $worst = Measure-PPWorstCase -Probes @($expansion.Probes) -IcmpTargets $icmpTargets -Options $options
            $header = Get-PPRunHeader -Options $options -ProfileDocument $profileDocument -Expansion $expansion -ProbeCount $total `
                -Basis 'pre-resolution-upper-bound' -ExecutionPath 'None' -StartedUtc $startedUtc -RunId $runId -WorstCaseSeconds $worst
            Write-PPDryRunReport -Options $options -ProfileDocument $profileDocument -Expansion $expansion -Header $header
            $ExitCode.Value = 0
            return
        }

        # 8. Output preflight (Files only). Creates nothing.
        $plan = $null
        if ($options.Emit -ceq 'Files') { $plan = Test-PPOutputPreflight -Options $options }

        # 9. Resolution.
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Status 'Resolving names' }
        $resolution = Resolve-PPProbeList -Probes @($expansion.Probes) -Resolver $resolver
        $resolvedTimestamp = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [cultureinfo]::InvariantCulture)

        # 10. Gate -> Scheduler. The header is printed once the Gate has admitted the list.
        $executionPath = if ($PSVersionTable.PSVersion.Major -ge 7) { 'Parallel' } else { 'Runspace' }
        $ppAdmitState = @{
            Options = $options; ProfileDocument = $profileDocument; Expansion = $expansion; Resolution = $resolution
            StartedUtc = $startedUtc; RunId = $runId; ExecutionPath = $executionPath; Header = $null
        }
        $schedule = @{
            Concurrency = $options.Concurrency; MaxProbesPerSecond = $options.MaxProbesPerSecond
            JitterMs = $options.JitterMs; TimeoutMs = $options.TimeoutMs; ExecutionPath = $executionPath
        }
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Status 'Probing' }
        # -OnAdmitted is an inline scriptblock literal at the call site.
        $gateResult = Invoke-PPGate -Resolution $resolution -Cap $options.EffectiveCap -Icmp:$options.Icmp -Schedule $schedule `
            -Adapters $Adapters -Recorder $Recorder -OnAdmitted {
            param($AdmittedCount)
            $st = $ppAdmitState
            $execCount = @($st.Resolution.ExecProbes | Where-Object { $null -ne $_ }).Count
            $worstCase = Measure-PPWorstCase -Probes @($st.Resolution.ExecProbes) -IcmpTargets ([int]$AdmittedCount - $execCount) -Options $st.Options
            $st.Header = Get-PPRunHeader -Options $st.Options -ProfileDocument $st.ProfileDocument -Expansion $st.Expansion `
                -ProbeCount ([int]$AdmittedCount) -Basis 'admitted' -ExecutionPath $st.ExecutionPath -StartedUtc $st.StartedUtc `
                -RunId $st.RunId -WorstCaseSeconds $worstCase
            Write-PPRunHeader -Header $st.Header
        }

        # 11. Results, ResultSet, exit code.
        $rows = Join-PPResults -Expansion $expansion -Resolution $resolution -GateResult $gateResult -RunId $runId -ResolvedTimestamp $resolvedTimestamp
        $header = $ppAdmitState.Header
        if ($null -eq $header) {
            $header = Get-PPRunHeader -Options $options -ProfileDocument $profileDocument -Expansion $expansion `
                -ProbeCount ([int]$gateResult.AdmittedCount) -Basis 'admitted' -ExecutionPath $executionPath -StartedUtc $startedUtc -RunId $runId
        }
        $header.Flags.ExecutionPath = if ($gateResult.ExecutionPath) { [string]$gateResult.ExecutionPath } else { $executionPath }
        $summary = Get-PPSummary -Rows $rows -ElapsedMs $stopwatch.ElapsedMilliseconds
        $resultSet = [pscustomobject][ordered]@{ PSTypeName = 'PortProof.ResultSet'; Header = $header; Rows = $rows; Summary = $summary }

        # 12. Emit.
        if ($options.Emit -ceq 'Files') {
            [void][System.IO.Directory]::CreateDirectory($plan.Directory)
            $written = [System.Collections.Generic.List[string]]::new()
            foreach ($format in @($options.Formats)) {
                $path = $plan.Files[$format]
                try {
                    switch -CaseSensitive ($format) {
                        'Html' { Write-PPOutputFile -Path $path -Text (ConvertTo-PPHtml -ResultSet $resultSet) -Bom $false -Force $options.Force }
                        'Csv' { Write-PPOutputFile -Path $path -Text (ConvertTo-PPCsv -ResultSet $resultSet) -Bom $true -Force $options.Force }
                        'Json' { Write-PPOutputFile -Path $path -Text (ConvertTo-PPJson -ResultSet $resultSet) -Bom $false -Force $options.Force }
                    }
                }
                catch {
                    if ([string]$_.FullyQualifiedErrorId -clike 'PortProof.*') { throw }
                    $already = if ($written.Count -gt 0) { $written -join ', ' } else { 'none' }
                    Invoke-PPRefusal -Code 'Output.WriteFailed' -Message ("could not write '{0}': {1}; files already written: {2}" -f $path,
                        (Get-PPSafeText -Text $_.Exception.Message), $already)
                }
                $written.Add($path)
            }
        }
        elseif ($options.Emit -ceq 'Stream') {
            switch -CaseSensitive ($options.Formats[0]) {
                'Csv' { Write-Output (ConvertTo-PPCsv -ResultSet $resultSet) }
                'Json' { Write-Output (ConvertTo-PPJson -ResultSet $resultSet) }
            }
        }

        # 13. Summary and exit code.
        if (-not $quiet) { Write-Progress -Activity 'PortProof' -Completed }
        Write-PPSummary -ResultSet $resultSet
        $ExitCode.Value = [int]$summary.ExitCode
    }
    catch {
        $fqid = [string]$_.FullyQualifiedErrorId
        if ($fqid -clike 'PortProof.*') {
            Write-Error -Message $_.Exception.Message -ErrorId $fqid -Category InvalidArgument -ErrorAction Continue
        }
        else {
            $message = 'PortProof: internal error: {0}: {1}' -f $_.Exception.GetType().FullName, (Get-PPSafeText -Text $_.Exception.Message)
            Write-Error -Message $message -ErrorId 'PortProof.InternalError' -Category NotSpecified -ErrorAction Continue
        }
        $ExitCode.Value = 2
    }
}

# Entry block - the last lines of 90-Main.ps1 and so of dist/PortProof.ps1. Dot-sourcing this file
# (tests) leaves it inert.
if ($MyInvocation.InvocationName -ne '.') {
    $ppRaw = @{
        ProfilePath = $ProfilePath; Set = $Set; Out = $Out; Format = $Format; Timeout = $Timeout
        Concurrency = $Concurrency; MaxProbesPerSecond = $MaxProbesPerSecond; Jitter = $Jitter
        MaxProbes = $MaxProbes; MaxProbesGiven = $PSBoundParameters.ContainsKey('MaxProbes'); OutGiven = $PSBoundParameters.ContainsKey('Out')
        AllowLarge = [bool]$AllowLarge; AllowCidr = [bool]$AllowCidr; Icmp = [bool]$Icmp
        DryRun = [bool]$DryRun; NoOperator = [bool]$NoOperator; Force = [bool]$Force
        Quiet = [bool]$Quiet; Version = [bool]$Version
    }
    $ppExit = [ref]0
    Invoke-PortProof -Raw $ppRaw -ExitCode $ppExit
    exit $ppExit.Value
}
