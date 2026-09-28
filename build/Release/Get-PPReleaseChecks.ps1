<#
.SYNOPSIS
Local pre-tag release sanity check. Not called by any workflow (ci.yml/release.yml read only
release-config.yml, build/Build-PortProof.ps1 and tests/Invoke-Tests.ps1); this is for a human to
run by hand before pushing a version tag.

.DESCRIPTION
Three read-only checks, no writes, no network:

1. AC35 - the manifest is the only one, and the five version strings agree: PortProof.psd1
   `ModuleVersion`, `dist/PortProof.ps1 -Version`, the first CHANGELOG.md release heading, the
   README version badge, and the `docs/releases/v<version>/` directory name. Also asserts
   `PowerShellVersion = '5.1'`, no `RequiredModules` key at all, and `Apache-2.0` in the
   `Copyright` line.
2. Recomputes `SHA256SUMS` for every flat file directly under `dist/` as a dry preview - printed,
   never written to disk. `release.yml` is the one place that publishes the real file.
3. Reads `checklist_version` out of the machine-readable block in `docs/RELEASE-CHECKLIST.md`, so
   a human can eyeball it against the value recorded in `docs/releases/<version>/release-evidence.json`.

Exit 0 when every check above passes; exit 1 with every problem listed on the error stream.

.PARAMETER Root
Repository root. Default: two levels up from this script (`build/Release/..\..`).
#>
[CmdletBinding()]
param(
    [string] $Root
)

$ErrorActionPreference = 'Stop'

function Get-PPReleaseFullPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $BasePath, [Parameter(Mandatory)] [string] $Path)

    [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($BasePath, $Path))
}

function Get-PPManifestCandidate {
    # Every *.psd1 within three directory levels of the root, '.git' excluded - the same search
    # space release.yml and the test-windows lane each use to pick "the manifest" (AC35).
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $RootPath)

    $found = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $rootFull = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
    foreach ($file in [System.IO.Directory]::EnumerateFiles($rootFull, '*.psd1', [System.IO.SearchOption]::AllDirectories)) {
        $relative = $file.Substring($rootFull.Length).TrimStart('\', '/')
        if ($relative -match '(^|[\\/])\.git([\\/]|$)') { continue }
        $depth = ($relative -split '[\\/]').Count - 1
        if ($depth -gt 2) { continue }   # 3 levels deep = 2 separators below the root
        $found.Add($relative)
    }
    $found.Sort([System.StringComparer]::Ordinal)
    return , $found.ToArray()
}

function Test-PPManifest {
    # Returns @{ Problems = [string[]]; Version = [string] } for the one manifest found.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $RootPath, [Parameter(Mandatory)] [string[]] $Candidates)

    $problems = New-Object -TypeName 'System.Collections.Generic.List[string]'
    if ($Candidates.Count -ne 1) {
        $problems.Add("expected exactly one *.psd1 within three directory levels; found $($Candidates.Count): $($Candidates -join ', ')")
        return @{ Problems = $problems.ToArray(); Version = $null }
    }
    if ($Candidates[0] -ne 'PortProof.psd1') {
        $problems.Add("the one manifest found is '$($Candidates[0])', not 'PortProof.psd1'")
    }

    $manifestPath = Get-PPReleaseFullPath -BasePath $RootPath -Path $Candidates[0]
    $data = Import-PowerShellDataFile -LiteralPath $manifestPath
    $text = [System.IO.File]::ReadAllText($manifestPath)

    if ($data.PowerShellVersion -ne '5.1') {
        $problems.Add("PowerShellVersion is '$($data.PowerShellVersion)', expected '5.1'")
    }
    if (([regex]::Matches($text, 'RequiredModules')).Count -ne 0) {
        $problems.Add('RequiredModules is present in PortProof.psd1; AC35 requires the key to be absent entirely')
    }
    if ([string]::IsNullOrEmpty($data.Copyright) -or $data.Copyright -notmatch 'Apache-2\.0') {
        $problems.Add("Copyright ('$($data.Copyright)') does not mention Apache-2.0")
    }
    if ([string]::IsNullOrEmpty($data.ModuleVersion)) {
        $problems.Add('ModuleVersion is missing from PortProof.psd1')
    }

    return @{ Problems = $problems.ToArray(); Version = $data.ModuleVersion }
}

function Get-PPDistVersionString {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $DistPath)

    if (-not (Test-Path -LiteralPath $DistPath)) {
        throw "dist/PortProof.ps1 not found at '$DistPath' - build it first (build/Build-PortProof.ps1)."
    }
    $output = & $DistPath -Version 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "'$DistPath -Version' exited $LASTEXITCODE : $($output -join ' ')"
    }
    return ($output | Select-Object -First 1).ToString().Trim()
}

function Get-PPChangelogVersionString {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $ChangelogPath)

    foreach ($line in [System.IO.File]::ReadLines($ChangelogPath)) {
        $m = [regex]::Match($line, '^##\s+\[?v?(?<ver>[0-9]+\.[0-9]+\.[0-9]+)\]?.*[0-9]{4}-[0-9]{2}-[0-9]{2}')
        if ($m.Success) { return $m.Groups['ver'].Value }
    }
    throw "CHANGELOG.md has no dated '## [x.y.z] - yyyy-mm-dd' heading."
}

function Get-PPReadmeBadgeVersionString {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $ReadmePath)

    $text = [System.IO.File]::ReadAllText($ReadmePath)
    $m = [regex]::Match($text, 'version-(?<ver>[0-9]+\.[0-9]+\.[0-9]+)-blue')
    if (-not $m.Success) { throw "README.md has no 'version-x.y.z-blue' badge." }
    return $m.Groups['ver'].Value
}

function Get-PPReleaseDirVersionString {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $ReleasesDir, [Parameter(Mandatory)] [string] $Expected)

    $expectedDir = Join-Path $ReleasesDir "v$Expected"
    if (Test-Path -LiteralPath $expectedDir -PathType Container) { return $Expected }
    $dirs = @()
    if (Test-Path -LiteralPath $ReleasesDir -PathType Container) {
        $dirs = @(Get-ChildItem -LiteralPath $ReleasesDir -Directory | ForEach-Object { $_.Name })
    }
    throw "no 'docs/releases/v$Expected/' directory (found: $($dirs -join ', '))."
}

function Get-PPDistSha256Preview {
    # A dry SHA256SUMS preview over every flat file directly under dist/, `SHA256SUMS` itself
    # excluded - the same shape as release.yml step 5, sorted the same way (LC_ALL=C / ordinal).
    # Prints only; writes nothing to disk. This is a preview for a human, not the release file.
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [string] $DistDir)

    if (-not (Test-Path -LiteralPath $DistDir -PathType Container)) {
        throw "dist/ not found at '$DistDir'."
    }
    $files = @(Get-ChildItem -LiteralPath $DistDir -File | Where-Object { $_.Name -ne 'SHA256SUMS' } | Sort-Object -Property Name -CaseSensitive)
    if ($files.Count -eq 0) { throw "dist/ at '$DistDir' has no files to sum." }
    $lines = New-Object -TypeName 'System.Collections.Generic.List[string]'
    foreach ($file in $files) {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines.Add(('{0}  {1}' -f $hash, $file.Name))
    }
    return , $lines.ToArray()
}

function Get-PPChecklistVersion {
    # Same extraction shape as .github/workflows/scripts/check-release-evidence.mjs: the JSON
    # registry fenced between the two HTML comment markers.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ChecklistPath)

    $text = [System.IO.File]::ReadAllText($ChecklistPath)
    $beginMarker = '<!-- machine-readable: begin -->'
    $endMarker = '<!-- machine-readable: end -->'
    $begin = $text.IndexOf($beginMarker, [System.StringComparison]::Ordinal)
    $end = $text.IndexOf($endMarker, [System.StringComparison]::Ordinal)
    if ($begin -lt 0 -or $end -lt 0 -or $end -lt $begin) {
        throw "'$ChecklistPath' has no machine-readable gate registry between '$beginMarker' and '$endMarker'."
    }
    $body = $text.Substring($begin + $beginMarker.Length, $end - ($begin + $beginMarker.Length)).Trim()
    $fence = [regex]::Match($body, '^```[a-zA-Z0-9]*\r?\n([\s\S]*?)\r?\n```$')
    if ($fence.Success) { $body = $fence.Groups[1].Value }
    $registry = $body | ConvertFrom-Json
    if ($null -eq $registry.checklist_version) {
        throw "'$ChecklistPath' registry has no 'checklist_version'."
    }
    return [int]$registry.checklist_version
}

try {
    if ([string]::IsNullOrEmpty($Root)) {
        $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    $rootFull = [System.IO.Path]::GetFullPath($Root)

    $problems = New-Object -TypeName 'System.Collections.Generic.List[string]'

    Write-Output '== AC35: manifest search and version agreement =='
    $candidates = Get-PPManifestCandidate -RootPath $rootFull
    $manifestCheck = Test-PPManifest -RootPath $rootFull -Candidates $candidates
    foreach ($p in $manifestCheck.Problems) { $problems.Add("manifest: $p") }

    $versions = [ordered]@{}
    if ($null -ne $manifestCheck.Version) { $versions['PortProof.psd1 ModuleVersion'] = $manifestCheck.Version }

    try { $versions['dist/PortProof.ps1 -Version'] = Get-PPDistVersionString -DistPath (Get-PPReleaseFullPath -BasePath $rootFull -Path 'dist/PortProof.ps1') }
    catch { $problems.Add("dist version: $($_.Exception.Message)") }

    try { $versions['CHANGELOG.md heading'] = Get-PPChangelogVersionString -ChangelogPath (Get-PPReleaseFullPath -BasePath $rootFull -Path 'CHANGELOG.md') }
    catch { $problems.Add("changelog version: $($_.Exception.Message)") }

    try { $versions['README.md badge'] = Get-PPReadmeBadgeVersionString -ReadmePath (Get-PPReleaseFullPath -BasePath $rootFull -Path 'README.md') }
    catch { $problems.Add("readme badge version: $($_.Exception.Message)") }

    if ($null -ne $manifestCheck.Version) {
        try { $versions['docs/releases/ directory'] = Get-PPReleaseDirVersionString -ReleasesDir (Get-PPReleaseFullPath -BasePath $rootFull -Path 'docs/releases') -Expected $manifestCheck.Version }
        catch { $problems.Add("releases directory: $($_.Exception.Message)") }
    }

    foreach ($key in $versions.Keys) { Write-Output ('  {0,-28} {1}' -f $key, $versions[$key]) }

    $distinct = @($versions.Values | Select-Object -Unique)
    if ($versions.Count -lt 5) {
        $problems.Add("only $($versions.Count) of 5 version strings could be read; see errors above")
    }
    elseif ($distinct.Count -ne 1) {
        $problems.Add("version strings disagree: $($distinct -join ', ')")
    }
    else {
        Write-Output "  all $($versions.Count) version strings agree: $($distinct[0])"
    }

    Write-Output ''
    Write-Output '== SHA256SUMS dry preview (dist/) - printed only, nothing written to disk =='
    try {
        $sums = Get-PPDistSha256Preview -DistDir (Get-PPReleaseFullPath -BasePath $rootFull -Path 'dist')
        foreach ($line in $sums) { Write-Output "  $line" }
    }
    catch {
        $problems.Add("SHA256SUMS preview: $($_.Exception.Message)")
    }

    Write-Output ''
    Write-Output '== docs/RELEASE-CHECKLIST.md checklist_version =='
    try {
        $checklistVersion = Get-PPChecklistVersion -ChecklistPath (Get-PPReleaseFullPath -BasePath $rootFull -Path 'docs/RELEASE-CHECKLIST.md')
        Write-Output "  checklist_version: $checklistVersion"
    }
    catch {
        $problems.Add("checklist_version: $($_.Exception.Message)")
    }

    Write-Output ''
    if ($problems.Count -gt 0) {
        Write-Output "$($problems.Count) problem(s):"
        foreach ($p in $problems) { [Console]::Error.WriteLine("Get-PPReleaseChecks: $p") }
        exit 1
    }
    Write-Output 'All checks passed.'
    exit 0
}
catch {
    [Console]::Error.WriteLine('Get-PPReleaseChecks: ' + $_.Exception.Message)
    exit 1
}
