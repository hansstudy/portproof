<#
.SYNOPSIS
Builds dist/PortProof.ps1 by concatenating the parts listed in build/parts.txt.

.DESCRIPTION
Reads the part list (blank and '#' lines skipped; '/' separators; each path src/<name>.ps1,
existing, listed once; every src/*.ps1 listed). For each part: strip a UTF-8 BOM, decode strictly
as UTF-8, normalise CRLF and CR to LF, ensure one trailing newline. Joins the parts (a banner line
'# ---- <path> ----' before every part after the first), converts LF to CRLF, prepends the UTF-8
BOM and writes the bytes. Prints the SHA-256 of the output. No timestamps, no network, no code
generation, no content change beyond line endings and the BOM. Exit 0 on success, 1 on any
failure with a message on the error output.

.PARAMETER OutFile
Output path. Relative paths resolve against -Root. Default dist/PortProof.ps1.

.PARAMETER PartsFile
Part list. Relative paths resolve against -Root. Default build/parts.txt.

.PARAMETER Root
Repository root. Default: the parent of this script's directory.
#>
[CmdletBinding()]
param(
    [string] $OutFile = 'dist/PortProof.ps1',
    [string] $PartsFile = 'build/parts.txt',
    [string] $Root
)

$ErrorActionPreference = 'Stop'

function Get-PPBuildFullPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $BasePath, [Parameter(Mandatory)] [string] $Path)

    [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($BasePath, $Path))
}

function Read-PPBuildPartText {
    # Bytes -> text: strip a UTF-8 BOM, strict UTF-8, LF line endings, exactly one final LF added
    # when missing.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [string] $Name)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $offset = 0
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { $offset = 3 }
    $strict = [System.Text.UTF8Encoding]::new($false, $true)
    try {
        $text = $strict.GetString($bytes, $offset, $bytes.Length - $offset)
    }
    catch {
        throw ("part '{0}' is not valid UTF-8." -f $Name)
    }
    $text = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    if (-not $text.EndsWith("`n", [System.StringComparison]::Ordinal)) { $text += "`n" }
    return $text
}

try {
    if ([string]::IsNullOrEmpty($Root)) { $Root = Split-Path -Parent $PSScriptRoot }
    $rootFull = [System.IO.Path]::GetFullPath($Root)
    $partsPath = Get-PPBuildFullPath -BasePath $rootFull -Path $PartsFile
    $outPath = Get-PPBuildFullPath -BasePath $rootFull -Path $OutFile

    if (-not [System.IO.File]::Exists($partsPath)) { throw ("part list '{0}' was not found." -f $partsPath) }
    $srcDir = Get-PPBuildFullPath -BasePath $rootFull -Path 'src'
    if (-not [System.IO.Directory]::Exists($srcDir)) { throw ("source directory '{0}' was not found." -f $srcDir) }

    # Read the part list.
    $listText = Read-PPBuildPartText -Path $partsPath -Name $PartsFile
    $parts = New-Object -TypeName 'System.Collections.Generic.List[string]'
    $listed = New-Object -TypeName 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $lineNumber = 0
    foreach ($line in $listText.Split("`n")) {
        $lineNumber++
        $entry = $line.Trim()
        if ($entry.Length -eq 0 -or $entry.StartsWith('#', [System.StringComparison]::Ordinal)) { continue }
        if ($entry -cnotmatch '\Asrc/[A-Za-z0-9][A-Za-z0-9._-]*\.ps1\z') {
            throw ([string]::Format([cultureinfo]::InvariantCulture, "part list line {0}: '{1}' is not a path of the form src/<name>.ps1 with '/' separators.", $lineNumber, $entry))
        }
        if (-not $listed.Add($entry)) {
            throw ([string]::Format([cultureinfo]::InvariantCulture, "part list line {0}: '{1}' is listed more than once.", $lineNumber, $entry))
        }
        $partPath = Get-PPBuildFullPath -BasePath $rootFull -Path $entry
        if (-not [System.IO.File]::Exists($partPath)) {
            throw ([string]::Format([cultureinfo]::InvariantCulture, "part list line {0}: '{1}' does not exist.", $lineNumber, $entry))
        }
        $parts.Add($entry)
    }
    if ($parts.Count -eq 0) { throw 'the part list names no parts.' }

    # Every src/*.ps1 must be listed (an orphan part fails the build).
    $orphans = New-Object -TypeName 'System.Collections.Generic.List[string]'
    foreach ($file in [System.IO.Directory]::GetFiles($srcDir, '*.ps1')) {
        $relative = 'src/' + [System.IO.Path]::GetFileName($file)
        if (-not $listed.Contains($relative)) { $orphans.Add($relative) }
    }
    if ($orphans.Count -gt 0) {
        $orphans.Sort([System.StringComparer]::Ordinal)
        throw ('parts not in the part list: {0}.' -f ($orphans -join ', '))
    }

    # Join.
    $builder = New-Object -TypeName 'System.Text.StringBuilder'
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $text = Read-PPBuildPartText -Path (Get-PPBuildFullPath -BasePath $rootFull -Path $parts[$i]) -Name $parts[$i]
        if ($i -gt 0) { [void]$builder.Append('# ---- ' + $parts[$i] + " ----`n") }
        [void]$builder.Append($text)
    }
    $joined = $builder.ToString().Replace("`n", "`r`n")

    $body = [System.Text.UTF8Encoding]::new($false).GetBytes($joined)
    $bytes = New-Object -TypeName 'byte[]' -ArgumentList ($body.Length + 3)
    $bytes[0] = 0xEF; $bytes[1] = 0xBB; $bytes[2] = 0xBF
    [System.Array]::Copy($body, 0, $bytes, 3, $body.Length)

    $outDir = [System.IO.Path]::GetDirectoryName($outPath)
    if (-not [System.IO.Directory]::Exists($outDir)) { [void][System.IO.Directory]::CreateDirectory($outDir) }
    [System.IO.File]::WriteAllBytes($outPath, $bytes)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
    Write-Output ('{0}  {1}' -f $hash, $outPath)
    exit 0
}
catch {
    [Console]::Error.WriteLine('Build-PortProof: ' + $_.Exception.Message)
    exit 1
}
