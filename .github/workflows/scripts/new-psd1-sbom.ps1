# template-version: 2
<#
.SYNOPSIS
  Generate a CycloneDX JSON SBOM for a PowerShell module from its .psd1 manifest.

.DESCRIPTION
  Generates the `psd1` SBOM: a zero-dependency tool still ships an SBOM whose
  single component is the tool itself, and RequiredModules entries must carry
  an exact RequiredVersion pin, never a floor.

  Called by release.yml step 4 when release-config.yml sets
  sbom.generator to "psd1". PowerShell modules typically have a handful of
  RequiredModules and no transitive tree, so a manifest read is the whole graph.

  No external module is used; Import-PowerShellDataFile is in-box. There is
  deliberately no #Requires: nothing here needs PowerShell 7, and the script is
  written to behave identically under Windows PowerShell 5.1 so that it can be
  exercised off the runner.

  -Licence is mandatory and has no default. Per-project licence exceptions to
  the Apache-2.0 house default are allowed, and this document is the
  one a procurement reviewer reads, so asserting a licence nobody chose is worse
  than refusing to build. release.yml passes the
  `licence` value from .github/release-config.yml and fails before this point if
  it is empty.

.EXAMPLE
  pwsh -File new-psd1-sbom.ps1 -ManifestPath ./StudyADAudit/StudyADAudit.psd1 `
       -OutFile dist/ad-gpo-audit-1.0.0.cdx.json -Name ad-gpo-audit -Version 1.0.0 `
       -Description "Study AD Audit" -Licence Apache-2.0
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $ManifestPath,
  [Parameter(Mandatory)] [string] $OutFile,
  [Parameter(Mandatory)] [string] $Name,
  [Parameter(Mandatory)] [string] $Version,
  [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Licence,
  [string] $Description = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not (Test-Path -LiteralPath $ManifestPath)) {
  throw "manifest '$ManifestPath' does not exist"
}

$manifest = Import-PowerShellDataFile -LiteralPath $ManifestPath

$supplier = 'unknown'
if ($manifest.ContainsKey('CompanyName') -and $manifest.CompanyName) {
  $supplier = [string]$manifest.CompanyName
} elseif ($manifest.ContainsKey('Author') -and $manifest.Author) {
  $supplier = [string]$manifest.Author
}

# purl type: nuget. `powershell` is not a registered purl type, so an SBOM
# consumer (Dependency-Track, grype, a procurement scanner) could not resolve
# the component to any package or advisory source - which removes most of the
# SBOM's value. nuget is the conventional identifier for a PSGallery module.
$toolRef = "pkg:nuget/$Name@$Version"
$tool = [ordered]@{
  type        = 'application'
  'bom-ref'   = $toolRef
  name        = $Name
  version     = $Version
  description = $(if ($Description) { $Description } else { $Name })
  supplier    = @{ name = $supplier }
  licenses    = @(@{ license = @{ id = $Licence } })
  purl        = $toolRef
}

$components = [System.Collections.Generic.List[object]]::new()
$components.Add($tool)

if ($manifest.ContainsKey('RequiredModules')) {
  foreach ($required in @($manifest.RequiredModules)) {
    if ($null -eq $required) { continue }

    if ($required -is [string]) {
      throw ("RequiredModules entry '$required' in '$ManifestPath' has no RequiredVersion. " +
             'Dependency pinning requires an exact pin, not a floor, before a release can be cut.')
    }

    $moduleName = [string]$required['ModuleName']
    if (-not $moduleName) {
      throw "a RequiredModules entry in '$ManifestPath' has no ModuleName"
    }
    if (-not $required.ContainsKey('RequiredVersion') -or -not $required['RequiredVersion']) {
      throw ("RequiredModules entry '$moduleName' in '$ManifestPath' has no RequiredVersion. " +
             'ModuleVersion is a floor, not a pin.')
    }
    $requiredVersion = [string]$required['RequiredVersion']
    $ref = "pkg:nuget/$moduleName@$requiredVersion"
    $components.Add([ordered]@{
      type      = 'library'
      'bom-ref' = $ref
      name      = $moduleName
      version   = $requiredVersion
      purl      = $ref
      scope     = 'required'
    })
  }
}

$bom = [ordered]@{
  bomFormat    = 'CycloneDX'
  specVersion  = '1.5'
  version      = 1
  metadata     = [ordered]@{
    timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    component = $tool
    tools     = @(@{ name = 'new-psd1-sbom.ps1'; version = '1' })
  }
  components   = $components.ToArray()
}

$outDir = Split-Path -Parent $OutFile
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
  New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

# Written through .NET rather than Set-Content, and with an explicit no-BOM
# encoding, because the two hosts disagree: Windows PowerShell 5.1's
# `-Encoding utf8` emits a BOM and pwsh 7's does not. A BOM makes JSON.parse
# reject the file, so release.yml step 4 would fail with "SBOM does not parse"
# on a document that is otherwise correct. The script carries no #Requires and
# runs on both hosts, so this is a live difference, not a historical one - do
# not simplify it back to Set-Content.
$json = $bom | ConvertTo-Json -Depth 12
$fullPath = if ([System.IO.Path]::IsPathRooted($OutFile)) {
  $OutFile
} else {
  [System.IO.Path]::Combine($PWD.ProviderPath, $OutFile)
}
[System.IO.File]::WriteAllText($fullPath, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Host ("Wrote {0} with {1} component(s)." -f $OutFile, $components.Count)
