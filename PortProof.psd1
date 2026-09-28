@{
    # PortProof ships as one script (dist/PortProof.ps1). This manifest is the version anchor and the
    # SBOM input; it loads nothing, so it has no RootModule and no dependency list.
    ModuleVersion     = '1.0.0'
    GUID              = '5131520a-f5e5-41db-9db7-f2c19a5dd786'
    Author            = 'Hans Study'
    CompanyName       = 'Hans Study'
    Copyright         = '(c) 2026 Hans Study. Licensed under Apache-2.0.'
    Description       = 'Prove a firewall rule set is open before the vendor arrives.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @()
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags         = @('network', 'firewall', 'port')
            LicenseUri   = 'https://github.com/hansstudy/portproof/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/hansstudy/portproof'
            ReleaseNotes = 'https://github.com/hansstudy/portproof/blob/main/CHANGELOG.md'
        }
    }
}
