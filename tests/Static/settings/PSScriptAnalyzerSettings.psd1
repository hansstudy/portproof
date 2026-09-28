@{
    # PortProof PSScriptAnalyzer settings. Path is four levels deep from the repo root
    # (tests/Static/settings/<this file>) so AC35's shallow *.psd1 searches (Get-ChildItem -Depth 2
    # from the root, and the Git Bash `find -maxdepth 3` equivalent) never see it as a candidate
    # manifest - PortProof.psd1 stays the tree's only one.
    #
    # Default rules stay on; nothing is excluded. If a rule ever needs excluding, add it below with
    # a '# reason:' comment on the same line - Invoke-Lint.ps1 fails the run if that comment is
    # missing, so a suppression can never land silently.

    Severity     = @('Error', 'Warning')

    # PSAvoidUsingWriteHost is deliberately NOT excluded here: a Write-Host in src/ would bypass
    # the information-stream contract and must still fail. The runner scripts
    # that legitimately use Write-Host (this folder's own Invoke-Lint.ps1; tests/Invoke-Tests.ps1
    # and tests/Harness/*) each carry their own per-file/per-function
    # SuppressMessage attribute instead.
    ExcludeRules = @()

    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
