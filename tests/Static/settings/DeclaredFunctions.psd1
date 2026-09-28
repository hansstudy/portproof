@{
    # PortProof declared-function list.
    #
    # The command allowlist's "defined function" set is the UNION of (a) every FunctionDefinitionAst
    # name actually present in src/ right now (collected fresh each run - see
    # Get-PPDefinedFunctionName) and (b) this file - a fixed list of function names this tool's
    # signature set promises, kept as a safety net for a forward reference from 90-Main.ps1 to a
    # function defined in a file the fresh AST scan has not (yet, for whatever reason) picked up.
    # Once Get-PPDefinedFunctionName finds a name directly, this entry becomes redundant (harmless -
    # the union just has the name twice).
    #
    # Every entry names the exact file and the function's purpose, so this list can be audited
    # directly instead of trusted on faith. Names are taken only from the real function
    # signatures - never invented to make a scanner pass.
    #
    # A test in Static.Tests.ps1 checks that once dist/ exists, every entry here is defined
    # somewhere in src/ - a name still needed at that point means either the signature changed and
    # this file is stale, or the function was never written.

    'Import-PPProfile'             = 'The profile loader entry point, defined in 10-Parser.ps1.'
    'Expand-PPProfile'              = 'Group/list/CIDR expansion into the pre-resolution probe list, defined in 20-Expander.ps1.'
    'Assert-PPPreResolutionCount'   = 'The pre-resolution early-exit cap check, defined in 20-Expander.ps1.'
    'Get-PPDnsResolver'             = 'The live Resolver seam constructor, defined in 30-Resolver.ps1.'
    'Resolve-PPProbeList'           = 'Resolves the pre-resolution Probe list into ExecProbes, defined in 30-Resolver.ps1.'
    'Invoke-PPGate'                 = 'The one authoritative post-resolution cap and class check, and the only caller of the Scheduler, defined in 35-Gate.ps1.'
    'ConvertTo-PPHtml'              = 'The HTML renderer, defined in 70-Render.Html.ps1.'
    'ConvertTo-PPCsv'               = 'The CSV renderer, defined in 72-Render.Csv.ps1.'
    'ConvertTo-PPJson'              = 'The JSON renderer, defined in 74-Render.Json.ps1.'
}
