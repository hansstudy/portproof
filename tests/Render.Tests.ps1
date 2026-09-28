# Renderer tests. Dot-sources the contract and the three renderer
# files, loads the canned tests/Golden/resultset.json (test data, not a profile) into the runtime
# shape via a small test-side reader, and compares renderer output to the golden files byte for
# byte. Nothing here opens a socket, resolves a name, or touches the clock.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:GoldenDir = Join-Path $script:Root 'tests/Golden'
    . (Join-Path $script:Root 'src/00-Header.ps1')
    . (Join-Path $script:Root 'src/05-Contract.ps1')
    . (Join-Path $script:Root 'src/70-Render.Html.ps1')
    . (Join-Path $script:Root 'src/72-Render.Csv.ps1')
    . (Join-Path $script:Root 'src/74-Render.Json.ps1')
    . (Join-Path $script:GoldenDir 'Normalize.ps1')

    function Get-PPGoldenResultSet {
        # Test-side reader: resultset.json (test data, not a profile) -> the runtime ResultSet
        # shape, with literal member access exactly like the real pipeline
        # builds it (90-Main.ps1 Get-PPRunHeader / Join-PPResults / Get-PPSummary).
        param([Parameter(Mandatory)] [string] $Path)
        $doc = Get-Content -Raw -LiteralPath $Path -Encoding UTF8 | ConvertFrom-Json

        $f = $doc.Header.Flags
        $flags = [pscustomobject][ordered]@{
            PSTypeName         = 'PortProof.Flags'
            AllowLarge         = [bool]$f.AllowLarge
            AllowCidr          = [bool]$f.AllowCidr
            Icmp               = [bool]$f.Icmp
            DryRun             = [bool]$f.DryRun
            NoOperator         = [bool]$f.NoOperator
            Force              = [bool]$f.Force
            Quiet              = [bool]$f.Quiet
            Ceiling            = [int]$f.Ceiling
            EffectiveCap       = [int]$f.EffectiveCap
            TimeoutMs          = [int]$f.TimeoutMs
            Concurrency        = [int]$f.Concurrency
            MaxProbesPerSecond = [int]$f.MaxProbesPerSecond
            JitterMs           = [int]$f.JitterMs
            GroupOverrides     = [string[]]@($f.GroupOverrides)
            ExecutionPath      = [string]$f.ExecutionPath
        }

        $h = $doc.Header
        $header = [pscustomobject][ordered]@{
            PSTypeName          = 'PortProof.RunHeader'
            ToolVersion         = [string]$h.ToolVersion
            ProfileName         = [string]$h.ProfileName
            ProfileVersion      = [string]$h.ProfileVersion
            ProfileSha256       = [string]$h.ProfileSha256
            RunId               = [string]$h.RunId
            StartedUtc          = [string]$h.StartedUtc
            StartedLocal        = [string]$h.StartedLocal
            OperatorUser        = [string]$h.OperatorUser
            OperatorHost        = [string]$h.OperatorHost
            ProbeCount          = [int]$h.ProbeCount
            Flags               = $flags
            IgnoredColumns      = [string[]]@($h.IgnoredColumns)
            AuthorizedUseNotice = [string]$h.AuthorizedUseNotice
            OriginNote          = [string]$h.OriginNote
            ProbeCountBasis     = [string]$h.ProbeCountBasis
            WorstCaseSeconds    = [long]$h.WorstCaseSeconds
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($r in @($doc.Rows)) {
            $latency = $null
            if ($null -ne $r.LatencyMs) { $latency = [int]$r.LatencyMs }
            $rows.Add([pscustomobject][ordered]@{
                    PSTypeName        = 'PortProof.ResultRow'
                    RunId             = [string]$r.RunId
                    Timestamp         = [string]$r.Timestamp
                    SourceName        = [string]$r.SourceName
                    SourceIp          = [string]$r.SourceIp
                    TargetName        = [string]$r.TargetName
                    TargetIp          = [string]$r.TargetIp
                    ResolvedAddresses = [string[]]@($r.ResolvedAddresses)
                    Port              = [int]$r.Port
                    Protocol          = [string]$r.Protocol
                    Service           = [string]$r.Service
                    Required          = [string]$r.Required
                    Outcome           = [string]$r.Outcome
                    State             = [string]$r.State
                    LatencyMs         = $latency
                    Error             = [string]$r.Error
                    ProfileRow        = [int]$r.ProfileRow
                    SourceGroup       = [string]$r.SourceGroup
                    TargetGroup       = [string]$r.TargetGroup
                    Notes             = [string]$r.Notes
                })
        }

        $s = $doc.Summary
        $summary = [pscustomobject][ordered]@{
            PSTypeName        = 'PortProof.Summary'
            Total             = [int]$s.Total
            Pass              = [int]$s.Pass
            Fail              = [int]$s.Fail
            Inconclusive      = [int]$s.Inconclusive
            RequiredTotal     = [int]$s.RequiredTotal
            RequiredNotPassed = [int]$s.RequiredNotPassed
            ExitCode          = [int]$s.ExitCode
            ElapsedMs         = [long]$s.ElapsedMs
        }

        [pscustomobject][ordered]@{ PSTypeName = 'PortProof.ResultSet'; Header = $header; Rows = $rows.ToArray(); Summary = $summary }
    }

    function Get-PPUtf8NoBomByteArray {
        param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text)
        [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    }

    function Invoke-InCulture {
        # Runs $Action with CurrentCulture/CurrentUICulture set to $Name ('' = invariant), then
        # restores both (mirrors Contract.Tests.ps1's Invoke-InCulture).
        param([string] $Name, [scriptblock] $Action)
        $thread = [System.Threading.Thread]::CurrentThread
        $savedCulture = $thread.CurrentCulture
        $savedUi = $thread.CurrentUICulture
        try {
            $culture = [System.Globalization.CultureInfo]::GetCultureInfo($Name)
            $thread.CurrentCulture = $culture
            $thread.CurrentUICulture = $culture
            & $Action
        }
        finally {
            $thread.CurrentCulture = $savedCulture
            $thread.CurrentUICulture = $savedUi
        }
    }

    function Invoke-HtmlSelfContained {
        param([Parameter(Mandatory)] [string] $Path)
        $scriptPath = Join-Path $script:Root 'tests/Static/Test-HtmlSelfContained.ps1'
        $output = & $scriptPath -Path $Path
        [pscustomobject]@{ Output = @($output); ExitCode = $LASTEXITCODE }
    }

    $script:ResultSet = Get-PPGoldenResultSet -Path (Join-Path $script:GoldenDir 'resultset.json')
    $script:ExpectedHtmlBytes = [System.IO.File]::ReadAllBytes((Join-Path $script:GoldenDir 'expected.html'))
    $script:ExpectedCsvBytes = [System.IO.File]::ReadAllBytes((Join-Path $script:GoldenDir 'expected.csv'))
    $script:ExpectedJsonBytes = [System.IO.File]::ReadAllBytes((Join-Path $script:GoldenDir 'expected.json'))
}

Describe 'Golden byte equality (AC12)' -Tag 'Portable' {
    It 'ConvertTo-PPHtml matches expected.html byte for byte' {
        $actual = Get-PPUtf8NoBomByteArray -Text (ConvertTo-PPHtml -ResultSet $script:ResultSet)
        $actual | Should -Be $script:ExpectedHtmlBytes
    }

    It 'ConvertTo-PPCsv matches expected.csv byte for byte' {
        $actual = Get-PPUtf8NoBomByteArray -Text (ConvertTo-PPCsv -ResultSet $script:ResultSet)
        $actual | Should -Be $script:ExpectedCsvBytes
    }

    It 'ConvertTo-PPJson matches expected.json byte for byte' {
        $actual = Get-PPUtf8NoBomByteArray -Text (ConvertTo-PPJson -ResultSet $script:ResultSet)
        $actual | Should -Be $script:ExpectedJsonBytes
    }

    It '<Culture>: every renderer is byte-identical to the invariant-culture golden files' -ForEach @(
        foreach ($c in 'tr-TR', 'az-Latn-AZ') { @{ Culture = $c } }
    ) {
        Invoke-InCulture -Name $Culture -Action {
            (Get-PPUtf8NoBomByteArray -Text (ConvertTo-PPHtml -ResultSet $script:ResultSet)) | Should -Be $script:ExpectedHtmlBytes
            (Get-PPUtf8NoBomByteArray -Text (ConvertTo-PPCsv -ResultSet $script:ResultSet)) | Should -Be $script:ExpectedCsvBytes
            (Get-PPUtf8NoBomByteArray -Text (ConvertTo-PPJson -ResultSet $script:ResultSet)) | Should -Be $script:ExpectedJsonBytes
        }
    }

    It 'restores the culture after each test' {
        [System.Threading.Thread]::CurrentThread.CurrentCulture.Name | Should -Not -BeIn @('tr-TR', 'az-Latn-AZ')
    }
}

Describe 'Renderer purity' -Tag 'Portable' {
    It 'each renderer produces identical bytes on a second call (no clock/environment/fs dependency)' {
        $html1 = ConvertTo-PPHtml -ResultSet $script:ResultSet
        $html2 = ConvertTo-PPHtml -ResultSet $script:ResultSet
        $html1 | Should -BeExactly $html2
        $csv1 = ConvertTo-PPCsv -ResultSet $script:ResultSet
        $csv2 = ConvertTo-PPCsv -ResultSet $script:ResultSet
        $csv1 | Should -BeExactly $csv2
        $json1 = ConvertTo-PPJson -ResultSet $script:ResultSet
        $json2 = ConvertTo-PPJson -ResultSet $script:ResultSet
        $json1 | Should -BeExactly $json2
    }

    It 'the three renderer files carry no Get-Date, [Environment], or file-API token' -ForEach @(
        @{ File = 'src/70-Render.Html.ps1' }
        @{ File = 'src/72-Render.Csv.ps1' }
        @{ File = 'src/74-Render.Json.ps1' }
    ) {
        $text = [System.IO.File]::ReadAllText((Join-Path $script:Root $File))
        $text | Should -Not -Match 'Get-Date'
        $text | Should -Not -Match '(?i)\[\s*(System\.)?Environment\s*\]'
        $text | Should -Not -Match '(?i)\[\s*(System\.IO\.)(File|Directory|FileStream|Path)\s*\]'
        $text | Should -Not -Match '(?i)\b(Get-Content|Set-Content|Out-File|Add-Content)\b'
    }
}

Describe 'HTML self-containment and structure (AC13, AC14)' -Tag 'Portable' {
    It 'carries the CSP meta tag' {
        $html = ConvertTo-PPHtml -ResultSet $script:ResultSet
        $html | Should -Match ([regex]::Escape('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''">'))
    }

    It 'has no unescaped script tag' {
        $html = ConvertTo-PPHtml -ResultSet $script:ResultSet
        $html | Should -Not -Match '(?i)<script\b'
    }

    It 'escapes the hostile Service value instead of emitting a real tag' {
        $html = ConvertTo-PPHtml -ResultSet $script:ResultSet
        $html | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
    }

    It 'Test-HtmlSelfContained.ps1 passes on the golden expected.html' {
        $result = Invoke-HtmlSelfContained -Path (Join-Path $script:GoldenDir 'expected.html')
        $result.ExitCode | Should -Be 0
        $result.Output.Count | Should -Be 0
    }

    It 'escapes an astral character raw and passes it through on both hosts' {
        $html = ConvertTo-PPHtml -ResultSet $script:ResultSet
        $html | Should -Match ([regex]::Escape('deployment ' + [char]::ConvertFromUtf32(0x1F680) + ' done'))
    }
}

Describe 'CSV formula neutralisation (AC13)' -Tag 'Portable' {
    It '<Label>: apostrophe-prefixed exactly when <Triggers>' -ForEach @(
        @{ Label = 'plain HYPERLINK'; Value = '=HYPERLINK("http://evil.example/")'; Triggers = $true }
        @{ Label = 'leading space then equals'; Value = ' =1+1'; Triggers = $true }
        @{ Label = 'CR then equals'; Value = "`r=cmd"; Triggers = $true }
        @{ Label = 'fullwidth equals'; Value = ([string][char]0xFF1D + '1+1'); Triggers = $true }
        @{ Label = 'fullwidth plus'; Value = ([string][char]0xFF0B + '1'); Triggers = $true }
        @{ Label = 'fullwidth minus'; Value = ([string][char]0xFF0D + '1'); Triggers = $true }
        @{ Label = 'fullwidth at'; Value = ([string][char]0xFF20 + 'cmd'); Triggers = $true }
        @{ Label = 'plain plus'; Value = '+1'; Triggers = $true }
        @{ Label = 'plain minus'; Value = '-1'; Triggers = $true }
        @{ Label = 'plain at'; Value = '@cmd'; Triggers = $true }
        @{ Label = 'leading tab, no trigger follows'; Value = "`tsafe text"; Triggers = $false }
        @{ Label = 'no trigger'; Value = 'plain value'; Triggers = $false }
        @{ Label = 'embedded quote, no trigger'; Value = 'say "hi"'; Triggers = $false }
        @{ Label = 'CR then equals then quote'; Value = "`r=cmd|' /C calc'!A1"; Triggers = $true }
    ) {
        # Independent restatement of the CSV-encoding rule, so this is a real check against
        # the spec rather than the implementation checking itself: CR/LF -> space, then if the
        # first character after stripping ALL leading Unicode whitespace is a trigger character, a
        # "'" is prefixed to the (CR/LF-replaced, not stripped) value; then quote and double '"'.
        $spaced = $Value.Replace("`r`n", ' ').Replace("`r", ' ').Replace("`n", ' ')
        $prefix = ''
        if ($Triggers) { $prefix = "'" }
        $expected = '"' + ($prefix + $spaced).Replace('"', '""') + '"'
        ConvertTo-PPCsvField -Value $Value | Should -BeExactly $expected
        if ($Triggers) { (ConvertTo-PPCsvField -Value $Value).Substring(1, 1) | Should -BeExactly "'" }
    }

    It 'CR and LF become a single space before the trigger check' {
        ConvertTo-PPCsvField -Value "line1`r`nline2" | Should -BeExactly '"line1 line2"'
    }

    It 'quotes and neutralises every field of the golden CSV, header records included, with no bare leading formula trigger' {
        $csv = ConvertTo-PPCsv -ResultSet $script:ResultSet
        $lines = $csv -split "`r`n" | Where-Object { $_ -ne '' }
        foreach ($line in $lines) {
            $line.StartsWith('"') | Should -BeTrue -Because "every field is quoted: '$line'"
        }
        # The hostile ProfileName ("=SUM(...)"), Flags.GroupOverrides ("-CLIENT; DC") and
        # IgnoredColumns ("@Owner; Comment") header records all come out apostrophe-prefixed.
        ($lines | Where-Object { $_.StartsWith('"#ProfileName"') }) | Should -BeExactly '"#ProfileName","''=SUM(A1:A9)"'
        ($lines | Where-Object { $_.StartsWith('"#Flags.GroupOverrides"') }) | Should -BeExactly '"#Flags.GroupOverrides","''-CLIENT; DC"'
        ($lines | Where-Object { $_.StartsWith('"#IgnoredColumns"') }) | Should -BeExactly '"#IgnoredColumns","''@Owner; Comment"'
    }

    It 'CRLF line endings and exactly one trailing newline' {
        $csv = ConvertTo-PPCsv -ResultSet $script:ResultSet
        $csv.Substring($csv.Length - 2) | Should -BeExactly "`r`n"
        $csv.Substring($csv.Length - 4, 2) | Should -Not -BeExactly "`r`n"
        ($csv -replace "`r`n", '') | Should -Not -Match "`n"
        ($csv -replace "`r`n", '') | Should -Not -Match "`r"
    }
}

Describe 'JSON parses and round-trips (AC13)' -Tag 'Portable' {
    It 'parses with ConvertFrom-Json on the running host' {
        $json = ConvertTo-PPJson -ResultSet $script:ResultSet
        { ConvertFrom-Json -InputObject $json -ErrorAction Stop } | Should -Not -Throw
    }

    It 'round-trips every string, including the hostile and non-ASCII fixtures' {
        $json = ConvertTo-PPJson -ResultSet $script:ResultSet
        $parsed = ConvertFrom-Json -InputObject $json
        $parsed.schema | Should -BeExactly (Get-PPContract).ResultSchemaId
        $parsed.header.RunId | Should -BeExactly $script:ResultSet.Header.RunId
        $parsed.header.OperatorUser | Should -BeExactly $script:ResultSet.Header.OperatorUser
        $parsed.results.Count | Should -Be $script:ResultSet.Rows.Count
        ($parsed.results | Where-Object { $_.Service -like '*script*' }).Service | Should -BeExactly '<script>alert(1)</script>'
        ($parsed.results | Where-Object { $_.Notes -like '*HYPERLINK*' }).Notes | Should -BeExactly '=HYPERLINK("http://evil.example/","click")'
        $emojiRow = $parsed.results | Where-Object { $_.SourceName -eq 'Z' + [char]0xFC + 'rich-App' }
        $emojiRow.Notes | Should -BeExactly ('Z' + [char]0xFC + 'rich caf' + [char]0xE9 + ' ' + [char]0x2615 + ' deployment ' + [char]::ConvertFromUtf32(0x1F680) + ' done')
        $dnsFailureRow = $parsed.results | Where-Object { $_.Error -eq 'DnsFailure' }
        $dnsFailureRow.LatencyMs | Should -Be $null
        $dnsFailureRow.ResolvedAddresses.Count | Should -Be 0
    }

    It 'two-space indent, one member per line, and exactly one trailing newline' {
        $json = ConvertTo-PPJson -ResultSet $script:ResultSet
        $json.Substring(0, 2) | Should -BeExactly "{`n"
        $json.Substring($json.Length - 1) | Should -BeExactly "`n"
        $json.Substring($json.Length - 2, 1) | Should -Not -BeExactly "`n"
        $json | Should -Match '\n  "schema": '
    }
}

Describe 'Every State and Error appears in the golden fixture (coverage guard)' -Tag 'Portable' {
    It 'covers every contract State value' {
        $contract = Get-PPContract
        $expectedStates = [System.Collections.Generic.HashSet[string]]::new([string[]]@($contract.StateNotClassified))
        foreach ($protocol in $contract.States.Keys) { foreach ($state in $contract.States[$protocol]) { [void]$expectedStates.Add($state) } }
        $actualStates = [System.Collections.Generic.HashSet[string]]::new([string[]]@($script:ResultSet.Rows | ForEach-Object { $_.State }))
        foreach ($state in $expectedStates) { $actualStates.Contains($state) | Should -BeTrue -Because "State '$state' must appear in the golden fixture" }
    }

    It 'covers every contract Error value' {
        $contract = Get-PPContract
        $actualErrors = [System.Collections.Generic.HashSet[string]]::new([string[]]@($script:ResultSet.Rows | ForEach-Object { $_.Error }))
        foreach ($errorName in $contract.Errors) { $actualErrors.Contains($errorName) | Should -BeTrue -Because "Error '$errorName' must appear in the golden fixture" }
    }

    It 'covers Pass, Fail and Inconclusive' {
        $outcomes = [System.Collections.Generic.HashSet[string]]::new([string[]]@($script:ResultSet.Rows | ForEach-Object { $_.Outcome }))
        $outcomes.Contains('Pass') | Should -BeTrue
        $outcomes.Contains('Fail') | Should -BeTrue
        $outcomes.Contains('Inconclusive') | Should -BeTrue
    }

    It 'has a DnsFailure row, an ICMP row, and an IPv6 target' {
        @($script:ResultSet.Rows | Where-Object { $_.Error -eq 'DnsFailure' }).Count | Should -BeGreaterThan 0
        @($script:ResultSet.Rows | Where-Object { $_.Protocol -eq 'ICMP' }).Count | Should -BeGreaterThan 0
        @($script:ResultSet.Rows | Where-Object { $_.TargetIp -like '*:*' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'The authorized-use notice appears in every format header (AC20)' -Tag 'Portable' {
    BeforeAll {
        $script:NoticeLines = @(Get-PPAuthorizedUseNotice)
    }

    It 'appears in the HTML notice section' {
        $html = ConvertTo-PPHtml -ResultSet $script:ResultSet
        foreach ($line in $script:NoticeLines) { $html | Should -Match ([regex]::Escape((ConvertTo-PPHtmlText -Text $line))) }
    }

    It 'appears in the CSV run-header record' {
        $csv = ConvertTo-PPCsv -ResultSet $script:ResultSet
        foreach ($line in $script:NoticeLines) { $csv | Should -Match ([regex]::Escape($line)) }
    }

    It 'appears in the JSON header' {
        $json = ConvertTo-PPJson -ResultSet $script:ResultSet
        foreach ($line in $script:NoticeLines) { $json | Should -Match ([regex]::Escape($line)) }
    }
}
