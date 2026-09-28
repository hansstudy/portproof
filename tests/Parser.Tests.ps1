# Parser tests. Dot-sources 05-Contract.ps1 and 10-Parser.ps1 only -
# nothing here resolves a name or opens a socket. Drives the 71-file corpus plus the top-level
# valid-*/invalid-*/hostile-*/refused-* fixtures.
#
# The corpus table and lookup lists below run at Pester DISCOVERY time (they feed -ForEach), so they
# are plain script-scope code, not inside BeforeAll (which only runs at Run time, after discovery
# has already needed this data - a Pester v5/v6 rule, not a style choice).
$script:Root = Split-Path -Parent $PSScriptRoot
$script:FixturesRoot = Join-Path $script:Root 'tests/Fixtures'

# corpus/cases.csv covers every closed-domain/syntax violation for the parser (AC9, AC31 unit
# half). Group.* ids are the Expander's own domain (Expander.Tests.ps1 drives those, since
# the parser accepts a %GROUP% reference as a well-formed field - binding happens later).
$script:CorpusCases = Import-Csv (Join-Path $script:FixturesRoot 'corpus/cases.csv')
$script:GroupOwnedIds = @('Group.Unbound', 'Group.Syntax', 'Group.Nested', 'Group.CidrNotAllowed',
    'Group.CidrTooWide', 'Group.CidrNotAligned', 'Group.CidrIPv6', 'Group.CidrInSource', 'Group.TooLarge',
    # VLSM support: a wide-enough CIDR (e.g. /16) is refused by the Expander's own
    # EffectiveCap x ExpansionFactor arithmetic, not by a parser-level check - CapExceeded.Expansion
    # is an Expander-only id (Expander.Tests.ps1 drives it), so the parser-only corpus loops here
    # must skip it exactly as they already skip every Group.* id.
    'CapExceeded.Expansion')

BeforeAll {
    # Pester runs discovery (the top-level code above, which -ForEach needs) and each run's
    # BeforeAll in separate script-scope instances - $script: variables set at the top of the file
    # do not carry into here, so every one of them needed at run time is set again.
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:FixturesRoot = Join-Path $script:Root 'tests/Fixtures'
    $script:CorpusCases = Import-Csv (Join-Path $script:FixturesRoot 'corpus/cases.csv')
    $script:GroupOwnedIds = @('Group.Unbound', 'Group.Syntax', 'Group.Nested', 'Group.CidrNotAllowed',
        'Group.CidrTooWide', 'Group.CidrNotAligned', 'Group.CidrIPv6', 'Group.CidrInSource', 'Group.TooLarge',
        'CapExceeded.Expansion')

    . (Join-Path $script:Root 'src/05-Contract.ps1')
    . (Join-Path $script:Root 'src/10-Parser.ps1')
    $script:Contract = Get-PPContract

    function Get-FixturePath {
        param([Parameter(Mandatory)] [string] $Relative)
        Join-Path $script:FixturesRoot $Relative
    }

    function Get-Refusal {
        # Runs Import-PPProfile on a fixture and returns the ErrorRecord, or $null if it parsed.
        param([Parameter(Mandatory)] [string] $Relative)
        try {
            [void](Import-PPProfile -Path (Get-FixturePath $Relative) -Contract $script:Contract)
            return $null
        }
        catch {
            return $_
        }
    }

    function Invoke-InCulture {
        # Same pattern as Contract.Tests.ps1's Invoke-InCulture: run $Action under a named
        # culture ('' = invariant), then restore.
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
}

Describe 'Corpus error ids (AC9, AC31 unit half)' -Tag 'Portable' {
    It '<file> -> <expected_error_id>' -ForEach @(
        foreach ($case in $script:CorpusCases) {
            if ($script:GroupOwnedIds -notcontains $case.expected_error_id) {
                @{ file = $case.file; expected_error_id = $case.expected_error_id; names = $case.names }
            }
        }
    ) {
        $record = Get-Refusal -Relative $file
        $record | Should -Not -BeNullOrEmpty -Because "expected $expected_error_id ($names)"
        $record.FullyQualifiedErrorId | Should -BeExactly ('PortProof.{0}' -f $expected_error_id) -Because $names
        $record.Exception.Message | Should -Not -BeNullOrEmpty
    }

    It 'json-wrong-schema.json: no dedicated id for a wrong schema value; Profile.Domain is correct' {
        # The schema requires "schema": "portproof-profile/1" exactly; the error-id table has
        # no dedicated id for this field - every profile error names "row <n> ...
        # or a named top-level field" under Profile.Domain's general shape - the same treatment a
        # bad top-level `name`/`version` value gets. cases.csv marked this a guess; confirmed.
        $record = Get-Refusal -Relative 'corpus/json-wrong-schema.json'
        $record.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.Domain'
    }
}

Describe 'Corpus error ids under tr-TR (no culture-sensitive comparison anywhere in the parser)' -Tag 'Portable' {
    It 'every non-group corpus case matches under tr-TR exactly as under the invariant culture' {
        $offenders = [System.Collections.Generic.List[string]]::new()
        Invoke-InCulture -Name 'tr-TR' -Action {
            foreach ($case in $script:CorpusCases) {
                $isGroupOwned = $script:GroupOwnedIds -contains $case.expected_error_id
                if (-not $isGroupOwned) {
                    $record = Get-Refusal -Relative $case.file
                    $actual = ''
                    if ($null -ne $record) { $actual = $record.FullyQualifiedErrorId }
                    if ($actual -cne ('PortProof.{0}' -f $case.expected_error_id)) { $offenders.Add(('{0}: expected {1} got {2}' -f $case.file, $case.expected_error_id, $actual)) }
                }
            }
        }
        $offenders.Count | Should -Be 0 -Because ($offenders -join '; ')
    }
}

Describe 'Valid fixtures parse cleanly (AC9 valid half)' -Tag 'Portable' {
    It '<Relative>' -ForEach @(
        foreach ($name in 'valid-crlf.csv', 'valid-groups.json', 'valid-ipv4-mapped.csv', 'valid-ipv6-literal.csv',
            'valid-lf.csv', 'valid-minimal.csv', 'valid-minimal.json', 'valid-utf16le-bom.csv') {
            @{ Relative = $name }
        }
    ) {
        $record = Get-Refusal -Relative $Relative
        $record | Should -BeNullOrEmpty -Because ('valid fixtures must parse; got ' + $(if ($record) { $record.Exception.Message }))
    }

    It 'valid-utf16le-bom.csv decodes to the same rows as valid-minimal.csv' {
        $a = Import-PPProfile -Path (Get-FixturePath 'valid-utf16le-bom.csv') -Contract $script:Contract
        $b = Import-PPProfile -Path (Get-FixturePath 'valid-minimal.csv') -Contract $script:Contract
        $a.Rows[0].Target | Should -BeExactly $b.Rows[0].Target
        $a.Format | Should -BeExactly 'Csv'
    }

    It 'valid-groups.json carries its groups block, uppercased, and CSV profiles carry none' {
        $j = Import-PPProfile -Path (Get-FixturePath 'valid-groups.json') -Contract $script:Contract
        $j.Groups['CLIENT'] | Should -BeExactly '10.10.1.5'
        $j.Groups['DC'] | Should -BeExactly 'dc01.corp.example,dc02.corp.example'
        $c = Import-PPProfile -Path (Get-FixturePath 'valid-minimal.csv') -Contract $script:Contract
        $c.Groups.Count | Should -Be 0
        $c.Name | Should -BeExactly 'valid-minimal'
        $c.Version | Should -BeExactly ''
    }

    It 'ProfileSha256 of a known file is deterministic and matches an independent SHA-256' {
        $bytes = [System.IO.File]::ReadAllBytes((Get-FixturePath 'valid-minimal.csv'))
        $reference = ([BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        $p = Import-PPProfile -Path (Get-FixturePath 'valid-minimal.csv') -Contract $script:Contract
        $p.Sha256 | Should -BeExactly $reference
        $p2 = Import-PPProfile -Path (Get-FixturePath 'valid-minimal.csv') -Contract $script:Contract
        $p2.Sha256 | Should -BeExactly $p.Sha256
    }
}

Describe 'Invalid top-level fixtures refuse (AC9 invalid half)' -Tag 'Portable' {
    It '<Relative> -> <ExpectedId>' -ForEach @(
        @{ Relative = 'invalid-domain-port.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'invalid-domain-protocol.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'invalid-domain-required.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'invalid-domain-target.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'invalid-duplicate-row.csv'; ExpectedId = 'Profile.DuplicateRow' }
        @{ Relative = 'invalid-malformed-csv.csv'; ExpectedId = 'Profile.CsvSyntax' }
        @{ Relative = 'invalid-missing-column.csv'; ExpectedId = 'Profile.MissingColumn' }
        @{ Relative = 'invalid-port-range.csv'; ExpectedId = 'Profile.Domain' }
    ) {
        $record = Get-Refusal -Relative $Relative
        $record.FullyQualifiedErrorId | Should -BeExactly ('PortProof.{0}' -f $ExpectedId)
    }

    It 'invalid-unbound-group.csv parses at the parser level (Group.Unbound is the Expander''s job)' {
        # CSV has no groups block; a %CLIENT% Source is a well-formed Group-kind field at parse
        # time - binding and Group.Unbound belong to Expand-PPProfile.
        $record = Get-Refusal -Relative 'invalid-unbound-group.csv'
        $record | Should -BeNullOrEmpty
    }
}

Describe 'Refused literal target classes at parse time (AC15 literal half)' -Tag 'Portable' {
    It '<Relative>' -ForEach @(
        foreach ($name in 'refused-0.0.0.0.csv', 'refused-0.1.2.3.csv', 'refused-169.254.1.1.csv', 'refused-224.0.0.1.csv',
            'refused-239.255.255.250.csv', 'refused-255.255.255.255.csv', 'refused-fe80-1.csv', 'refused-ff02-1.csv',
            'refused-mapped-broadcast.csv', 'refused-mapped-linklocal.csv', 'refused-mapped-multicast.csv', 'refused-unspecified-v6.csv') {
            @{ Relative = $name }
        }
    ) {
        $record = Get-Refusal -Relative $Relative
        $record.FullyQualifiedErrorId | Should -BeExactly 'PortProof.RefusedTargetClass'
        $record.Exception.Message | Should -Match 'row \d+ Target'
    }

    It 'refused-cidr-hostbits.json (Expander''s CIDR check) does not parse at the raw-literal parser level' {
        # %NET% is a Group field at parse time; the CIDR literal-class check happens in
        # Expand-PPProfile/Expand-PPGroupValue, not here.
        $record = Get-Refusal -Relative 'refused-cidr-hostbits.json'
        $record | Should -BeNullOrEmpty
    }
}

Describe 'Hostile fixtures pass through as free text unaltered (escaping is the renderer''s job)' -Tag 'Portable' {
    It 'hostile-ansi-notes.csv is refused (a raw ESC control character in Notes is not let through - it used to be kept verbatim on the theory that escaping is the renderer''s job, but a control character is not printable free text the way a formula/script/path string is, and every other free-text field already refused it)' {
        $record = Get-Refusal -Relative 'hostile-ansi-notes.csv'
        $record.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.Domain'
        $record.Exception.Message | Should -Match 'Notes'
    }
    It 'hostile-formula-service.csv keeps the raw formula text in Service' {
        $p = Import-PPProfile -Path (Get-FixturePath 'hostile-formula-service.csv') -Contract $script:Contract
        $p.Rows[0].Service | Should -BeExactly "=cmd|' /c calc'!A1"
    }
    It 'hostile-script-service.csv keeps the raw markup in Service' {
        $p = Import-PPProfile -Path (Get-FixturePath 'hostile-script-service.csv') -Contract $script:Contract
        $p.Rows[0].Service | Should -BeExactly '<script>alert(1)</script>'
    }
    It 'hostile-path-traversal.csv keeps traversal strings as opaque text in Service/Notes' {
        $p = Import-PPProfile -Path (Get-FixturePath 'hostile-path-traversal.csv') -Contract $script:Contract
        $p.Rows[0].Service | Should -BeExactly '..\..\..\Windows\System32\config\SAM'
        $p.Rows[0].Notes | Should -BeExactly '..%2F..%2F..%2Fetc%2Fpasswd'
    }
    It 'hostile-formula-column.csv ignores the injected column name with a warning, values dropped' {
        $p = Import-PPProfile -Path (Get-FixturePath 'hostile-formula-column.csv') -Contract $script:Contract
        $p.IgnoredColumns | Should -Contain '=HYPERLINK("http://evil","open")'
        $p.Warnings.Count | Should -BeGreaterThan 0
    }
    It 'hostile-json-name-equals.json keeps the raw name/version text (CSV run-header neutralisation is the renderer''s job)' {
        $p = Import-PPProfile -Path (Get-FixturePath 'hostile-json-name-equals.json') -Contract $script:Contract
        $p.Name | Should -BeExactly "=cmd|' /c calc'!A1"
        $p.Version | Should -BeExactly '=1+1'
    }
}

Describe 'Hex/integer/control-character hostile vectors (AC15)' -Tag 'Portable' {
    It '<Relative> -> <ExpectedId>' -ForEach @(
        @{ Relative = 'corpus/hostile-hex-0xffffffff.csv'; ExpectedId = 'RefusedTargetClass' }
        @{ Relative = 'corpus/hostile-hex-0xe0000001.csv'; ExpectedId = 'RefusedTargetClass' }
        @{ Relative = 'corpus/hostile-hex-dotted-0xff.csv'; ExpectedId = 'RefusedTargetClass' }
        @{ Relative = 'corpus/hostile-hex-0x7f1.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'corpus/hostile-trailing-lf.json'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'corpus/hostile-control-esc-target.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'corpus/hostile-control-lf-target.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'corpus/hostile-control-leading-space.csv'; ExpectedId = 'Profile.Domain' }
        @{ Relative = 'corpus/csv-syntax-unquoted-lf.csv'; ExpectedId = 'Profile.CsvSyntax' }
    ) {
        $record = Get-Refusal -Relative $Relative
        $record.FullyQualifiedErrorId | Should -BeExactly ('PortProof.{0}' -f $ExpectedId)
    }

    It '<Text> -> <Kind> (direct grammar vectors)' -ForEach @(
        @{ Text = '0x0'; Kind = 'NonCanonicalLiteral' }
        @{ Text = '0X7F000001'; Kind = 'NonCanonicalLiteral' }
        @{ Text = '10.1'; Kind = 'NonCanonicalLiteral' }
        @{ Text = '3232235777'; Kind = 'NonCanonicalLiteral' }
        @{ Text = '010.0.0.1'; Kind = 'NonCanonicalLiteral' }
        @{ Text = '1.2.3'; Kind = 'NonCanonicalLiteral' }
        @{ Text = '[::1]'; Kind = 'NonCanonicalLiteral' }
        @{ Text = 'fe80::1%12'; Kind = 'NonCanonicalLiteral' }
        @{ Text = '0xg.test'; Kind = 'Hostname' }
        @{ Text = '00x1.test'; Kind = 'Hostname' }
        @{ Text = 'cafe.be'; Kind = 'Hostname' }
        @{ Text = '0x1f.example'; Kind = 'Invalid' }
    ) {
        (Get-PPTargetKind -Text $Text).Kind | Should -BeExactly $Kind
    }
}

Describe 'Bytes-to-text decode' -Tag 'Portable' {
    It '<Relative> -> Profile.Encoding' -ForEach @(
        foreach ($name in 'corpus/encoding-invalid-utf8.csv', 'corpus/encoding-utf16-no-bom.csv',
            'corpus/encoding-utf32-bom.csv', 'corpus/encoding-nul-byte.csv') {
            @{ Relative = $name }
        }
    ) {
        $record = Get-Refusal -Relative $Relative
        $record.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.Encoding'
    }

    It 'reads at most MaxProfileBytes + 1 bytes from the stream itself, not a stale Length (TOCTOU: the file grows after the caller''s own existence check, between opening the stream and reading it)' {
        $path = Join-Path $TestDrive 'growing.csv'
        $small = "Source,Target,Port,Protocol,Required`r`nclient,dc01.corp.example,389,TCP,yes`r`n"
        [System.IO.File]::WriteAllText($path, $small)
        $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            # The stream's own reported Length (captured here) reflects the small file - a naive
            # reader that trusted Length/FileInfo would not refuse. Grow the file underneath the
            # open handle via a second, sharing handle before the bounded read runs.
            $reportedLengthAtOpen = $stream.Length
            $extra = [string]::new('x', 200)
            [System.IO.File]::AppendAllText($path, $extra)
            $tinyContract = @{ MaxProfileBytes = ($small.Length + 10); MaxJsonDepth = 8 }
            { Read-PPProfileText -Stream $stream -Contract $tinyContract } | Should -Throw '*profile exceeds*'
            $reportedLengthAtOpen | Should -BeLessThan ($small.Length + $extra.Length)
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'a file at exactly MaxProfileBytes is accepted; one byte over is refused' {
        $header = "Source,Target,Port,Protocol,Required`r`nclient,dc01.corp.example,389,TCP,yes`r`n"
        $pad = $header.Length
        $atLimitPath = Join-Path $TestDrive 'at-limit.csv'
        $overLimitPath = Join-Path $TestDrive 'over-limit.csv'
        [System.IO.File]::WriteAllText($atLimitPath, $header)
        [System.IO.File]::WriteAllText($overLimitPath, $header + ' ')
        $contract = @{ MaxProfileBytes = $pad }
        $s1 = [System.IO.File]::Open($atLimitPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { { Read-PPProfileText -Stream $s1 -Contract $contract } | Should -Not -Throw } finally { $s1.Dispose() }
        $s2 = [System.IO.File]::Open($overLimitPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try { { Read-PPProfileText -Stream $s2 -Contract $contract } | Should -Throw '*profile exceeds*' } finally { $s2.Dispose() }
    }
}

Describe 'From-scratch SHA-256 (Get-PPSha256Hex) against .NET''s own implementation' -Tag 'Portable' {
    BeforeAll {
        $script:Sha = [System.Security.Cryptography.SHA256]::Create()
        function Get-ReferenceHash([byte[]] $Bytes) {
            ([BitConverter]::ToString($script:Sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
        }
    }

    It '<Label>' -ForEach @(
        @{ Label = 'empty input'; Bytes = [byte[]]@() }
        @{ Label = 'short ASCII (abc)'; Bytes = [System.Text.Encoding]::UTF8.GetBytes('abc') }
        @{ Label = 'exactly 55 bytes (last byte before the padding boundary shifts)'; Bytes = [byte[]]::new(55) }
        @{ Label = 'exactly 56 bytes (padding needs a whole extra block)'; Bytes = [byte[]]::new(56) }
        @{ Label = 'exactly 64 bytes (one full block, no fill)'; Bytes = [byte[]]::new(64) }
        @{ Label = 'exactly 119 bytes'; Bytes = [byte[]]::new(119) }
        @{ Label = 'exactly 120 bytes'; Bytes = [byte[]]::new(120) }
        @{ Label = '1000 ASCII bytes'; Bytes = [System.Text.Encoding]::UTF8.GetBytes([string]::new('x', 1000)) }
    ) {
        Get-PPSha256Hex -Bytes $Bytes | Should -BeExactly (Get-ReferenceHash $Bytes)
    }

    It 'matches across a length sweep (1..130 bytes, deterministic pseudo-random content)' {
        $random = [System.Random]::new(20260925)
        for ($n = 1; $n -le 130; $n++) {
            $bytes = [byte[]]::new($n)
            $random.NextBytes($bytes)
            Get-PPSha256Hex -Bytes $bytes | Should -BeExactly (Get-ReferenceHash $bytes) -Because "length $n"
        }
    }

    It 'matches for a multi-chunk input (70000 bytes)' {
        $random = [System.Random]::new(7)
        $bytes = [byte[]]::new(70000)
        $random.NextBytes($bytes)
        Get-PPSha256Hex -Bytes $bytes | Should -BeExactly (Get-ReferenceHash $bytes)
    }
}

Describe 'CSV syntax primitives' -Tag 'Portable' {
    It 'ConvertFrom-PPCsvText drops one true trailing empty line but keeps an interior one' {
        $records = ConvertFrom-PPCsvText -Text "a,b`r`nc,d`r`n" -MaxRecords 8193
        $records.Count | Should -Be 2
        $records2 = ConvertFrom-PPCsvText -Text "a,b`r`n`r`nc,d" -MaxRecords 8193
        $records2.Count | Should -Be 3
        $records2[1].Length | Should -Be 1
    }
    It 'handles a doubled quote inside a quoted field' {
        # Single-quoted PowerShell string so the embedded " characters are literal, with no PS-level
        # escaping to get confused with the CSV-level "" escape: raw CSV text is a,"say ""hi"""\r\n
        $records = ConvertFrom-PPCsvText -Text ('a,"say ""hi"""' + "`r`n") -MaxRecords 8193
        $records[0][1] | Should -BeExactly 'say "hi"'
    }
    It 'never throws on hostile input to Get-PPTargetKind (defence in depth alongside the contract layer''s own fuzz test)' {
        $vectors = @('', ' ', "`t", [string][char]0, [string][char]0x2028, '%', '%%', '..', '\\evil', ('a' * 5000))
        foreach ($v in $vectors) { { Get-PPTargetKind -Text $v } | Should -Not -Throw }
    }
}

Describe 'Count-while-reading: no hostile size runs unbounded before refusal' -Tag 'Portable' {
    It 'a 2M-element JSON rows array refuses Profile.TooLarge in under 5 seconds' {
        # 5 s, not 2 s: a full-suite run on a loaded CI box measured this at 2154 ms once against the
        # original 2 s bound - a real flake, not a real regression. The absolute number here is a
        # loose backstop; the test below (a 10x larger claim costing about the same) is what actually
        # proves count-while-reading, independent of how fast or loaded the box happens to be.
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('{ "schema": "portproof-profile/1", "name": "x", "rows": [')
        for ($i = 0; $i -lt 2000000; $i++) {
            if ($i -gt 0) { [void]$sb.Append(',') }
            [void]$sb.Append('0')
        }
        [void]$sb.Append('] }')
        $json = $sb.ToString()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            ConvertFrom-PPStrictJson -Text $json -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
            throw 'expected a refusal'
        }
        catch {
            $sw.Stop()
            $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.TooLarge'
        }
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It 'refusal time does not scale with a 10x larger claimed size (a 20M-element claim costs about the same as 2M) - this, not one absolute number, is what proves count-while-reading' {
        # This exercises ConvertFrom-PPStrictJson directly, not the full profile-file byte cap
        # (MaxProfileBytes bounds a real FILE elsewhere, in Read-PPProfileText) - 20,000,000 elements
        # is a claimed array size no MaxProfileBytes-compliant file could ever contain, which is
        # exactly the point: the fix must refuse just as fast for an absurd claim as for a merely
        # large one. String replication ('0,' * N), not a per-element append loop, builds even the
        # 20M-element text in low single-digit milliseconds, so building it is not what is measured.
        function Measure-JsonArrayRefusalTime {
            param([int] $ElementCount)
            $json = '{ "schema": "portproof-profile/1", "name": "x", "rows": [' + (('0,' * $ElementCount) + '0') + '] }'
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                ConvertFrom-PPStrictJson -Text $json -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
                throw 'expected a refusal'
            }
            catch {
                $sw.Stop()
                $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.TooLarge'
            }
            return $sw.ElapsedMilliseconds
        }
        $ms2m = Measure-JsonArrayRefusalTime -ElementCount 2000000
        $ms20m = Measure-JsonArrayRefusalTime -ElementCount 20000000
        # 1.5x the 2M measurement, plus a small fixed allowance so a very fast (and therefore
        # noise-sensitive) $ms2m can't make this flaky on its own.
        $bound = ($ms2m * 1.5) + 500
        $ms20m | Should -BeLessThan $bound -Because "2M measured ${ms2m}ms, so 20M (10x the claimed size) should stay near it, not scale with it"
    }

    It '4M blank CSV lines refuse Profile.TooLarge in under 5 seconds, with bounded memory (no 4M-record allocation)' {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append("Source,Target,Port,Protocol,Required`r`n")
        for ($i = 0; $i -lt 4000000; $i++) { [void]$sb.Append("`n") }
        $csv = $sb.ToString()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            ConvertFrom-PPCsvText -Text $csv -MaxRecords 8193
            throw 'expected a refusal'
        }
        catch {
            $sw.Stop()
            $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.TooLarge'
        }
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It 'a legitimate 8192-row JSON document still parses (the cap does not fire early on a compliant document)' {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('{ "schema": "portproof-profile/1", "name": "x", "rows": [')
        for ($i = 0; $i -lt 8192; $i++) {
            if ($i -gt 0) { [void]$sb.Append(',') }
            [void]$sb.Append('{ "source": "a", "target": "10.0.0.1", "port": 443, "protocol": "TCP", "required": "yes" }')
        }
        [void]$sb.Append('] }')
        $value = ConvertFrom-PPStrictJson -Text $sb.ToString() -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
        $value.Data['rows'].Data.Count | Should -Be 8192
    }

    It 'a 140,000-member JSON object (e.g. a hostile "groups" block) refuses Profile.TooLarge in under 5 seconds' {
        # Same shape as the review's own finding: a groups-like object with far more members than
        # any legitimate profile could use, well under MaxProfileBytes (3.28 MB per the finding).
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('{ "schema": "portproof-profile/1", "name": "x", "groups": {')
        for ($i = 0; $i -lt 140000; $i++) {
            if ($i -gt 0) { [void]$sb.Append(',') }
            [void]$sb.Append('"G')
            [void]$sb.Append($i)
            [void]$sb.Append('":"10.0.0.1"')
        }
        [void]$sb.Append('}, "rows": [ { "source": "a", "target": "10.0.0.2", "port": 443, "protocol": "TCP", "required": "yes" } ] }')
        $json = $sb.ToString()
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            ConvertFrom-PPStrictJson -Text $json -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
            throw 'expected a refusal'
        }
        catch {
            $sw.Stop()
            $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.TooLarge'
        }
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It 'a legitimate groups object still parses (the member cap does not fire early on a compliant profile)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "CLIENT": "10.0.0.1", "DC": "dc01.corp.example,dc02.corp.example" }, "rows": [ { "source": "%CLIENT%", "target": "%DC%", "port": 389, "protocol": "TCP", "required": "yes" } ] }'
        $value = ConvertFrom-PPStrictJson -Text $json -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
        $value.Data['groups'].Data.Count | Should -Be 2
        $value.Data['groups'].Data['CLIENT'] | Should -BeExactly '10.0.0.1'
        # Also through the full Import-PPProfile path, end to end.
        $p = Import-PPProfile -Path (Get-FixturePath 'valid-groups.json') -Contract $script:Contract
        $p.Groups['CLIENT'] | Should -BeExactly '10.10.1.5'
    }
}

Describe 'Containers nested under rows[] parsed in full before shape validation' -Tag 'Portable' {
    BeforeAll {
        # Plain script-scope functions defined directly in a Describe body (not inside BeforeAll)
        # only exist at Pester DISCOVERY time - the same discovery/run scope split noted at the top
        # of this file - so anything an It needs at RUN time must be (re)defined inside BeforeAll.
        function script:New-NestedContainerRepro {
            # The review's own repro: 255 sibling arrays of 8192 zeros each (4.18 MB, under every
            # existing cap at the time). Each inner array, alone, is within MaxItems (8192); none of
            # the 255 arrays nests past the schema's own depth (an array standing where a row object
            # belongs sits at the *same* depth a legitimate row object would) - so neither the
            # per-container MaxItems cap nor the finding 1(a) schema-depth check alone catches this;
            # finding 1(b)'s document-wide $ValueBudget is what actually stops it.
            param([int] $ArrayCount = 255, [int] $ZerosPerArray = 8192)
            $inner = '[' + (('0,' * ($ZerosPerArray - 1)) + '0') + ']'
            $sb = [System.Text.StringBuilder]::new()
            [void]$sb.Append('{"schema":"portproof-profile/1","name":"x","rows":[')
            for ($i = 0; $i -lt $ArrayCount; $i++) {
                if ($i -gt 0) { [void]$sb.Append(',') }
                [void]$sb.Append($inner)
            }
            [void]$sb.Append(']}')
            return $sb.ToString()
        }
    }

    It 'the review''s exact repro (255 arrays x 8192 zeros) refuses Profile.TooLarge in under 5 seconds' {
        $json = New-NestedContainerRepro
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            ConvertFrom-PPStrictJson -Text $json -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
            throw 'expected a refusal'
        }
        catch {
            $sw.Stop()
            $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.TooLarge'
        }
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It 'the same repro refuses in under 5 seconds through the full Import-PPProfile file path (the review''s own real-world shape: a hostile file, not a raw parser call)' {
        $path = Join-Path $TestDrive 'finding1-repro.json'
        [System.IO.File]::WriteAllText($path, (New-NestedContainerRepro))
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            Import-PPProfile -Path $path -Contract $script:Contract
            throw 'expected a refusal'
        }
        catch {
            $sw.Stop()
            $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.TooLarge'
        }
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It 'refusal time does not scale with a 10x larger claim (2550 arrays costs about the same as 255) - proves the document-wide budget, not the absolute number' {
        function script:Measure-NestedContainerRefusalTime {
            param([int] $ArrayCount)
            $json = New-NestedContainerRepro -ArrayCount $ArrayCount
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                ConvertFrom-PPStrictJson -Text $json -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
                throw 'expected a refusal'
            }
            catch {
                $sw.Stop()
                $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.TooLarge'
            }
            return $sw.ElapsedMilliseconds
        }
        $ms1x = Measure-NestedContainerRefusalTime -ArrayCount 255
        $ms10x = Measure-NestedContainerRefusalTime -ArrayCount 2550
        $bound = ($ms1x * 1.5) + 500
        $ms10x | Should -BeLessThan $bound -Because "255 arrays measured ${ms1x}ms, so 2550 arrays (10x the claimed size) should stay near it, not scale with it"
    }

    It 'a container opening one level past the schema''s real depth (finding 1(a)) refuses Profile.JsonDepth - a minimal, cheap unit case distinct from the value-budget mechanism above' {
        # root(0) -> rows array(1) -> row object(2, the legitimate maximum) -> a nested object
        # inside one of the row's own field values opens at incoming Depth 3, which the schema
        # never needs (a row's fields are always scalars) and is refused outright. The id for this
        # is Profile.JsonDepth, not JsonSyntax - the problem is nesting depth, and JsonDepth names
        # it exactly and stays reachable; the generic MaxDepth=8 check below is kept as defence in
        # depth.
        $json = '{"schema":"portproof-profile/1","name":"x","rows":[{"source":"a","target":"10.0.0.1","port":443,"protocol":"TCP","required":"yes","extra":{"nested":1}}]}'
        try {
            ConvertFrom-PPStrictJson -Text $json -MaxDepth 8 -MaxItems 8192 -MaxValues ([int]$script:Contract.MaxProfileRows * 16)
            throw 'expected a refusal'
        }
        catch {
            $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.JsonDepth'
        }
    }

    It 'corpus/json-depth-exceeded.json (9 levels of array nesting under an unrelated top-level key) still refuses Profile.JsonDepth - the schema-depth check (>= 3) necessarily fires before the generic MaxDepth check (> 8) ever could for any real container nesting, but both now share the one id, so the corpus''s own expectation holds unchanged' {
        $record = Get-Refusal -Relative 'corpus/json-depth-exceeded.json'
        $record.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.JsonDepth'
    }

    It 'a legitimate 8192-row profile still parses end to end through Import-PPProfile under the new depth and value-budget checks' {
        # Port varies per row (1..8192, well within 1..65535) so no two rows collide on the
        # Source|Target|Port|Protocol duplicate-row key - a distinct concern from this test's own
        # point (depth/value-budget), so it is sidestepped rather than exercised here.
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('{"schema":"portproof-profile/1","name":"x","rows":[')
        for ($i = 0; $i -lt 8192; $i++) {
            if ($i -gt 0) { [void]$sb.Append(',') }
            [void]$sb.Append('{"source":"a","target":"10.0.0.1","port":')
            [void]$sb.Append($i + 1)
            [void]$sb.Append(',"protocol":"TCP","required":"yes","service":"svc","notes":"note"}')
        }
        [void]$sb.Append(']}')
        $path = Join-Path $TestDrive 'legit-8192.json'
        [System.IO.File]::WriteAllText($path, $sb.ToString())
        $p = Import-PPProfile -Path $path -Contract $script:Contract
        $p.Rows.Count | Should -Be 8192
        $p.Rows[8191].Target | Should -BeExactly '10.0.0.1'
    }
}

Describe 'Control characters in Service/Notes (extending the Source/Target rule to every free-text field)' -Tag 'Portable' {
    It '<Field> containing <Name> (<Hex>) refuses Profile.Domain in a CSV row' -ForEach @(
        @{ Field = 'Service'; Name = 'ESC'; Char = [char]0x1B }
        @{ Field = 'Service'; Name = 'BEL'; Char = [char]0x07 }
        @{ Field = 'Service'; Name = 'C1 NEL'; Char = [char]0x85 }
        @{ Field = 'Notes'; Name = 'ESC'; Char = [char]0x1B }
        @{ Field = 'Notes'; Name = 'BEL'; Char = [char]0x07 }
        @{ Field = 'Notes'; Name = 'C1 NEL'; Char = [char]0x85 }
        @{ Field = 'Notes'; Name = 'lone CR'; Char = [char]0x0D }
    ) {
        $hex = '{0:X2}' -f [int]$Char
        # Quoted (RFC 4180): a raw CR/LF inside a field must be quoted to survive as field content
        # rather than being read as a record terminator - ESC/BEL/NEL do not need it, but quoting
        # is valid regardless of content, so the same construction covers the CR case too.
        $service = if ($Field -eq 'Service') { "`"x$($Char)y`"" } else { 'plain-service' }
        $notes = if ($Field -eq 'Notes') { "`"x$($Char)y`"" } else { 'plain-notes' }
        $csv = "Source,Target,Port,Protocol,Required,Service,Notes`r`nclient,dc01.corp.example,443,TCP,yes,$service,$notes`r`n"
        $path = Join-Path $TestDrive "control-char-$Field-$hex.csv"
        [System.IO.File]::WriteAllText($path, $csv, [System.Text.UTF8Encoding]::new($false))
        $record = $null
        try { [void](Import-PPProfile -Path $path -Contract $script:Contract) } catch { $record = $_ }
        $record | Should -Not -BeNullOrEmpty -Because "a raw $Name in $Field must be refused, not passed through"
        $record.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.Domain'
        $record.Exception.Message | Should -Match $Field
    }

    It '<Field> containing <Name> (<Hex>) refuses Profile.Domain in a JSON row' -ForEach @(
        @{ Field = 'service'; Name = 'ESC'; Escaped = '\u001b' }
        @{ Field = 'service'; Name = 'BEL'; Escaped = '\u0007' }
        @{ Field = 'service'; Name = 'C1 NEL'; Escaped = '\u0085' }
        @{ Field = 'notes'; Name = 'ESC'; Escaped = '\u001b' }
        @{ Field = 'notes'; Name = 'BEL'; Escaped = '\u0007' }
        @{ Field = 'notes'; Name = 'C1 NEL'; Escaped = '\u0085' }
        @{ Field = 'notes'; Name = 'lone CR'; Escaped = '\r' }
    ) {
        # Escaped as a \uXXXX (or \r) JSON escape, not a raw byte: the strict reader's own grammar
        # already rejects a raw/unescaped control character inside any JSON string (Read-PPJsonString's
        # "a raw control character is not permitted" rule) - the point of MINOR#3 is the *legally
        # escaped* case, which decodes to a real control character and needs this separate,
        # semantic per-field check.
        $serviceValue = if ($Field -eq 'service') { "x${Escaped}y" } else { 'plain-service' }
        $notesValue = if ($Field -eq 'notes') { "x${Escaped}y" } else { 'plain-notes' }
        $json = '{"schema":"portproof-profile/1","name":"x","rows":[{"source":"client","target":"dc01.corp.example","port":443,"protocol":"TCP","required":"yes","service":"' + $serviceValue + '","notes":"' + $notesValue + '"}]}'
        $path = Join-Path $TestDrive "control-char-json-$Field-$($Name -replace '\s', '').json"
        [System.IO.File]::WriteAllText($path, $json, [System.Text.UTF8Encoding]::new($false))
        $record = $null
        try { [void](Import-PPProfile -Path $path -Contract $script:Contract) } catch { $record = $_ }
        $record | Should -Not -BeNullOrEmpty -Because "a legally-escaped $Name decoded into $Field must still be refused"
        $record.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Profile.Domain'
        $record.Exception.Message | Should -Match $Field
    }

    It 'a plain Service/Notes value with ordinary punctuation and no control characters still parses (the new check does not over-refuse)' {
        $csv = "Source,Target,Port,Protocol,Required,Service,Notes`r`nclient,dc01.corp.example,443,TCP,yes,LDAP (389),`"multi, word, notes`"`r`n"
        $path = Join-Path $TestDrive 'control-char-negative.csv'
        [System.IO.File]::WriteAllText($path, $csv, [System.Text.UTF8Encoding]::new($false))
        $p = Import-PPProfile -Path $path -Contract $script:Contract
        $p.Rows[0].Service | Should -BeExactly 'LDAP (389)'
        $p.Rows[0].Notes | Should -BeExactly 'multi, word, notes'
    }
}
