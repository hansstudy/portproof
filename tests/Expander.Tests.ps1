# Expander tests. Dot-sources 05-Contract.ps1, 10-Parser.ps1 and
# 20-Expander.ps1 - nothing here resolves a name or opens a socket.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:Root 'src/05-Contract.ps1')
    . (Join-Path $script:Root 'src/10-Parser.ps1')
    . (Join-Path $script:Root 'src/20-Expander.ps1')
    $script:FixturesRoot = Join-Path $script:Root 'tests/Fixtures'
    $script:Contract = Get-PPContract

    function Get-FixturePath {
        param([Parameter(Mandatory)] [string] $Relative)
        Join-Path $script:FixturesRoot $Relative
    }

    function Get-ExpandResult {
        # Imports a fixture then expands it; returns @{ Expansion; Error }, at most one non-null.
        param(
            [Parameter(Mandatory)] [string] $Relative,
            [string[]] $Bindings = @(),
            [switch] $AllowCidr
        )
        try {
            $profileDocument = Import-PPProfile -Path (Get-FixturePath $Relative) -Contract $script:Contract
            $expansion = Expand-PPProfile -ProfileDocument $profileDocument -Bindings $Bindings -AllowCidr:$AllowCidr -Contract $script:Contract
            return [pscustomobject]@{ Expansion = $expansion; Error = $null }
        }
        catch {
            return [pscustomobject]@{ Expansion = $null; Error = $_ }
        }
    }

    function Write-ScratchProfile {
        # Writes $Json under $TestDrive and returns its full path.
        param([Parameter(Mandatory)] [string] $Json, [string] $Name = 'scratch.json')
        $path = Join-Path $TestDrive $Name
        [System.IO.File]::WriteAllText($path, $Json)
        return $path
    }

    function Get-ExpandJson {
        param([Parameter(Mandatory)] [string] $Json, [string[]] $Bindings = @(), [switch] $AllowCidr, [string] $Name = 'scratch.json', [long] $EffectiveCap = 0)
        $path = Write-ScratchProfile -Json $Json -Name $Name
        try {
            $profileDocument = Import-PPProfile -Path $path -Contract $script:Contract
            $expansion = Expand-PPProfile -ProfileDocument $profileDocument -Bindings $Bindings -AllowCidr:$AllowCidr -EffectiveCap $EffectiveCap -Contract $script:Contract
            return [pscustomobject]@{ Expansion = $expansion; Error = $null }
        }
        catch {
            return [pscustomobject]@{ Expansion = $null; Error = $_ }
        }
    }

    function Invoke-InCulture {
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

Describe 'Group corpus cases (AC15 CIDR half)' -Tag 'Portable' {
    It '<Relative> -> <ExpectedId>' -ForEach @(
        @{ Relative = 'corpus/json-group-unbound.json'; ExpectedId = 'Group.Unbound'; Bindings = @(); AllowCidr = $false }
        @{ Relative = 'corpus/json-group-nested.json'; ExpectedId = 'Group.Nested'; Bindings = @('BAR=1.2.3.4'); AllowCidr = $false }
        @{ Relative = 'corpus/json-group-cidr-no-switch.json'; ExpectedId = 'Group.CidrNotAllowed'; Bindings = @(); AllowCidr = $false }
        # VLSM support: corpus/json-group-cidr-16.json (10.10.0.0/16) and
        # corpus/json-group-cidr-31.json (10.10.5.0/31) both asserted the old 24..30-only limit
        # (cases.csv rows 53/54 still say so too and are stale, but that fixture file is out of
        # scope here). Under the new 8..32 range: /16 is a valid prefix but its 65534 hosts still
        # exceed the default cap, so it is now refused CapExceeded.Expansion, not CidrTooWide; /31
        # is now a fully valid, successfully-expanding CIDR (RFC 3021) and is no longer a refusal
        # case at all - moved to its own positive test in the CIDR expansion Describe below.
        @{ Relative = 'corpus/json-group-cidr-16.json'; ExpectedId = 'CapExceeded.Expansion'; Bindings = @(); AllowCidr = $true }
        @{ Relative = 'corpus/json-group-hostbits.json'; ExpectedId = 'Group.CidrNotAligned'; Bindings = @(); AllowCidr = $true }
        @{ Relative = 'corpus/json-group-ipv6-cidr.json'; ExpectedId = 'Group.CidrIPv6'; Bindings = @(); AllowCidr = $true }
        @{ Relative = 'corpus/json-group-cidr-in-source.json'; ExpectedId = 'Group.CidrInSource'; Bindings = @(); AllowCidr = $true }
        @{ Relative = 'corpus/json-group-oversize.json'; ExpectedId = 'Group.TooLarge'; Bindings = @(); AllowCidr = $false }
        @{ Relative = 'corpus/json-group-syntax.json'; ExpectedId = 'Group.Syntax'; Bindings = @(); AllowCidr = $false }
        @{ Relative = 'refused-cidr-hostbits.json'; ExpectedId = 'Group.CidrNotAligned'; Bindings = @(); AllowCidr = $true }
    ) {
        $result = Get-ExpandResult -Relative $Relative -Bindings $Bindings -AllowCidr:$AllowCidr
        $result.Expansion | Should -BeNullOrEmpty
        $result.Error.FullyQualifiedErrorId | Should -BeExactly ('PortProof.{0}' -f $ExpectedId)
    }

    It 'json-group-ipv6-cidr.json refuses IPv6 CIDR regardless of -AllowCidr (it is not the switch that is missing)' {
        $result = Get-ExpandResult -Relative 'corpus/json-group-ipv6-cidr.json' -AllowCidr
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrIPv6'
    }
}

Describe 'Bindings: -Set overrides JSON groups, semicolon pieces, comma lists' -Tag 'Portable' {
    It '-Set overrides a JSON groups entry and records it in GroupOverrides' {
        $result = Get-ExpandResult -Relative 'valid-groups.json' -Bindings @('CLIENT=10.20.30.40')
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.GroupOverrides | Should -Contain 'CLIENT'
        $result.Expansion.Rows[0].SourceIp | Should -BeExactly '10.20.30.40'
    }

    It 'a -Set binding for a group the profile never defined is not an override' {
        $result = Get-ExpandResult -Relative 'valid-minimal.csv' -Bindings @('UNUSED=10.0.0.9')
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.GroupOverrides.Count | Should -Be 0
        $result.Expansion.UnusedGroups | Should -Contain 'UNUSED'
    }

    It 'ConvertFrom-PPBinding splits at the first ''='' only' {
        $b = ConvertFrom-PPBinding -Text 'DC=dc01.corp.example=x'
        $b.Name | Should -BeExactly 'DC'
        $b.Value | Should -BeExactly 'dc01.corp.example=x'
    }

    It 'several ";"-joined -Set pieces each bind independently (Assert-Arguments splits them; the Expander receives Bindings already split)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "rows": [ { "source": "%A%", "target": "%B%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -Bindings @('A=10.0.0.1', 'B=10.0.0.2')
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Rows[0].SourceIp | Should -BeExactly '10.0.0.1'
        $result.Expansion.Probes[0].Target | Should -BeExactly '10.0.0.2'
    }

    It 'a comma list binds every item and each becomes its own probe' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "DC": "dc01.corp.example,dc02.corp.example,10.0.0.9" }, "rows": [ { "source": "client", "target": "%DC%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Rows.Count | Should -Be 3
        $result.Expansion.Probes.Count | Should -Be 3
        (@($result.Expansion.Probes.Target) | Sort-Object) | Should -Be (@('10.0.0.9', 'dc01.corp.example', 'dc02.corp.example') | Sort-Object)
    }
}

Describe 'CIDR expansion' -Tag 'Portable' {
    It '10.1.2.0/30 expands to exactly .1 and .2, in order' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.1.2.0/30" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error | Should -BeNullOrEmpty
        @($result.Expansion.Probes.Target) | Should -Be @('10.1.2.1', '10.1.2.2')
    }

    It '/24 expands to exactly 254 hosts, network and broadcast excluded' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.5.5.0/24" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Probes.Count | Should -Be 254
        $result.Expansion.Probes.Target | Should -Not -Contain '10.5.5.0'
        $result.Expansion.Probes.Target | Should -Not -Contain '10.5.5.255'
    }

    It 'CIDR is refused without -AllowCidr' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.0.0.0/24" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrNotAllowed'
    }

    It '/16 without -AllowLarge (default EffectiveCap) is refused before build, quickly (/16 is a valid prefix, but its 65534 hosts still exceed DefaultCeiling(1024) x ExpansionFactor(8) = 8192, so it is refused by the same pass-1 arithmetic every other oversized expansion uses - not by the prefix-range check)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.0.0.0/16" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Get-ExpandJson -Json $json -AllowCidr
        $sw.Stop()
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.Expansion'
        $sw.ElapsedMilliseconds | Should -BeLessThan 2000
    }

    It '/8 is refused fast (16,777,214 hosts - pure O(1) arithmetic in Get-PPCidrPlan, never enumerated, so refusal is instant regardless of how wide the prefix claims to be)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.0.0.0/8" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Get-ExpandJson -Json $json -AllowCidr
        $sw.Stop()
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.Expansion'
        $sw.ElapsedMilliseconds | Should -BeLessThan 2000
    }

    It '/0 never reaches the 2^(32-prefix) arithmetic: the prefix-range refusal fires first (the valid range is 8..32 - /0 is still outside it)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "0.0.0.0/0" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrTooWide'
        # And the same prefix, even further out, still refuses cleanly and instantly (no overflow,
        # no wrap to a small or negative count).
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $json2 = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "255.255.255.255/1" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result2 = Get-ExpandJson -Json $json2 -AllowCidr -Name 'scratch2.json'
        $sw.Stop()
        $result2.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrTooWide'
        $sw.ElapsedMilliseconds | Should -BeLessThan 2000
    }

    It 'a prefix outside the new 8..32 range is still refused (7 too wide, 33 not parseable as a valid prefix at all - covers the new boundary, not the old 24..30 one)' -ForEach @(
        @{ Prefix = 7 }
        @{ Prefix = 6 }
        @{ Prefix = 1 }
    ) {
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "NET": "10.9.9.0/{0}" }}, "rows": [ {{ "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $Prefix
        $result = Get-ExpandJson -Json $json -AllowCidr -Name ('scratch-toowide-{0}.json' -f $Prefix)
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrTooWide'
    }

    It '8..30 stay [long]-correct at every prefix (VLSM support means every prefix in this range is valid, not only 24..30; network and broadcast excluded, as before)' -ForEach @(
        @{ Prefix = 8; Expected = 16777214 }
        @{ Prefix = 16; Expected = 65534 }
        @{ Prefix = 22; Expected = 1022 }
        @{ Prefix = 23; Expected = 510 }
        @{ Prefix = 24; Expected = 254 }
        @{ Prefix = 25; Expected = 126 }
        @{ Prefix = 26; Expected = 62 }
        @{ Prefix = 27; Expected = 30 }
        @{ Prefix = 28; Expected = 14 }
        @{ Prefix = 29; Expected = 6 }
        @{ Prefix = 30; Expected = 2 }
    ) {
        # A wide prefix (/8, /16, /22, /23) would exceed the default cap, so this measures the
        # *count* via Measure-PPGroupItemCount directly (pure arithmetic, pass 1) rather than
        # building the full expansion for prefixes too large for -Suite Full to enumerate in the
        # test run - /24 through /30 are additionally proven end to end (built and counted for
        # real) below, since they are small enough to build in full.
        # 10.0.0.0 (not 10.9.9.0): aligned for every prefix from /8 up to /30 at once, since every
        # bit past the first octet is already zero.
        $count = Measure-PPGroupItemCount -GroupName 'NET' -Value ('10.0.0.0/{0}' -f $Prefix) -AllowCidr -Origin 'Target' -Row 1 -Contract $script:Contract
        $count | Should -Be $Expected
    }

    It '/22, /27 and /30 expand to the right counts end to end (built in full, not just counted)' -ForEach @(
        @{ Prefix = 22; Expected = 1022 }
        @{ Prefix = 27; Expected = 30 }
        @{ Prefix = 30; Expected = 2 }
    ) {
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "NET": "10.8.0.0/{0}" }}, "rows": [ {{ "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $Prefix
        $result = Get-ExpandJson -Json $json -AllowCidr -EffectiveCap 8192 -Name ('scratch-e2e-{0}.json' -f $Prefix)
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Probes.Count | Should -Be $Expected
    }

    It 'an aligned /22 through -Set works' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -Bindings @('NET=10.4.0.0/22') -AllowCidr -EffectiveCap 8192 -Name 'set-aligned-22.json'
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Probes.Count | Should -Be 1022
        $result.Expansion.Probes.Target | Should -Not -Contain '10.4.0.0'
        $result.Expansion.Probes.Target | Should -Not -Contain '10.4.3.255'
    }

    It 'misaligned /22 is refused' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -Bindings @('NET=10.4.1.0/22') -AllowCidr -Name 'set-misaligned-22.json'
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrNotAligned'
    }

    It '/31 is accepted (RFC 3021 point-to-point): both addresses are usable, no network/broadcast to exclude' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.10.5.0/31" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error | Should -BeNullOrEmpty
        @($result.Expansion.Probes.Target | Sort-Object) | Should -Be @('10.10.5.0', '10.10.5.1')
    }

    It '/32 is accepted (single host route): the one address is directly usable' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.10.5.9/32" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error | Should -BeNullOrEmpty
        @($result.Expansion.Probes.Target) | Should -Be @('10.10.5.9')
    }

    It 'a misaligned /31 (odd starting address) is still refused Group.CidrNotAligned - RFC 3021 does not exempt the alignment rule itself' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.10.5.1/31" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrNotAligned'
    }

    It 'host bits set in a /24 is refused (use the network address)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.10.5.5/24" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrNotAligned'
    }

    It 'IPv6 CIDR is refused regardless of prefix' -ForEach @(
        @{ Value = 'fe80::/64' }
        @{ Value = '2001:db8::/32' }
    ) {
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "NET": "{0}" }}, "rows": [ {{ "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $Value
        $result = Get-ExpandJson -Json $json -AllowCidr -Name ('scratch-v6-{0}.json' -f ($Value -replace '[:/]', '_'))
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrIPv6'
    }

    It 'a CIDR group referenced from Source is refused even though the same group would be fine from Target' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.10.5.0/24" }, "rows": [ { "source": "%NET%", "target": "dc01.corp.example", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.CidrInSource'

        $json2 = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.10.5.0/24" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result2 = Get-ExpandJson -Json $json2 -AllowCidr -Name 'source-vs-target.json'
        $result2.Error | Should -BeNullOrEmpty
        $result2.Expansion.Probes.Count | Should -Be 254
    }
}

Describe 'Refused target classes reached through a group (target position only)' -Tag 'Portable' {
    It 'a refused-class address as a Target-position group list item is refused' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "BAD": "224.0.0.1" }, "rows": [ { "source": "client", "target": "%BAD%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.RefusedTargetClass'
    }

    It 'a refused-class address as a Source-position group list item is NOT refused (Source is a label, never probed)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "BAD": "224.0.0.1" }, "rows": [ { "source": "%BAD%", "target": "10.0.0.5", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Rows[0].SourceIp | Should -BeExactly '224.0.0.1'
    }

    It 'a CIDR-enumerated host in a refused-class block is refused (defence in depth if a caller ever allowed a bad prefix)' {
        # 224.0.0.0/24 is entirely multicast; every enumerated host must be refused.
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "224.0.0.0/24" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json -AllowCidr
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.RefusedTargetClass'
    }

    It 'a non-canonical Target-position group item is class-checked first, not reported as Group.Syntax' -ForEach @(
        @{ Item = '0xe0000001'; Label = 'hex multicast (224.0.0.1)' }
        @{ Item = 'fe80::1%9'; Label = 'zone-id link-local' }
    ) {
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "BAD": "{0}" }}, "rows": [ {{ "source": "client", "target": "%BAD%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $Item
        $result = Get-ExpandJson -Json $json -Name ('minor3-{0}.json' -f ($Item -replace '[^A-Za-z0-9]', '_'))
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.RefusedTargetClass' -Because $Label
    }

    It 'a non-canonical Target-position group item that is NOT a refused class still falls through to Group.Syntax' {
        # 10.1 = 10.0.0.1 (non-canonical, not refused): the class check has nothing to catch, so
        # the item is still rejected for not being one of IPv4/IPv6/Hostname in canonical form.
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.1" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.Syntax'
    }

    It 'the same non-canonical item at Source position is neither class-checked nor refused for its class (target position only)' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "BAD": "0xe0000001" }, "rows": [ { "source": "%BAD%", "target": "10.0.0.5", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        # Source position never class-checks a group item; it still is not an accepted canonical
        # list-item form, so it is Group.Syntax, not RefusedTargetClass.
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.Syntax'
    }
}

Describe 'Naming, dedup and probe identity' -Tag 'Portable' {
    It 'dedup on ProbeKey; Rows accumulates every profile row that references the probe' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "rows": [' +
        '{ "source": "a", "target": "dup.test", "port": 443, "protocol": "TCP", "required": "yes" },' +
        '{ "source": "b", "target": "dup.test", "port": 443, "protocol": "TCP", "required": "no" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Rows.Count | Should -Be 2
        $result.Expansion.Probes.Count | Should -Be 1
        @($result.Expansion.Probes[0].Rows) | Should -Be @(1, 2)
    }

    It 'two names to different ports/protocols on the same host are different probes' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "rows": [' +
        '{ "source": "a", "target": "10.0.0.1", "port": 443, "protocol": "TCP", "required": "yes" },' +
        '{ "source": "a", "target": "10.0.0.1", "port": 443, "protocol": "UDP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Expansion.Probes.Count | Should -Be 2
    }

    It '5 sources x 200 rows gives 200 probes, not 1000 (Source is a label, plan invariant)' {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append('{ "schema": "portproof-profile/1", "name": "x", "groups": { "SRC": "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5" }, "rows": [')
        for ($i = 1; $i -le 200; $i++) {
            if ($i -gt 1) { [void]$sb.Append(',') }
            [void]$sb.Append(('{{ "source": "%SRC%", "target": "10.80.{0}.{1}", "port": 443, "protocol": "TCP", "required": "yes" }}' -f [Math]::Floor(($i - 1) / 250), (($i - 1) % 250 + 1)))
        }
        [void]$sb.Append('] }')
        $result = Get-ExpandJson -Json $sb.ToString() -Name 'src-multiply.json'
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Rows.Count | Should -Be 1000
        $result.Expansion.Probes.Count | Should -Be 200
    }

    It 'TargetName for a group bound to a hostname keeps both the group and the host (GROUP:hostname); a literal keeps only the group name' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "DC": "dc01.corp.example", "NET": "10.0.0.9" }, "rows": [' +
        '{ "source": "client", "target": "%DC%", "port": 443, "protocol": "TCP", "required": "yes" },' +
        '{ "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Error | Should -BeNullOrEmpty
        ($result.Expansion.Rows | Where-Object { $_.Row -eq 1 }).TargetName | Should -BeExactly 'DC:dc01.corp.example'
        ($result.Expansion.Rows | Where-Object { $_.Row -eq 2 }).TargetName | Should -BeExactly 'NET'
    }

    It 'DistinctTargets counts distinct target texts, not distinct probes' {
        $json = '{ "schema": "portproof-profile/1", "name": "x", "rows": [' +
        '{ "source": "a", "target": "10.0.0.1", "port": 443, "protocol": "TCP", "required": "yes" },' +
        '{ "source": "a", "target": "10.0.0.1", "port": 80, "protocol": "TCP", "required": "yes" } ] }'
        $result = Get-ExpandJson -Json $json
        $result.Expansion.Probes.Count | Should -Be 2
        $result.Expansion.DistinctTargets | Should -Be 1
    }
}

Describe 'Group.TooLarge and CapExceeded.Expansion' -Tag 'Portable' {
    BeforeAll {
        function Get-CommaList([int] $Count, [string] $Prefix = 'h') {
            $items = New-Object System.Collections.Generic.List[string]
            for ($i = 1; $i -le $Count; $i++) { $items.Add(('{0}{1}.test' -f $Prefix, $i)) }
            return ($items -join ',')
        }
    }

    It 'a group with 8193 items refuses Group.TooLarge (8192 is the limit)' {
        $list = Get-CommaList -Count 8193
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "BIG": "{0}" }}, "rows": [ {{ "source": "client", "target": "%BIG%", "port": 443, "protocol": "TCP", "required": "no" }} ] }}' -f $list
        $result = Get-ExpandJson -Json $json -Name 'toolarge.json'
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.TooLarge'
    }

    It 'Measure-PPGroupItemCount counts a hostile ~950k-item group value in under 5 seconds, no Split() before the refusal' {
        # A single comma-joined string, not an array of items - proves the count itself never
        # splits/allocates the (would-be) 950k substrings before Group.TooLarge fires. 5 s, not 1 s:
        # the same loaded-CI-box margin applied to every other count-while-reading timing test in
        # this suite (a real flake was measured on the JSON array's original 2 s bound).
        $value = ('h,' * 950000) + 'h'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            Measure-PPGroupItemCount -GroupName 'BIG' -Value $value -Row 1 -Origin 'Target' -Contract $script:Contract
            throw 'expected a refusal'
        }
        catch {
            $sw.Stop()
            $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.Group.TooLarge'
        }
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It 'a group with exactly 8192 items is accepted (the boundary itself is not TooLarge, and E=8192 does not exceed the cap x 8 limit either)' {
        $list = Get-CommaList -Count 8192
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "BIG": "{0}" }}, "rows": [ {{ "source": "client", "target": "%BIG%", "port": 443, "protocol": "TCP", "required": "no" }} ] }}' -f $list
        $result = Get-ExpandJson -Json $json -Name 'exactly8192.json'
        $result.Error | Should -BeNullOrEmpty
        $result.Expansion.Probes.Count | Should -Be 8192
    }

    It '100x100 source/target groups on one row (E=10000>8192) refuses CapExceeded.Expansion before any ExpandedRow exists' {
        $src = Get-CommaList -Count 100 -Prefix 's'
        $dst = Get-CommaList -Count 100 -Prefix 'd'
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "SRC": "{0}", "DST": "{1}" }}, "rows": [ {{ "source": "%SRC%", "target": "%DST%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $src, $dst
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Get-ExpandJson -Json $json -Name 'groupcap-caseA.json'
        $sw.Stop()
        $result.Expansion | Should -BeNullOrEmpty
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.Expansion'
        $result.Error.Exception.Message | Should -Match '10000 rows'
        # A row-builder counting stub is not wired into this function (its own two-pass structure IS
        # the guarantee: pass 2's loop is textually and sequentially after pass 1 completes for every
        # row). As an independent, observable proxy for "no ExpandedRow/Probe was built": building
        # 10,000 x 100 = 1,000,000+ PSCustomObjects would not complete in well under a second.
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It '1100 rows x 8 targets (P=8800>8192) refuses CapExceeded.Expansion, stopping as soon as the running total crosses the limit' {
        $dst8 = Get-CommaList -Count 8 -Prefix 't'
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.Append(('{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "DST8": "{0}" }}, "rows": [' -f $dst8))
        for ($i = 1; $i -le 1100; $i++) {
            if ($i -gt 1) { [void]$sb.Append(',') }
            [void]$sb.Append(('{{ "source": "src{0}", "target": "%DST8%", "port": 443, "protocol": "TCP", "required": "yes" }}' -f $i))
        }
        [void]$sb.Append('] }')
        $result = Get-ExpandJson -Json $sb.ToString() -Name 'groupcap-caseB.json'
        $result.Expansion | Should -BeNullOrEmpty
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.Expansion'
        # Stops as soon as the running total crosses 8192 (at row 1025: 1025 x 8 = 8200), not after
        # processing every one of the 1100 rows.
        $result.Error.Exception.Message | Should -Match '82\d\d rows'
    }

    It 'a single row with two small groups (90 sources x 92 targets = 8280 > 8192) also refuses before building, and quickly - neither group alone is anywhere near Group.TooLarge' {
        $src = Get-CommaList -Count 90 -Prefix 's'
        $dst = Get-CommaList -Count 92 -Prefix 'd'
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "SRC": "{0}", "DST": "{1}" }}, "rows": [ {{ "source": "%SRC%", "target": "%DST%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $src, $dst
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $result = Get-ExpandJson -Json $json -Name 'small-groups-big-product.json'
        $sw.Stop()
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.Expansion'
        $result.Error.Exception.Message | Should -Match '8280 rows'
        $sw.ElapsedMilliseconds | Should -BeLessThan 5000
    }

    It '-EffectiveCap defaults to Contract.DefaultCeiling - E=8193 (one over the default limit of 1024 x 8 = 8192) refuses' {
        # 8193 = 3 x 2731, both factors well under MaxGroupItems (8192) so neither group alone is
        # Group.TooLarge; the product is the precise one-past-the-boundary case (8192 exactly is
        # accepted, proven elsewhere in this Describe).
        $src = Get-CommaList -Count 3 -Prefix 's'
        $dst = Get-CommaList -Count 2731 -Prefix 'd'
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "SRC": "{0}", "DST": "{1}" }}, "rows": [ {{ "source": "%SRC%", "target": "%DST%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $src, $dst
        $result = Get-ExpandJson -Json $json -Name 'boundary-8193.json'
        $result.Expansion | Should -BeNullOrEmpty
        $result.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.Expansion'
        $result.Error.Exception.Message | Should -Match '8193 rows'
    }

    It '-EffectiveCap 65536 raises the pass-1 limit to 65536 x 8 = 524288, admitting a ~70000-row expansion the default cap would have refused' {
        # 100 x 700 = 70000, comfortably under 524288 but far over the default limit of 8192.
        $src = Get-CommaList -Count 100 -Prefix 's'
        $dst = Get-CommaList -Count 700 -Prefix 'd'
        $json = '{{ "schema": "portproof-profile/1", "name": "x", "groups": {{ "SRC": "{0}", "DST": "{1}" }}, "rows": [ {{ "source": "%SRC%", "target": "%DST%", "port": 443, "protocol": "TCP", "required": "yes" }} ] }}' -f $src, $dst

        $refused = Get-ExpandJson -Json $json -Name 'raised-cap-default.json'
        $refused.Error.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.Expansion'

        $admitted = Get-ExpandJson -Json $json -EffectiveCap 65536 -Name 'raised-cap-raised.json'
        $admitted.Error | Should -BeNullOrEmpty
        $admitted.Expansion.Rows.Count | Should -Be 70000
        # Probe identity is by TARGET only (Source is a label): 700 distinct targets, not 70000.
        $admitted.Expansion.Probes.Count | Should -Be 700
    }
}

Describe 'Assert-PPPreResolutionCount (AC30 early-exit unit half)' -Tag 'Portable' {
    It 'refuses 1030 at cap 1024' {
        { Assert-PPPreResolutionCount -Count 1030 -Cap 1024 -Ceiling 1024 } | Should -Throw '*1030*1024*'
    }
    It 'refuses 101 at cap 100' {
        { Assert-PPPreResolutionCount -Count 101 -Cap 100 -Ceiling 1024 } | Should -Throw
        try { Assert-PPPreResolutionCount -Count 101 -Cap 100 -Ceiling 1024 } catch { $_.FullyQualifiedErrorId | Should -BeExactly 'PortProof.CapExceeded.PreResolution' }
    }
    It 'accepts the boundary (Count equal to the cap)' {
        { Assert-PPPreResolutionCount -Count 100 -Cap 100 -Ceiling 1024 } | Should -Not -Throw
    }
    It 'uses min(Cap, Ceiling) as the effective threshold' {
        { Assert-PPPreResolutionCount -Count 50 -Cap 100 -Ceiling 40 } | Should -Throw '*40*'
    }
}

Describe 'Culture invariance (tr-TR): group names, overrides and CIDR arithmetic are unaffected' -Tag 'Portable' {
    It 'binds, overrides and expands identically under tr-TR' {
        Invoke-InCulture -Name 'tr-TR' -Action {
            $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "II": "dc01.corp.example", "DIRECTORY": "10.0.0.1,10.0.0.2" }, "rows": [' +
            '{ "source": "%ii%", "target": "%directory%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
            $result = Get-ExpandJson -Json $json -Bindings @('directory=10.0.0.9') -Name 'tr-culture.json'
            $result.Error | Should -BeNullOrEmpty
            $result.Expansion.GroupOverrides | Should -Contain 'DIRECTORY'
            $result.Expansion.Probes[0].Target | Should -BeExactly '10.0.0.9'
        }
    }

    It 'CIDR prefix arithmetic and refusals are unchanged under tr-TR' {
        Invoke-InCulture -Name 'tr-TR' -Action {
            $json = '{ "schema": "portproof-profile/1", "name": "x", "groups": { "NET": "10.9.9.0/24" }, "rows": [ { "source": "client", "target": "%NET%", "port": 443, "protocol": "TCP", "required": "yes" } ] }'
            $result = Get-ExpandJson -Json $json -AllowCidr -Name 'tr-cidr.json'
            $result.Error | Should -BeNullOrEmpty
            $result.Expansion.Probes.Count | Should -Be 254
        }
    }

    It 'restores the culture after each test' {
        [System.Threading.Thread]::CurrentThread.CurrentCulture.Name | Should -Not -Be 'tr-TR'
    }
}
