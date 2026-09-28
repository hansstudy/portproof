# PortProof expander: group/list/CIDR expansion into the pre-resolution probe list, with the
# count-before-build early exit. Function definitions only.

function ConvertFrom-PPBinding {
    # 'NAME=VALUE' -> @{ Name; Value }. Grammar (name shape, single '=') is already checked by
    # Assert-Arguments in 90-Main.ps1; this only splits at the first '='.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Text)

    $idx = $Text.IndexOf('=')
    @{ Name = $Text.Substring(0, $idx); Value = $Text.Substring($idx + 1) }
}

function Get-PPGroupValueShape {
    # Classifies a bound group's raw text as a plain list or a CIDR attempt, without validating
    # -AllowCidr/prefix range/host bits (that is Measure-PPGroupItemCount's and
    # Expand-PPGroupValue's job, in that order). A value is a CIDR
    # candidate only when it has exactly one '/'; anything else (including two or more '/') is a
    # list, and an item that is not a valid address/host name fails its own grammar check later.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Value)

    $v4 = '\A(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\z'
    $parts = $Value.Split('/')
    if ($parts.Length -eq 2) {
        $addrText = $parts[0]
        $prefixText = $parts[1]
        if ($addrText -cmatch $v4 -and $prefixText -cmatch '\A[0-9]{1,2}\z') {
            return [pscustomobject]@{ Kind = 'Ipv4Cidr'; Address = $addrText; PrefixText = $prefixText }
        }
        $parsed = $null
        if ([System.Net.IPAddress]::TryParse($addrText, [ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return [pscustomobject]@{ Kind = 'Ipv6Cidr'; Address = $addrText; PrefixText = $prefixText }
        }
    }
    return [pscustomobject]@{ Kind = 'List'; Address = ''; PrefixText = '' }
}

function Get-PPCidrPlan {
    # Shared CIDR validation (shape already known to be 'Ipv4Cidr'): -AllowCidr, prefix 8..32,
    # not Source, host bits clear - in that order, and the item count is computed only after all
    # of these pass (shape and -AllowCidr validated before any count is
    # computed, so a /0 - or anything else outside 8..32 - never reaches the 2^(32-prefix)
    # arithmetic; the prefix range check always runs first and uses [long] shifts throughout, so
    # even a would-be /0 can never wrap negative the way a 32-bit-masked shift-by-32 could).
    #
    # VLSM support: any prefix must work, not only /24, since VLSM routinely
    # uses narrow point-to-point prefixes alongside wide ones. The range is 8..32 (still gated by
    # -AllowCidr and, downstream, by the same EffectiveCap x ExpansionFactor
    # arithmetic every other expansion path already uses - a /8 or /16 is refused there, on pure
    # arithmetic, before pass 2 ever enumerates a single address). /31 and /32 need their own usable-
    # range rule, since the classic "network and broadcast excluded" formula (2^hostBits - 2) is
    # undefined for them: a /31 has no network/broadcast address at all (RFC 3021 - both of its two
    # addresses are usable, the standard point-to-point convention every VLSM design already relies
    # on), and a /32 is a single host route (the one address is directly usable; there is nothing to
    # exclude - excluding it would make a /32 always empty, which defeats accepting it at all). Every
    # other prefix (8..30) keeps the original network+1..broadcast-1 rule unchanged.
    # Returns @{ AddressLong; Prefix; HostBits; BlockMask; HostMask; Network; Broadcast; FirstUsable;
    # LastUsable; Count }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $GroupName,
        [Parameter(Mandatory)] $Shape,
        [switch] $AllowCidr,
        [Parameter(Mandatory)] [string] $Origin,
        [Parameter(Mandatory)] [int] $Row
    )

    if (-not $AllowCidr) {
        Invoke-PPRefusal -Code 'Group.CidrNotAllowed' -Row $Row -Message ("row {0} group '{1}' is a CIDR prefix; run with -AllowCidr." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName)
    }
    $prefix = [int]::Parse($Shape.PrefixText, [cultureinfo]::InvariantCulture)
    if ($prefix -lt 8 -or $prefix -gt 32) {
        Invoke-PPRefusal -Code 'Group.CidrTooWide' -Row $Row -Message ("row {0} group '{1}' prefix /{2} is outside 8..32." -f
            $Row.ToString([cultureinfo]::InvariantCulture), $GroupName, $prefix.ToString([cultureinfo]::InvariantCulture))
    }
    if ($Origin -ceq 'Source') {
        Invoke-PPRefusal -Code 'Group.CidrInSource' -Row $Row -Message ("row {0} group '{1}' is a CIDR prefix and cannot be referenced from Source." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName)
    }
    $parsed = $null
    [void][System.Net.IPAddress]::TryParse($Shape.Address, [ref]$parsed)
    $bytes = $parsed.GetAddressBytes()
    $addrLong = ([long]$bytes[0] -shl 24) -bor ([long]$bytes[1] -shl 16) -bor ([long]$bytes[2] -shl 8) -bor [long]$bytes[3]
    $hostBits = 32 - $prefix
    $blockMask = (0xFFFFFFFFL -shl $hostBits) -band 0xFFFFFFFFL
    $hostMask = (-bnot $blockMask) -band 0xFFFFFFFFL
    if (($addrLong -band $hostMask) -ne 0L) {
        Invoke-PPRefusal -Code 'Group.CidrNotAligned' -Row $Row -Message ("row {0} group '{1}' has host bits set for a /{2}; use the network address." -f
            $Row.ToString([cultureinfo]::InvariantCulture), $GroupName, $prefix.ToString([cultureinfo]::InvariantCulture))
    }
    $network = $addrLong -band $blockMask
    $broadcast = $network -bor $hostMask
    if ($prefix -eq 32) {
        # Single host route: the one address is the whole usable range.
        $firstUsable = $network
        $lastUsable = $network
    }
    elseif ($prefix -eq 31) {
        # RFC 3021 point-to-point: both addresses usable, no network/broadcast concept.
        $firstUsable = $network
        $lastUsable = $broadcast
    }
    else {
        $firstUsable = $network + 1L
        $lastUsable = $broadcast - 1L
    }
    [pscustomobject]@{
        AddressLong = $addrLong
        Prefix      = $prefix
        HostBits    = $hostBits
        BlockMask   = $blockMask
        HostMask    = $hostMask
        Network     = $network
        Broadcast   = $broadcast
        FirstUsable = $firstUsable
        LastUsable  = $lastUsable
        Count       = $lastUsable - $firstUsable + 1L
    }
}

function Measure-PPGroupItemCount {
    # Pass 1: arithmetic only, no item objects built. Validates CIDR shape/-AllowCidr/
    # prefix range/host bits/position (via Get-PPCidrPlan), or counts a list's items straight from
    # its text - counted with
    # IndexOf, never $Value.Split(), and Group.TooLarge is refused before any split happens; the
    # per-item empty-item/nested-group grammar checks are Expand-PPGroupValue's, pass 2's, job -
    # they need the actual item strings, which pass 1 never builds). Group.TooLarge/MaxGroupItems
    # applies to list counts only, unchanged by CIDR support - a CIDR's count is bounded by a different mechanism entirely: it
    # is pure O(1) arithmetic (Get-PPCidrPlan never enumerates), so however large a /8's 16,777,214
    # count is, it flows straight into Expand-PPProfile's own eTotal/pTotal x EffectiveCap x
    # ExpansionFactor check below, at no enumeration cost - a wide-enough prefix (e.g. /16 without
    # -AllowLarge, or /8 regardless) is refused there, CapExceeded.Expansion, before pass 2 ever
    # calls Expand-PPGroupValue.
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory)] [string] $GroupName,
        [Parameter(Mandatory)] [string] $Value,
        [switch] $AllowCidr,
        [Parameter(Mandatory)] [string] $Origin,
        [Parameter(Mandatory)] [int] $Row,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $shape = Get-PPGroupValueShape -Value $Value
    if ($shape.Kind -ceq 'Ipv6Cidr') {
        Invoke-PPRefusal -Code 'Group.CidrIPv6' -Row $Row -Message ("row {0} group '{1}' is an IPv6 prefix; CIDR is IPv4 only." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName)
    }
    if ($shape.Kind -ceq 'Ipv4Cidr') {
        $plan = Get-PPCidrPlan -GroupName $GroupName -Shape $shape -AllowCidr:$AllowCidr -Origin $Origin -Row $Row
        return $plan.Count
    }

    $maxItems = [long]$Contract.MaxGroupItems
    $count = [long]1
    $searchFrom = -1
    while ($true) {
        $commaIndex = $Value.IndexOf(',', $searchFrom + 1)
        if ($commaIndex -lt 0) { break }
        $count++
        $searchFrom = $commaIndex
        if ($count -gt $maxItems) { break }
    }
    if ($count -gt $maxItems) {
        Invoke-PPRefusal -Code 'Group.TooLarge' -Row $Row -Message ("row {0} group '{1}' has more than {2} items." -f $Row.ToString([cultureinfo]::InvariantCulture), $GroupName,
            ([int]$Contract.MaxGroupItems).ToString([cultureinfo]::InvariantCulture))
    }
    return $count
}

function Expand-PPGroupValue {
    # -> TargetKind[]. Pass 2: builds the concrete items a bound group or CIDR
    # produces (re-running the same shape/CIDR checks Measure-PPGroupItemCount already passed for
    # this exact value/-AllowCidr/-Origin in pass 1, defensively). Does not itself call
    # Assert-PPLiteralTargetClass: that check is scoped to target-position items, and the
    # caller (Expand-PPProfile) is the one that knows the row number the message should name.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Contract',
        Justification = 'This function''s signature is fixed at (Name, Value, AllowCidr, Origin, Contract). This pass-2 builder does not need a Contract-derived limit itself - Group.TooLarge is pass 1''s job (Measure-PPGroupItemCount, which already validated this exact value before Expand-PPProfile calls this function) - but the parameter stays to match the fixed interface every other unit codes against.')]
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Value,
        [switch] $AllowCidr,
        [Parameter(Mandatory)] [string] $Origin,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $results = [System.Collections.Generic.List[object]]::new()
    $shape = Get-PPGroupValueShape -Value $Value

    if ($shape.Kind -ceq 'Ipv6Cidr') {
        Invoke-PPRefusal -Code 'Group.CidrIPv6' -Message ("group '{0}' is an IPv6 prefix; CIDR is IPv4 only." -f $Name)
    }
    if ($shape.Kind -ceq 'Ipv4Cidr') {
        $plan = Get-PPCidrPlan -GroupName $Name -Shape $shape -AllowCidr:$AllowCidr -Origin $Origin -Row 0
        for ($current = $plan.FirstUsable; $current -le $plan.LastUsable; $current++) {
            $b0 = [byte](($current -shr 24) -band 0xFFL)
            $b1 = [byte](($current -shr 16) -band 0xFFL)
            $b2 = [byte](($current -shr 8) -band 0xFFL)
            $b3 = [byte]($current -band 0xFFL)
            $address = [System.Net.IPAddress]::new([byte[]]($b0, $b1, $b2, $b3))
            $results.Add([pscustomobject][ordered]@{
                    PSTypeName = 'PortProof.TargetKind'
                    Kind       = 'IPv4'
                    Text       = $address.ToString()
                    Address    = $address
                    Reason     = ''
                })
        }
        return , $results.ToArray()
    }

    foreach ($item in $Value.Split(',')) {
        if ($item.Length -eq 0) {
            Invoke-PPRefusal -Code 'Group.Syntax' -Message ("group '{0}' has an empty item between commas." -f $Name)
        }
        if ($item -cmatch '\A%([A-Za-z][A-Za-z0-9_]{0,31})%\z') {
            Invoke-PPRefusal -Code 'Group.Nested' -Message ("group '{0}' item '{1}' is itself a group reference; groups may not nest." -f $Name, (Get-PPSafeText -Text $item))
        }
        $kind = Get-PPTargetKind -Text $item
        # The same TryParse-then-class-check order used for a plain target field - a
        # NonCanonicalLiteral item (e.g. 0xe0000001) is class-checked (target position only)
        # before it is rejected as Group.Syntax, so a refused-class address reached through a
        # group names its class, exactly like a literal target does, instead of being reported as a
        # plain syntax error. Row 0: a bound group's own value has no single owning row (the same
        # convention the CIDR path above already uses).
        if ($Origin -ceq 'Target' -and $kind.Kind -ceq 'NonCanonicalLiteral') {
            Assert-PPLiteralTargetClass -Address $kind.Address -Row 0 -Field $Origin -Origin $item
        }
        if ($kind.Kind -cne 'IPv4' -and $kind.Kind -cne 'IPv6' -and $kind.Kind -cne 'Hostname') {
            Invoke-PPRefusal -Code 'Group.Syntax' -Message ("group '{0}' item '{1}' is not an address or host name (write it in dotted-decimal, standard IPv6, or as a plain host name)." -f
                $Name, (Get-PPSafeText -Text $item))
        }
        $results.Add($kind)
    }
    return , $results.ToArray()
}

function Assert-PPPreResolutionCount {
    # Throws PortProof.CapExceeded.PreResolution when Count > the effective
    # cap. Never resolves; takes counts only. Effective cap = min(Cap, Ceiling), mirroring the
    # Gate's own min(Cap, AbsoluteProbeCeiling) defence.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [int] $Count,
        [Parameter(Mandatory)] [int] $Cap,
        [Parameter(Mandatory)] [int] $Ceiling
    )

    $effectiveCap = $Cap
    if ($Ceiling -lt $effectiveCap) { $effectiveCap = $Ceiling }
    if ($Count -gt $effectiveCap) {
        Invoke-PPRefusal -Code 'CapExceeded.PreResolution' -Message ('{0} probes exceed the cap of {1} (before name resolution; nothing was resolved or sent)' -f
            $Count.ToString([cultureinfo]::InvariantCulture), $effectiveCap.ToString([cultureinfo]::InvariantCulture))
    }
}

function Expand-PPProfile {
    # -> PortProof.Expansion. Pass 1 (count-before-build): pure arithmetic, no ExpandedRow/Probe
    # built, refuses Group.TooLarge/CidrIPv6/
    # CidrNotAllowed/CidrTooWide/CidrInSource/CidrNotAligned/Syntax/Nested/Unbound and
    # CapExceeded.Expansion. Pass 2: builds the deduplicated Probe list and the ExpandedRow list.
    #
    # The pass-1 limit is EffectiveCap x ExpansionFactor, using the
    # run's real effective cap. -EffectiveCap defaults to Contract.DefaultCeiling (0 or an
    # unbound/omitted value both mean "use the default") so every existing caller - including this
    # file's own tests - keeps working unchanged; 90-Main.ps1
    # passes -EffectiveCap $options.EffectiveCap.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [pscustomobject] $ProfileDocument,
        [AllowEmptyCollection()] [string[]] $Bindings,
        [switch] $AllowCidr,
        [long] $EffectiveCap = 0,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $groups = [ordered]@{}
    foreach ($key in @($ProfileDocument.Groups.Keys)) { $groups[$key] = $ProfileDocument.Groups[$key] }
    $groupOverrides = [System.Collections.Generic.List[string]]::new()
    foreach ($bindingText in @($Bindings)) {
        $parsedBinding = ConvertFrom-PPBinding -Text $bindingText
        $upperName = $parsedBinding.Name.ToUpperInvariant()
        if ($groups.Contains($upperName)) { $groupOverrides.Add($upperName) }
        $groups[$upperName] = $parsedBinding.Value
    }

    $usedGroups = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $effectiveCapInForce = $EffectiveCap
    if ($effectiveCapInForce -le 0) { $effectiveCapInForce = [long]$Contract.DefaultCeiling }
    $limit = $effectiveCapInForce * [long]$Contract.ExpansionFactor
    $eTotal = [long]0
    $pTotal = [long]0

    foreach ($row in @($ProfileDocument.Rows)) {
        $srcKind = Get-PPTargetKind -Text $row.Source
        $tgtKind = Get-PPTargetKind -Text $row.Target

        if ($srcKind.Kind -ceq 'Group') {
            $groupName = $srcKind.Text
            $usedGroups[$groupName] = $true
            if (-not $groups.Contains($groupName)) {
                Invoke-PPRefusal -Code 'Group.Unbound' -Row $row.Row -Message ("row {0} group '{1}' (Source) is not bound; add -Set '{1}=...' or a groups entry." -f
                    $row.Row.ToString([cultureinfo]::InvariantCulture), $groupName)
            }
            $sCount = Measure-PPGroupItemCount -GroupName $groupName -Value ([string]$groups[$groupName]) -AllowCidr:$AllowCidr -Origin 'Source' -Row $row.Row -Contract $Contract
        }
        else {
            $sCount = [long]1
        }

        if ($tgtKind.Kind -ceq 'Group') {
            $groupName = $tgtKind.Text
            $usedGroups[$groupName] = $true
            if (-not $groups.Contains($groupName)) {
                Invoke-PPRefusal -Code 'Group.Unbound' -Row $row.Row -Message ("row {0} group '{1}' (Target) is not bound; add -Set '{1}=...' or a groups entry." -f
                    $row.Row.ToString([cultureinfo]::InvariantCulture), $groupName)
            }
            $tCount = Measure-PPGroupItemCount -GroupName $groupName -Value ([string]$groups[$groupName]) -AllowCidr:$AllowCidr -Origin 'Target' -Row $row.Row -Contract $Contract
        }
        else {
            $tCount = [long]1
        }

        $eTotal += ($sCount * $tCount)
        $pTotal += $tCount
        if ($eTotal -gt $limit -or $pTotal -gt $limit) {
            Invoke-PPRefusal -Code 'CapExceeded.Expansion' -Row $row.Row -Message ('profile expands to {0} rows ({1} probe targets); the limit is {2} = cap x {3}; nothing was built, resolved or sent' -f
                $eTotal.ToString([cultureinfo]::InvariantCulture), $pTotal.ToString([cultureinfo]::InvariantCulture), $limit.ToString([cultureinfo]::InvariantCulture),
                ([int]$Contract.ExpansionFactor).ToString([cultureinfo]::InvariantCulture))
        }
    }

    # Pass 2: build. No ExpandedRow or Probe exists above this line.
    $expandedRows = [System.Collections.Generic.List[object]]::new()
    $probesByKey = [ordered]@{}
    $distinctTargets = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)

    foreach ($row in @($ProfileDocument.Rows)) {
        $srcKind = Get-PPTargetKind -Text $row.Source
        $tgtKind = Get-PPTargetKind -Text $row.Target

        $srcGroupName = ''
        if ($srcKind.Kind -ceq 'Group') {
            $srcGroupName = $srcKind.Text
            $sourceItems = Expand-PPGroupValue -Name $srcGroupName -Value ([string]$groups[$srcGroupName]) -AllowCidr:$AllowCidr -Origin 'Source' -Contract $Contract
        }
        else {
            $sourceItems = , $srcKind
        }

        $tgtGroupName = ''
        if ($tgtKind.Kind -ceq 'Group') {
            $tgtGroupName = $tgtKind.Text
            $targetItems = Expand-PPGroupValue -Name $tgtGroupName -Value ([string]$groups[$tgtGroupName]) -AllowCidr:$AllowCidr -Origin 'Target' -Contract $Contract
            foreach ($targetItem in $targetItems) {
                if ($targetItem.Kind -ceq 'IPv4' -or $targetItem.Kind -ceq 'IPv6') {
                    Assert-PPLiteralTargetClass -Address $targetItem.Address -Row $row.Row -Field 'Target' -Origin $targetItem.Text
                }
            }
        }
        else {
            $targetItems = , $tgtKind
        }

        foreach ($sourceItem in $sourceItems) {
            $sourceName = $sourceItem.Text
            if ($srcGroupName.Length -gt 0) {
                if ($sourceItem.Kind -ceq 'Hostname') { $sourceName = '{0}:{1}' -f $srcGroupName, $sourceItem.Text }
                else { $sourceName = $srcGroupName }
            }
            $sourceIp = ''
            if ($sourceItem.Kind -ceq 'IPv4' -or $sourceItem.Kind -ceq 'IPv6') { $sourceIp = $sourceItem.Text }

            foreach ($targetItem in $targetItems) {
                $targetName = $targetItem.Text
                if ($tgtGroupName.Length -gt 0) {
                    if ($targetItem.Kind -ceq 'Hostname') { $targetName = '{0}:{1}' -f $tgtGroupName, $targetItem.Text }
                    else { $targetName = $tgtGroupName }
                }

                $probeKey = '{0}|{1}|{2}' -f $targetItem.Text, ([int]$row.Port).ToString([cultureinfo]::InvariantCulture), $row.Protocol
                if (-not $probesByKey.Contains($probeKey)) {
                    $probesByKey[$probeKey] = [pscustomobject][ordered]@{
                        PSTypeName = 'PortProof.Probe'
                        ProbeKey   = $probeKey
                        Target     = $targetItem.Text
                        TargetKind = $targetItem.Kind
                        Address    = $targetItem.Address
                        Port       = $row.Port
                        Protocol   = $row.Protocol
                        Rows       = [System.Collections.Generic.List[int]]::new()
                    }
                    $distinctTargets[$targetItem.Text] = $true
                }
                $probeRowList = $probesByKey[$probeKey].Rows
                if (-not $probeRowList.Contains([int]$row.Row)) { [void]$probeRowList.Add([int]$row.Row) }

                $expandedRows.Add([pscustomobject][ordered]@{
                        PSTypeName  = 'PortProof.ExpandedRow'
                        Row         = $row.Row
                        SourceName  = $sourceName
                        SourceGroup = $srcGroupName
                        SourceIp    = $sourceIp
                        TargetName  = $targetName
                        TargetGroup = $tgtGroupName
                        TargetKind  = $targetItem.Kind
                        Port        = $row.Port
                        Protocol    = $row.Protocol
                        Service     = $row.Service
                        Required    = $row.Required
                        Notes       = $row.Notes
                        ProbeKey    = $probeKey
                    })
            }
        }
    }

    $probes = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $probesByKey.Keys) {
        $probeEntry = $probesByKey[$key]
        $probes.Add([pscustomobject][ordered]@{
                PSTypeName = 'PortProof.Probe'
                ProbeKey   = $probeEntry.ProbeKey
                Target     = $probeEntry.Target
                TargetKind = $probeEntry.TargetKind
                Address    = $probeEntry.Address
                Port       = $probeEntry.Port
                Protocol   = $probeEntry.Protocol
                Rows       = [int[]]$probeEntry.Rows.ToArray()
            })
    }

    $unusedGroups = [System.Collections.Generic.List[string]]::new()
    foreach ($key in $groups.Keys) {
        if (-not $usedGroups.ContainsKey($key)) { $unusedGroups.Add($key) }
    }

    [pscustomobject][ordered]@{
        PSTypeName      = 'PortProof.Expansion'
        Rows            = [pscustomobject[]]$expandedRows.ToArray()
        Probes          = [pscustomobject[]]$probes.ToArray()
        GroupOverrides  = [string[]]$groupOverrides.ToArray()
        UnusedGroups    = [string[]]$unusedGroups.ToArray()
        DistinctTargets = [int]$distinctTargets.Count
    }
}
