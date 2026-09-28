# PortProof resolver. The only file in src/ that references System.Net.Dns or any
# resolving API (AC11-4). Function definitions only.

function Get-PPDnsResolver {
    # The live Resolver seam: Kind 'Dns', an Invocations counter (incremented by
    # Resolve-PPProbeList, not here) and a Resolve scriptblock property. Resolve returns one or more
    # [IPAddress]; a timeout, a resolver exception or an empty answer throws an ErrorRecord whose
    # FullyQualifiedErrorId is 'PortProof.DnsFailure'. The closure calls no PortProof function (a
    # GetNewClosure() block runs in its own module scope and cannot see the script's functions), so
    # it builds its error record inline.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([int] $TimeoutMs = 5000)

    $waitMs = $TimeoutMs
    if ($waitMs -lt 1) { $waitMs = 1 }

    $resolve = {
        param([string] $Name)

        $answer = $null
        $reason = 'did not resolve'
        try {
            $pending = [System.Net.Dns]::BeginGetHostAddresses($Name, $null, $null)
            if ($pending.AsyncWaitHandle.WaitOne($waitMs)) {
                $answer = [System.Net.Dns]::EndGetHostAddresses($pending)
                $pending.AsyncWaitHandle.Close()
            }
            else {
                # The lookup is abandoned, not cancelled: the OS resolver has no cancel. Its wait
                # handle is left to the finaliser because the lookup may still signal it.
                $reason = 'timed out'
            }
        }
        catch {
            $answer = $null
            $reason = 'did not resolve'
        }

        if ($null -eq $answer -or @($answer).Count -eq 0) {
            $shown = [regex]::Replace([string]$Name, '[\u0000-\u001F\u007F-\u009F]', '?',
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
            if ($shown.Length -gt 253) { $shown = $shown.Substring(0, 253) }
            $exception = [System.InvalidOperationException]::new("PortProof: name '$shown' $reason.")
            $record = [System.Management.Automation.ErrorRecord]::new($exception, 'PortProof.DnsFailure',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound, $shown)
            throw $record
        }
        $answer
    }.GetNewClosure()

    [pscustomobject][ordered]@{
        PSTypeName  = 'PortProof.Resolver'
        Kind        = 'Dns'
        Invocations = 0
        Resolve     = $resolve
    }
}

function Resolve-PPProbeList {
    # -> PortProof.Resolution. Literals are canonicalised without a Resolve call.
    # Names get one Resolve call per distinct lowercase name (cache); TargetIp is the canonical
    # first address and ResolvedAddresses holds every returned address, canonical, in returned
    # order. PortProof.DnsFailure marks the entry Failed and produces no ExecProbe; any other
    # exception (PortProof.DryRunResolutionAttempted included) propagates unchanged. ExecProbes are
    # deduplicated on ExecKey, so CountAfter <= CountBefore by construction. JitterMs is left 0: the
    # Gate assigns it.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Probes,
        [Parameter(Mandatory)] [pscustomobject] $Resolver
    )

    $inv = [cultureinfo]::InvariantCulture
    $entries = @{}
    $cache = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $execByKey = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $execProbes = [System.Collections.Generic.List[object]]::new()
    $countBefore = 0

    foreach ($probe in $Probes) {
        if ($null -eq $probe) { continue }
        $countBefore++
        $probeKey = [string]$probe.ProbeKey
        $kind = [string]$probe.TargetKind
        $addresses = $null
        $failed = $false

        if ($kind -ceq 'IPv4' -or $kind -ceq 'IPv6') {
            if ($probe.Address -isnot [System.Net.IPAddress]) {
                Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: literal probe '{0}' carries no address." -f (Get-PPSafeText -Text $probeKey))
            }
            $addresses = @(ConvertTo-CanonicalAddress -Address $probe.Address)
        }
        elseif ($kind -ceq 'Hostname') {
            $name = ([string]$probe.Target).ToLowerInvariant()
            if (-not $cache.ContainsKey($name)) {
                $Resolver.Invocations = [int]$Resolver.Invocations + 1
                $outcome = $null
                try {
                    $returned = @(& $Resolver.Resolve $name)
                    $canonical = [System.Collections.Generic.List[object]]::new()
                    foreach ($item in $returned) {
                        if ($item -isnot [System.Net.IPAddress]) {
                            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: the resolver returned a non-address for '{0}'." -f (Get-PPSafeText -Text $name))
                        }
                        $canonical.Add((ConvertTo-CanonicalAddress -Address $item))
                    }
                    if ($canonical.Count -gt 0) { $outcome = $canonical.ToArray() }
                }
                catch {
                    if ([string]$_.FullyQualifiedErrorId -cne 'PortProof.DnsFailure') { throw }
                    $outcome = $null
                }
                $cache[$name] = $outcome
            }
            $addresses = $cache[$name]
            if ($null -eq $addresses) { $failed = $true }
        }
        else {
            Invoke-PPRefusal -Code 'InternalInvariant' -Message ("internal error: probe '{0}' has target kind '{1}'." -f (Get-PPSafeText -Text $probeKey), (Get-PPSafeText -Text $kind))
        }

        $targetIp = $null
        $resolvedText = [string[]]@()
        if (-not $failed) {
            $targetIp = $addresses[0]
            $texts = [System.Collections.Generic.List[string]]::new()
            foreach ($a in $addresses) { $texts.Add($a.ToString()) }
            $resolvedText = $texts.ToArray()
        }

        $entries[$probeKey] = [pscustomobject][ordered]@{
            PSTypeName        = 'PortProof.ResolutionEntry'
            TargetIp          = $targetIp
            ResolvedAddresses = $resolvedText
            Failed            = $failed
            TargetName        = [string]$probe.Target
            Rows              = @($probe.Rows)
        }

        if ($failed) { continue }
        $port = [int]$probe.Port
        $protocol = [string]$probe.Protocol
        $execKey = '{0}|{1}|{2}' -f $targetIp.ToString(), $port.ToString($inv), $protocol
        if ($execByKey.ContainsKey($execKey)) { continue }
        $exec = [pscustomobject][ordered]@{
            PSTypeName = 'PortProof.ExecProbe'
            ExecKey    = $execKey
            TargetIp   = $targetIp
            Port       = $port
            Protocol   = $protocol
            JitterMs   = 0
        }
        $execByKey[$execKey] = $exec
        $execProbes.Add($exec)
    }

    [pscustomobject][ordered]@{
        PSTypeName  = 'PortProof.Resolution'
        Entries     = $entries
        ExecProbes  = $execProbes.ToArray()
        CountBefore = $countBefore
        CountAfter  = $execProbes.Count
    }
}
