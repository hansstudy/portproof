@{
    # PortProof type allowlist.
    #
    # Every TypeExpressionAst (`[Type]::Member`, `[Type]$x` casts) and TypeConstraintAst (a
    # parameter or variable type constraint, `[Type] $x`) in src/ and dist/ must name a type in
    # General (allowed anywhere) or in Scoped (allowed only in the one named file). A generic
    # type's bracketed arguments (`List[string]`) and an array suffix (`string[]`) are stripped
    # before the lookup, so `System.Collections.Generic.List[string]` checks as
    # `System.Collections.Generic.List` and `string[]` checks as `string`. Matching is by the
    # short name OR the fully-qualified name (both spellings of `[System.Net.IPAddress]` and
    # `[IPAddress]` resolve to the same entry). Attribute type names (`[Parameter(...)]`,
    # `[ValidateSet(...)]`, `[CmdletBinding()]`, `[OutputType(...)]`, ...) are a different AST node
    # (AttributeAst) and are never scanned here - only real type references.
    #
    # `scriptblock` is deliberately absent from every list: no function signature anywhere takes a
    # scriptblock-typed parameter or variable, so even a plain `param([scriptblock] $x)` constraint
    # is a finding here - on top of, not instead of, Find-PPScriptBlockConversionFinding's
    # cast/-as-specific ban and the outright `-as [AnyType]` ban.

    General = @{
        # Primitives and basic .NET/PowerShell shapes used throughout.
        'string'                                          = 'Primitive.'
        'int'                                              = 'Primitive.'
        'int32'                                            = 'Primitive.'
        'long'                                             = 'Primitive (probe counts, cap arithmetic).'
        'bool'                                              = 'Primitive.'
        'double'                                            = 'Primitive.'
        'void'                                              = 'Primitive (no-return casts).'
        'object'                                            = 'Primitive.'
        'hashtable'                                         = 'Primitive (Contract, Flags, groups).'
        'ordered'                                           = 'Primitive ([ordered] hashtables backing the Contract/Flags/RunHeader shapes).'
        'pscustomobject'                                    = 'Every one of this tool''s own shapes (ProfileRow, ResultRow, RunHeader, ...) is a pscustomobject.'
        'switch'                                            = 'Switch parameters.'
        'ref'                                               = '[ref] out-parameters (e.g. TryParse, Receive([ref] $remote)).'
        'char'                                               = 'Character-class checks in text sanitisation (05-Contract.ps1 Get-PPSafeText: [char]::IsWhiteSpace/IsHighSurrogate).'
        'byte'                                               = 'byte[] buffers (UDP/ICMP zero-length payloads).'
        'guid'                                               = 'RunId generation (RunHeader.RunId).'
        'datetime'                                           = 'StartedUtc/StartedLocal timestamps and ISO-8601 ProbeResult.Timestamp formatting.'
        'System.DateTimeKind'                                = 'Explicit Utc/Local kind when constructing/formatting the timestamps above.'
        'array'                                              = 'Generic array typing in a few internal signatures (e.g. Get-PPShapeFields-style helpers).'
        'System.StringComparison'                             = 'Explicit ordinal string comparisons (05-Contract.ps1: EndsWith(..., [StringComparison]::Ordinal)) - deliberate, not the culture-sensitive default.'
        'System.IFormattable'                                = 'Culture-invariant ToString formatting alongside [cultureinfo]::InvariantCulture.'
        'System.Math'                                        = 'Rounding/clamping arithmetic (e.g. LatencyMs = [int][Math]::Round(...); cap/worst-case-duration arithmetic).'
        'System.InvalidOperationException'                    = 'The one exception type Invoke-PPRefusal throws (05-Contract.ps1).'
        'System.Management.Automation.ErrorRecord'            = 'Constructing the FQID PortProof.* error record (05-Contract.ps1 Invoke-PPRefusal).'
        'System.Management.Automation.ErrorCategory'          = 'The ErrorRecord category value for the same construction.'
        'System.Text.RegularExpressions.Regex'                = 'Control-character stripping in Get-PPSafeText (05-Contract.ps1: [regex]::Replace with an explicit CultureInvariant option).'
        'System.Text.RegularExpressions.RegexOptions'         = 'The CultureInvariant option for the Regex.Replace call above.'

        # Network data types (not construction - construction of the client/socket classes below
        # is scoped to one file each). An address/endpoint is passed around and typed on
        # parameters everywhere (adapters, the Contract predicate, the Gate), so these are general.
        'System.Net.IPAddress'                              = 'Address value type; parameter type on every adapter and the class predicate (05-Contract.ps1).'
        'System.Net.IPEndPoint'                              = 'Endpoint value type; UDP Connect/Receive target.'
        'System.Net.Sockets.AddressFamily'                   = 'The one legitimate TcpClient/UdpClient constructor argument ($Address.AddressFamily). SocketType/ProtocolType are deliberately absent: this tool never constructs a raw Socket, and those two enums have no other legitimate use (AC16 already bans SocketType]::Raw/ProtocolType]::Raw literally).'
        'System.Net.NetworkInformation.IPStatus'             = 'Ping.Send(...) result status classification.'

        # Timing, text and collections used by the Contract shapes and the Scheduler's rate gate.
        'System.Diagnostics.Stopwatch'                       = 'LatencyMs timing (every adapter) and the rate gate (Diagnostics.Stopwatch]::Frequency/GetTimestamp).'
        'System.Text.StringBuilder'                          = 'Text assembly for the hand-rolled CSV/JSON/HTML serializers ("own serializer, not ConvertTo-Json").'
        'System.Text.UTF8Encoding'                           = 'Explicit BOM control for deterministic output bytes (AC32 build determinism; Write-PPOutputFile -Bom).'
        'System.Environment'                                 = 'OperatorUser/OperatorHost ([Environment]::UserDomainName/UserName/MachineName).'
        'System.Globalization.CultureInfo'                   = 'CultureInvariant matching (culture-sensitive -match under tr-TR needs an explicit invariant-culture fix).'
        'System.StringComparer'                              = 'Ordinal dictionary keys (already used in 90-Main.ps1: [System.StringComparer]::Ordinal).'
        'System.Collections.Generic.List'                    = 'Ordered mutable collections (already used in 90-Main.ps1).'
        'System.Collections.Generic.Dictionary'              = 'Keyed lookups (already used in 90-Main.ps1).'
        'System.Collections.Generic.HashSet'                 = 'Deduplication (e.g. the pre-resolution probe list).'
        'System.IO.File'                                     = 'Byte-exact reads/writes instead of Get-Content/Set-Content ("reads at most MaxProfileBytes+1 bytes from the stream"; AC32 determinism).'
        'System.IO.Path'                                     = 'Path manipulation alongside Split-Path/Join-Path/Resolve-Path.'
        'System.IO.FileStream'                                = 'Streamed profile reads bounded by MaxProfileBytes.'
        'System.IO.Directory'                                 = 'Creating/checking the -Out directory ("created if absent").'
        'System.IO.FileMode'                                  = 'Explicit FileStream open mode for the bounded profile read and output-file collision handling (-Force semantics, AC21).'
        'System.IO.FileAccess'                                = 'Explicit FileStream access mode for the same bounded read/write.'
        'System.IO.FileShare'                                 = 'Explicit FileStream share mode for the same bounded read/write.'
        'System.Comparison'                                   = 'A typed comparison delegate for List[T].Sort(...) (ResultSet row ordering) - an alternative to Sort-Object where a stable, explicit comparer is needed.'
        'System.Collections.Concurrent.ConcurrentQueue'       = 'The Recorder queue type shared with tests/Harness/Recorder.ps1 and general thread-safe collection needs in the Scheduler.'

        # Attribute/help-only types that legitimately appear as TypeConstraintAst rather than
        # AttributeAst in a few PowerShell shapes (e.g. an [OutputType] value list uses
        # TypeExpressionAst-shaped entries for the types it names).
        'System.Management.Automation.PSCustomObject'        = 'Same as pscustomobject (the fully-qualified spelling).'
    }

    # Class name -> the one file it is allowed to be constructed/used in. TcpClient/UdpClient
    # match Test-ResolverIsolation.ps1's own construction-file-scope rule; Dns and Ping are added
    # here too for defense in depth (Dns is already confined by the AC11 token scan; Ping has no
    # other check owning it). Socket is intentionally not scoped anywhere: this tool never
    # constructs one, so it simply is not on any list, general or scoped - a bare `[Socket]`
    # reference anywhere is a finding.
    Scoped  = @{
        'System.Net.Sockets.TcpClient'                       = @{ File = '50-Probe.Tcp.ps1'; Reason = 'TCP adapter.' }
        'System.Net.Sockets.UdpClient'                       = @{ File = '55-Probe.Udp.ps1'; Reason = 'UDP adapter.' }
        'System.Net.NetworkInformation.Ping'                 = @{ File = '58-Probe.Icmp.ps1'; Reason = 'ICMP adapter.' }
        'System.Net.Dns'                                     = @{ File = '30-Resolver.ps1'; Reason = 'The one Resolver seam; the AC11 token scan already confines the GetHostAddresses/GetHostEntry methods here, this scopes the type reference the same way.' }

        # The 5.1 runspace-pool path: "[InitialSessionState]::CreateDefault2() plus
        # one SessionStateFunctionEntry per definition; CreateRunspacePool(1, Concurrency, $iss,
        # $Host); one [PowerShell] per queue, BeginInvoke/EndInvoke". All four types that mechanism
        # needs are scoped to 40-Scheduler.ps1 - none of them has any other legitimate call site.
        'System.Management.Automation.Runspaces.InitialSessionState'      = @{ File = '40-Scheduler.ps1'; Reason = '5.1 path: CreateDefault2().' }
        'System.Management.Automation.Runspaces.SessionStateFunctionEntry' = @{ File = '40-Scheduler.ps1'; Reason = '5.1 path: one entry per worker-set definition.' }
        'System.Management.Automation.Runspaces.RunspaceFactory'          = @{ File = '40-Scheduler.ps1'; Reason = '5.1 path: CreateRunspacePool(1, Concurrency, $iss, $Host).' }
        'System.Management.Automation.Runspaces.RunspacePool'             = @{ File = '40-Scheduler.ps1'; Reason = 'The pool object CreateRunspacePool returns.' }
        'System.Management.Automation.PowerShell'                        = @{ File = '40-Scheduler.ps1'; Reason = 'One [PowerShell] per queue, BeginInvoke/EndInvoke.' }
        'System.Threading.Monitor'                                       = @{ File = '40-Scheduler.ps1'; Reason = 'Wait-PPRateSlot: Monitor::Enter/Exit around the shared rate gate''s critical section (the "per-target lock ... one queue per probe" design has no other lock primitive anywhere).' }
        'System.Random'                                                  = @{ File = '35-Gate.ps1'; Reason = 'Per-probe jitter, one generator per Gate call - "precomputed on this thread from one generator (no identical seeds across workers)".' }

        # A narrow allowlist entry beats a hand-rolled substitute: hand-rolling a FIPS 180-4
        # SHA-256 or a surrogate-pair-aware UTF-16 decoder specifically to
        # avoid needing these two types would be strictly worse (more code to
        # review, more places to get the crypto/encoding subtly wrong) than one reviewed, scoped
        # allowlist line. Both confined to 10-Parser.ps1: neither has any other legitimate call site.
        'System.Security.Cryptography.SHA256'                            = @{ File = '10-Parser.ps1'; Reason = 'Profile.Sha256 ("lowercase hex of the file bytes") - Create()/ComputeHash(byte[]) only.' }
        'System.Text.UnicodeEncoding'                                    = @{ File = '10-Parser.ps1'; Reason = 'Strict UTF-16LE/BE profile decode (BOM-sniffed, replacing the hand-rolled surrogate-pair decoder).' }

        # `scriptblock` is deliberately NOT listed here (or in General): it gets its own dedicated,
        # parameter-shaped allowance instead of a file scope, because the risk is not "which file"
        # but "which parameter, and only as a type constraint" - see
        # Test-PPIsAllowedScriptBlockParameterConstraint and Find-PPTypeAllowlistFinding's special
        # case for it: `[scriptblock]` may appear only as the TypeConstraintAst on
        # Invoke-PPGate's own `$OnAdmitted` parameter in 35-Gate.ps1 - never as a cast (`[scriptblock]
        # $x`), never with `-as` (both already independently banned everywhere by
        # Find-PPScriptBlockConversionFinding/Find-PPAsTypeCastFinding regardless of this), and never
        # on any other function or parameter. PowerShell does not convert a string argument to a
        # scriptblock-typed parameter (verified empirically; Static.Tests.ps1's own fixture proves
        # it), so a plain type constraint here cannot be used to smuggle a string into becoming code.
    }
}
