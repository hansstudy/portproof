# PortProof parser: bytes-to-text decode, strict CSV/JSON readers, closed-domain row validation,
# and the literal refused-class check. Function definitions only.
#
# No hand-rolled crypto or codecs, and no API substitution to dodge a static-scanner rule. UTF-16
# decode uses `[System.Text.UnicodeEncoding]` (throwOnInvalidBytes) and the profile SHA-256 uses
# `[System.Security.Cryptography.SHA256]::Create()`/`ComputeHash` - both scoped to this file on
# tests/Static/settings/AllowedTypes.psd1. The bounded profile read uses a plain
# `$Stream.Read(...)` loop on the `[System.IO.FileStream] $Stream` parameter, which
# Test-ProbeProhibitions.ps1's `Find-PPReadReceiverFinding` allows by that parameter's declared
# type, never the stream's own Length.

function Read-PPProfileText {
    # Reads at most MaxProfileBytes + 1 bytes from
    # the stream itself, in a bounded loop - never FileInfo.Length or Stream.Length - so a file that
    # grows after the caller's existence check cannot exceed the cap. BOM sniff, strict UTF-8/UTF-16
    # decode, embedded-NUL check. Returns @{ Bytes = [byte[]]; Text = [string] }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [System.IO.FileStream] $Stream,
        [Parameter(Mandatory)] [hashtable] $Contract
    )

    $maxBytes = [int]$Contract.MaxProfileBytes
    $limit = $maxBytes + 1
    $buffer = [byte[]]::new($limit)
    $total = 0
    while ($total -lt $limit) {
        $read = $Stream.Read($buffer, $total, $limit - $total)
        if ($read -le 0) { break }
        $total += $read
    }
    if ($total -gt $maxBytes) {
        Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('profile exceeds the maximum size of {0} bytes.' -f $maxBytes.ToString([cultureinfo]::InvariantCulture))
    }
    $bytes = [byte[]]::new($total)
    [System.Array]::Copy($buffer, $bytes, $total)

    $body = $bytes
    $decodeError = $false
    $text = ''

    if ($total -ge 4 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE -and $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x00) {
        $decodeError = $true
    }
    elseif ($total -ge 4 -and $bytes[0] -eq 0x00 -and $bytes[1] -eq 0x00 -and $bytes[2] -eq 0xFE -and $bytes[3] -eq 0xFF) {
        $decodeError = $true
    }
    elseif ($total -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $body = [byte[]]::new($total - 3)
        [System.Array]::Copy($bytes, 3, $body, 0, $total - 3)
        try {
            $decoder = [System.Text.UTF8Encoding]::new($false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }
    elseif ($total -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $body = [byte[]]::new($total - 2)
        [System.Array]::Copy($bytes, 2, $body, 0, $total - 2)
        try {
            $decoder = [System.Text.UnicodeEncoding]::new($false, $false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }
    elseif ($total -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $body = [byte[]]::new($total - 2)
        [System.Array]::Copy($bytes, 2, $body, 0, $total - 2)
        try {
            $decoder = [System.Text.UnicodeEncoding]::new($true, $false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }
    else {
        try {
            $decoder = [System.Text.UTF8Encoding]::new($false, $true)
            $text = $decoder.GetString($body)
        }
        catch { $decodeError = $true }
    }

    if (-not $decodeError -and $text.IndexOf([char]0) -ge 0) { $decodeError = $true }
    if ($decodeError) {
        Invoke-PPRefusal -Code 'Profile.Encoding' -Message 'profile is not valid UTF-8/UTF-16; save the profile as UTF-8.'
    }

    [pscustomobject][ordered]@{ Bytes = $bytes; Text = $text }
}

function Get-PPSha256Hex {
    # Plain .NET SHA-256, scoped to this file
    # on tests/Static/settings/AllowedTypes.psd1 (Create()/ComputeHash(byte[]) only). Returns
    # lowercase hex. Disposes the algorithm instance in finally.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]] $Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha256.ComputeHash($Bytes)
    }
    finally {
        $sha256.Dispose()
    }
    $sb = [System.Text.StringBuilder]::new(64)
    foreach ($byteValue in $hash) { [void]$sb.Append($byteValue.ToString('x2', [cultureinfo]::InvariantCulture)) }
    return $sb.ToString()
}

function ConvertFrom-PPCsvText {
    # Own RFC 4180 state machine (never Import-Csv). Returns a
    # List[string[]] of raw records (record 0 is the header); quote handling and record splitting
    # only - header/ragged/blank-record/domain checks are the caller's (Import-PPProfile).
    # $MaxRecords (header + MaxProfileRows data rows) is enforced the
    # instant each record completes - including a blank one - so a hostile file of millions of
    # bare line breaks can never build more than MaxRecords + 1 record objects, whatever its true
    # line count is.
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $MaxRecords)

    $records = [System.Collections.Generic.List[object]]::new()
    $fields = [System.Collections.Generic.List[string]]::new()
    $field = [System.Text.StringBuilder]::new()
    $inQuotes = $false
    $quoteJustClosed = $false
    $len = $Text.Length
    $line = 1

    for ($i = 0; $i -lt $len; ) {
        $ch = $Text[$i]

        if (-not $inQuotes -and $quoteJustClosed -and $ch -cne ',' -and $ch -cne "`r" -and $ch -cne "`n") {
            Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} line {1}: a character after a closing quote must be a comma or end of line.' -f ($records.Count + 1), $line)
        }

        if ($inQuotes) {
            if ($ch -ceq '"') {
                if ($i + 1 -lt $len -and $Text[$i + 1] -ceq '"') {
                    [void]$field.Append('"')
                    $i += 2
                    continue
                }
                $inQuotes = $false
                $quoteJustClosed = $true
                $i++
                continue
            }
            if ($ch -ceq "`n") { $line++ }
            [void]$field.Append($ch)
            $i++
            continue
        }

        if ($ch -ceq '"') {
            if ($field.Length -gt 0) {
                Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} line {1}: a quote character inside an unquoted field.' -f ($records.Count + 1), $line)
            }
            $inQuotes = $true
            $i++
            continue
        }
        if ($ch -ceq ',') {
            $fields.Add($field.ToString())
            [void]$field.Clear()
            $quoteJustClosed = $false
            $i++
            continue
        }
        if ($ch -ceq "`r" -or $ch -ceq "`n") {
            $fields.Add($field.ToString())
            [void]$field.Clear()
            $quoteJustClosed = $false
            if ($ch -ceq "`r" -and $i + 1 -lt $len -and $Text[$i + 1] -ceq "`n") { $i += 2 } else { $i++ }
            $line++
            $records.Add([string[]]$fields.ToArray())
            $fields = [System.Collections.Generic.List[string]]::new()
            if ($records.Count -gt $MaxRecords) {
                Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has more than {0} records.' -f $MaxRecords.ToString([cultureinfo]::InvariantCulture))
            }
            continue
        }
        [void]$field.Append($ch)
        $i++
    }

    if ($inQuotes) {
        Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} line {1}: EOF inside quotes (an opening quote was never closed).' -f ($records.Count + 1), $line)
    }
    if ($field.Length -gt 0 -or $fields.Count -gt 0) {
        $fields.Add($field.ToString())
        $records.Add([string[]]$fields.ToArray())
        if ($records.Count -gt $MaxRecords) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has more than {0} records.' -f $MaxRecords.ToString([cultureinfo]::InvariantCulture))
        }
    }

    return , $records
}

function Read-PPJsonPosition {
    # Line number (1-based) of a character offset, for JSON syntax error messages.
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Offset)

    $line = 1
    $stop = $Offset
    if ($stop -gt $Text.Length) { $stop = $Text.Length }
    for ($i = 0; $i -lt $stop; $i++) { if ($Text[$i] -ceq "`n") { $line++ } }
    return $line
}

function Measure-PPJsonWhitespace {
    # Returns the index of the next non-whitespace character at or after $Pos (JSON whitespace:
    # space, tab, CR, LF only).
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos)

    $i = $Pos
    $len = $Text.Length
    while ($i -lt $len) {
        $c = $Text[$i]
        if ($c -ceq ' ' -or $c -ceq "`t" -or $c -ceq "`r" -or $c -ceq "`n") { $i++ } else { break }
    }
    return $i
}

function Invoke-PPJsonSyntaxError {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Offset, [Parameter(Mandatory)] [string] $Reason)

    $line = Read-PPJsonPosition -Text $Text -Offset $Offset
    Invoke-PPRefusal -Code 'Profile.JsonSyntax' -Message ('line {0}: {1}' -f $line.ToString([cultureinfo]::InvariantCulture), $Reason)
}

function Read-PPJsonString {
    # Reads a JSON string starting at $Text[$Pos] (which must be '"'). Returns @{ Value; Next }.
    # Unescaped runs are appended in bulk (one $Text.Substring/StringBuilder.Append per run, not per
    # character) - per-character appends measured as a major cost at object/array member-count
    # scale, since a profile's realistic key/value strings are almost always entirely unescaped.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos)

    $len = $Text.Length
    $i = $Pos + 1
    $runStart = $i
    # Fast path: a string with no escape and no control character needs neither a StringBuilder nor
    # a run-by-run copy - one Substring returns the whole value. Falls through to the general
    # (correctness-preserving) loop below the moment either is seen.
    while ($i -lt $len) {
        $fc = $Text[$i]
        if ($fc -ceq '"') { return [pscustomobject]@{ Value = $Text.Substring($runStart, $i - $runStart); Next = $i + 1 } }
        if ($fc -ceq '\' -or [int][char]$fc -le 0x1F) { break }
        $i++
    }
    $sb = [System.Text.StringBuilder]::new()
    while ($true) {
        if ($i -ge $len) { Invoke-PPJsonSyntaxError -Text $Text -Offset $Pos -Reason 'unterminated string.' }
        $c = $Text[$i]
        if ($c -ceq '"') {
            if ($i -gt $runStart) { [void]$sb.Append($Text.Substring($runStart, $i - $runStart)) }
            $i++
            break
        }
        if ($c -ceq '\') {
            if ($i -gt $runStart) { [void]$sb.Append($Text.Substring($runStart, $i - $runStart)) }
            if ($i + 1 -ge $len) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'unterminated escape.' }
            $e = $Text[$i + 1]
            switch -CaseSensitive ($e) {
                '"' { [void]$sb.Append('"'); $i += 2 }
                '\' { [void]$sb.Append('\'); $i += 2 }
                '/' { [void]$sb.Append('/'); $i += 2 }
                'b' { [void]$sb.Append([char]8); $i += 2 }
                'f' { [void]$sb.Append([char]12); $i += 2 }
                'n' { [void]$sb.Append([char]10); $i += 2 }
                'r' { [void]$sb.Append([char]13); $i += 2 }
                't' { [void]$sb.Append([char]9); $i += 2 }
                'u' {
                    if ($i + 5 -ge $len) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'incomplete \u escape.' }
                    $hex = $Text.Substring($i + 2, 4)
                    $code = 0
                    $validHex = $true
                    foreach ($hc in $hex.ToCharArray()) {
                        $digit = -1
                        if ($hc -cge '0' -and $hc -cle '9') { $digit = [int][char]$hc - [int][char]'0' }
                        elseif ($hc -cge 'a' -and $hc -cle 'f') { $digit = [int][char]$hc - [int][char]'a' + 10 }
                        elseif ($hc -cge 'A' -and $hc -cle 'F') { $digit = [int][char]$hc - [int][char]'A' + 10 }
                        else { $validHex = $false; break }
                        $code = ($code * 16) + $digit
                    }
                    if (-not $validHex) {
                        Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'invalid \u escape.'
                    }
                    [void]$sb.Append([char]$code)
                    $i += 6
                }
                default { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason ('invalid escape ''\{0}''.' -f $e) }
            }
            $runStart = $i
            continue
        }
        if ([int][char]$c -le 0x1F) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'a raw control character is not permitted in a JSON string.' }
        $i++
    }
    [pscustomobject]@{ Value = $sb.ToString(); Next = $i }
}

function Read-PPJsonNumber {
    # RFC 8259 number grammar only: no leading zero in the integer part (except a lone 0).
    # Returns @{ Value ([long] or [double]); Next }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos)

    # Digit tests are direct char-range comparisons, not -cmatch '[0-9]' (a regex engine call per
    # character measured as a significant cost at MaxProfileRows scale).
    $len = $Text.Length
    $start = $Pos
    $i = $Pos
    if ($i -lt $len -and $Text[$i] -ceq '-') { $i++ }
    if ($i -ge $len -or $Text[$i] -clt '0' -or $Text[$i] -cgt '9') { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'expected a number.' }
    if ($Text[$i] -ceq '0') {
        $i++
        if ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') {
            Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'a leading zero is not a valid JSON number token.'
        }
    }
    else {
        while ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') { $i++ }
    }
    $isFloat = $false
    if ($i -lt $len -and $Text[$i] -ceq '.') {
        $isFloat = $true
        $i++
        if ($i -ge $len -or $Text[$i] -clt '0' -or $Text[$i] -cgt '9') { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'a fraction needs at least one digit.' }
        while ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') { $i++ }
    }
    if ($i -lt $len -and ($Text[$i] -ceq 'e' -or $Text[$i] -ceq 'E')) {
        $isFloat = $true
        $i++
        if ($i -lt $len -and ($Text[$i] -ceq '+' -or $Text[$i] -ceq '-')) { $i++ }
        if ($i -ge $len -or $Text[$i] -clt '0' -or $Text[$i] -cgt '9') { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'an exponent needs at least one digit.' }
        while ($i -lt $len -and $Text[$i] -cge '0' -and $Text[$i] -cle '9') { $i++ }
    }
    $token = $Text.Substring($start, $i - $start)
    if ($isFloat) {
        $value = [double]::Parse($token, [cultureinfo]::InvariantCulture)
    }
    else {
        $value = [long]::Parse($token, [cultureinfo]::InvariantCulture)
    }
    [pscustomobject]@{ Value = $value; Next = $i }
}

function Read-PPJsonValue {
    # Dispatches on the next non-whitespace character. Returns @{ Value; Next }.
    # $ValueBudget is a document-wide counter (a hashtable, a
    # reference type, so every recursive call shares the same one) - every value read anywhere in
    # the document, container or scalar, counts against it; Import-PPProfile sets its Limit to
    # Contract.MaxProfileRows x 16. This is what stops a document built from many small siblings
    # (say 255 arrays of 8192 zeros each): no single array or object exceeds its own MaxItems, and
    # none of them nests past the schema's real depth, so neither of those checks alone catches it -
    # but 255 x 8192 = 2,088,960 values blows through this total long before the document finishes.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos, [Parameter(Mandatory)] [int] $Depth, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [hashtable] $ValueBudget)

    $ValueBudget.Count = $ValueBudget.Count + 1
    if ($ValueBudget.Count -gt $ValueBudget.Limit) {
        Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the document has more than {0} JSON values.' -f $ValueBudget.Limit.ToString([cultureinfo]::InvariantCulture))
    }

    # Whitespace skip inlined (not a Measure-PPJsonWhitespace call): this dispatch runs once per
    # array/object member, and the per-call overhead of PowerShell's advanced-function machinery
    # measured as the dominant cost at MaxProfileRows scale, not the scan itself.
    $p = $Pos
    $textLen = $Text.Length
    while ($p -lt $textLen) {
        $wc = $Text[$p]
        if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $p++ } else { break }
    }
    if ($p -ge $textLen) { Invoke-PPJsonSyntaxError -Text $Text -Offset $p -Reason 'unexpected end of input; expected a value.' }
    $c = $Text[$p]
    if ($c -ceq '{') { return Read-PPJsonObject -Text $Text -Pos $p -Depth $Depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget }
    if ($c -ceq '[') { return Read-PPJsonArray -Text $Text -Pos $p -Depth $Depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget }
    if ($c -ceq '"') {
        $r = Read-PPJsonString -Text $Text -Pos $p
        return [pscustomobject]@{ Value = $r.Value; Next = $r.Next }
    }
    if ($c -ceq '-' -or ($c -cge '0' -and $c -cle '9')) { return Read-PPJsonNumber -Text $Text -Pos $p }
    if ($p + 4 -le $Text.Length -and $Text.Substring($p, 4) -ceq 'true') { return [pscustomobject]@{ Value = $true; Next = $p + 4 } }
    if ($p + 5 -le $Text.Length -and $Text.Substring($p, 5) -ceq 'false') { return [pscustomobject]@{ Value = $false; Next = $p + 5 } }
    if ($p + 4 -le $Text.Length -and $Text.Substring($p, 4) -ceq 'null') { return [pscustomobject]@{ Value = $null; Next = $p + 4 } }
    if ($c -ceq '/') { Invoke-PPJsonSyntaxError -Text $Text -Offset $p -Reason 'JSON does not allow comments.' }
    Invoke-PPJsonSyntaxError -Text $Text -Offset $p -Reason ('unexpected character ''{0}''.' -f $c)
}

function ConvertTo-PPJsonObjectValue {
    # Wraps a parsed JSON object's [ordered] dictionary in a discriminated marker. The marker
    # (JsonKind/Data) is used instead of an `-is`/`-isnot` type check against the dictionary's own
    # .NET type, because that type is not on tests/Static/settings/AllowedTypes.psd1 and `[ordered]`
    # itself only resolves as a hashtable-literal cast prefix, not as a general type reference.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Data)

    [pscustomobject]@{ JsonKind = 'Object'; Data = $Data }
}

function ConvertTo-PPJsonArrayValue {
    # See ConvertTo-PPJsonObjectValue for why this marker exists instead of a type check.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $Data)

    [pscustomobject]@{ JsonKind = 'Array'; Data = $Data }
}

function Test-PPJsonValueKind {
    [CmdletBinding()]
    [OutputType([bool])]
    param($Value, [Parameter(Mandatory)] [string] $Kind)

    return [bool]($Value -is [pscustomobject] -and $null -ne $Value.JsonKind -and $Value.JsonKind -ceq $Kind)
}

function Read-PPJsonObject {
    # An object is capped at $MaxItems members, the same
    # bound Read-PPJsonArray uses for elements - the profile schema defines no groups-specific
    # member-count constant (MaxGroupItems bounds the item count *within* one bound group's value, a
    # different thing), so this reuses MaxItems/Contract.MaxProfileRows uniformly, exactly as arrays
    # already do. Checked the instant a new key is accepted, before its value is even parsed -
    # earlier than the array check can be (an array element has no name to count until its value is
    # read).
    #
    # The profile schema never nests a container past this depth
    # (root object -> "rows" array/"groups" object -> row object, at incoming $Depth 0/1/2 in turn -
    # a row object's own fields, and a group's own value, are always scalars). A container that
    # opens at incoming $Depth 3 or deeper is refused outright: nothing legitimate needs it, and it
    # is cheap insurance against a container stuffed somewhere a scalar was expected. Depth alone
    # cannot catch every hostile shape (an illegitimate array standing where a row object belongs
    # sits at the *same* depth as a legitimate row object would) - $ValueBudget above is what stops
    # that one.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos, [Parameter(Mandatory)] [int] $Depth, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [hashtable] $ValueBudget)

    if ($Depth -ge 3) {
        Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message 'nesting deeper than the profile schema ever needs (the profile schema nests no container past depth 2).'
    }
    $depth = $Depth + 1
    if ($depth -gt $MaxDepth) { Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message ('nesting exceeds the maximum depth of {0}.' -f $MaxDepth.ToString([cultureinfo]::InvariantCulture)) }
    $obj = [ordered]@{}
    $seen = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $i = $Pos + 1
    $i = Measure-PPJsonWhitespace -Text $Text -Pos $i
    if ($i -lt $Text.Length -and $Text[$i] -ceq '}') {
        return [pscustomobject]@{ Value = (ConvertTo-PPJsonObjectValue -Data $obj); Next = $i + 1 }
    }
    $textLen = $Text.Length
    while ($true) {
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $textLen -or $Text[$i] -cne '"') { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected a string key.' }
        # Key names are read inline (not via a Read-PPJsonString call) for the common unescaped
        # case - every member pays this cost once for its key
        # and once for a string value, and the per-call overhead of PowerShell's advanced-function
        # machinery was measured as the dominant remaining cost at 8192-member scale. Read-PPJsonString
        # (with its own identical fast path) still runs for the rare escaped/control-character key.
        $keyScan = $i + 1
        $keyHasEscape = $false
        while ($keyScan -lt $textLen) {
            $kc = $Text[$keyScan]
            if ($kc -ceq '"') { break }
            if ($kc -ceq '\' -or [int][char]$kc -le 0x1F) { $keyHasEscape = $true; break }
            $keyScan++
        }
        if (-not $keyHasEscape -and $keyScan -lt $textLen) {
            $keyResult = [pscustomobject]@{ Value = $Text.Substring($i + 1, $keyScan - $i - 1); Next = $keyScan + 1 }
        }
        else {
            $keyResult = Read-PPJsonString -Text $Text -Pos $i
        }
        $key = $keyResult.Value
        if ($seen.ContainsKey($key)) { Invoke-PPRefusal -Code 'Profile.JsonDuplicateKey' -Message ("duplicate object key '{0}'." -f (Get-PPSafeText -Text $key)) }
        $seen[$key] = $true
        if ($seen.Count -gt $MaxItems) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('an object exceeds the maximum size of {0} members.' -f $MaxItems.ToString([cultureinfo]::InvariantCulture))
        }
        $i = $keyResult.Next
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $textLen -or $Text[$i] -cne ':') { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected '':'' after an object key.' }
        $i++
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        # Fast path for a string-valued member (DESIGN's own "groups" object shape: every value is a
        # string) - skips Read-PPJsonValue's generic dispatch layer entirely for the common case,
        # and (like the key above) reads the common unescaped case inline rather than through a
        # Read-PPJsonString call. Read-PPJsonValue/Read-PPJsonString still handle everything else
        # (objects, arrays, numbers, booleans, null, and any escaped/control-character string)
        # exactly as before.
        if ($i -lt $textLen -and $Text[$i] -ceq '"') {
            # A fast-pathed value bypasses Read-PPJsonValue entirely (that is the point of the fast
            # path), so it must still count against $ValueBudget itself here - otherwise a document
            # built entirely of fast-pathable string-valued members would never be counted at all.
            $ValueBudget.Count = $ValueBudget.Count + 1
            if ($ValueBudget.Count -gt $ValueBudget.Limit) {
                Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the document has more than {0} JSON values.' -f $ValueBudget.Limit.ToString([cultureinfo]::InvariantCulture))
            }
            $valScan = $i + 1
            $valHasEscape = $false
            while ($valScan -lt $textLen) {
                $vc = $Text[$valScan]
                if ($vc -ceq '"') { break }
                if ($vc -ceq '\' -or [int][char]$vc -le 0x1F) { $valHasEscape = $true; break }
                $valScan++
            }
            if (-not $valHasEscape -and $valScan -lt $textLen) {
                $valueResult = [pscustomobject]@{ Value = $Text.Substring($i + 1, $valScan - $i - 1); Next = $valScan + 1 }
            }
            else {
                $valueResult = Read-PPJsonString -Text $Text -Pos $i
            }
        }
        else {
            $valueResult = Read-PPJsonValue -Text $Text -Pos $i -Depth $depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget
        }
        $obj[$key] = $valueResult.Value
        $i = $valueResult.Next
        while ($i -lt $textLen) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'unterminated object.' }
        if ($Text[$i] -ceq ',') {
            # Trailing comma (",}"): not special-cased with an extra whitespace-skip (same
            # performance reasoning as Read-PPJsonArray) - the next iteration's "expected a string
            # key" naturally rejects '}', still Profile.JsonSyntax.
            $i++
            continue
        }
        if ($Text[$i] -ceq '}') { return [pscustomobject]@{ Value = (ConvertTo-PPJsonObjectValue -Data $obj); Next = $i + 1 } }
        Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected '','' or ''}''.'
    }
}

function Read-PPJsonArray {
    # An array is capped at $MaxItems elements, checked the instant each one
    # is added - never after the whole (possibly hostile) array has been parsed and allocated. This
    # applies to every array in the document (not only "rows"), since a huge single-level array
    # anywhere (e.g. an unknown top-level key) is not bounded by the depth check. This bounds the
    # work to at most MaxItems + 1 elements' worth of parsing, however large the hostile array
    # claims to be - a full lexical pre-scan of the whole array was tried and measured slower for
    # the largest inputs (its own per-character cost scales with the array's full length, where
    # this per-element cap does not), so it was not kept.
    #
    # Same schema-depth reasoning as Read-PPJsonObject (a container
    # opening at incoming $Depth 3+ is refused outright - the schema never nests one there), plus
    # $ValueBudget, the document-wide counter that is what actually stops many sibling arrays, each
    # individually within $MaxItems, from together parsing millions of values.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Text, [Parameter(Mandatory)] [int] $Pos, [Parameter(Mandatory)] [int] $Depth, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [hashtable] $ValueBudget)

    if ($Depth -ge 3) {
        Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message 'nesting deeper than the profile schema ever needs (the profile schema nests no container past depth 2).'
    }
    $depth = $Depth + 1
    if ($depth -gt $MaxDepth) { Invoke-PPRefusal -Code 'Profile.JsonDepth' -Message ('nesting exceeds the maximum depth of {0}.' -f $MaxDepth.ToString([cultureinfo]::InvariantCulture)) }
    $list = [System.Collections.Generic.List[object]]::new()
    $i = $Pos + 1
    $i = Measure-PPJsonWhitespace -Text $Text -Pos $i
    if ($i -lt $Text.Length -and $Text[$i] -ceq ']') {
        return [pscustomobject]@{ Value = (ConvertTo-PPJsonArrayValue -Data $list); Next = $i + 1 }
    }
    $textLen2 = $Text.Length
    while ($true) {
        while ($i -lt $textLen2) {
            $awc = $Text[$i]
            if ($awc -ceq ' ' -or $awc -ceq "`t" -or $awc -ceq "`r" -or $awc -ceq "`n") { $i++ } else { break }
        }
        # Fast path for a number or plain-string element (the same
        # element-count budget check as before, now also proven at true document-wide scale, so the
        # per-element dispatch overhead this bypasses matters far more than it used to) - skips
        # Read-PPJsonValue's dispatch layer entirely for the two most common element shapes, calling
        # Read-PPJsonNumber/Read-PPJsonString directly instead; $ValueBudget is still counted here,
        # since it bypasses the one place that normally counts it. Objects, arrays, booleans and null
        # still go through Read-PPJsonValue exactly as before (depth and recursion still apply).
        if ($i -lt $textLen2 -and (($Text[$i] -cge '0' -and $Text[$i] -cle '9') -or $Text[$i] -ceq '-' -or $Text[$i] -ceq '"')) {
            $ValueBudget.Count = $ValueBudget.Count + 1
            if ($ValueBudget.Count -gt $ValueBudget.Limit) {
                Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the document has more than {0} JSON values.' -f $ValueBudget.Limit.ToString([cultureinfo]::InvariantCulture))
            }
            if ($Text[$i] -ceq '"') {
                $valScan2 = $i + 1
                $valHasEscape2 = $false
                while ($valScan2 -lt $textLen2) {
                    $vc2 = $Text[$valScan2]
                    if ($vc2 -ceq '"') { break }
                    if ($vc2 -ceq '\' -or [int][char]$vc2 -le 0x1F) { $valHasEscape2 = $true; break }
                    $valScan2++
                }
                if (-not $valHasEscape2 -and $valScan2 -lt $textLen2) {
                    $valueResult = [pscustomobject]@{ Value = $Text.Substring($i + 1, $valScan2 - $i - 1); Next = $valScan2 + 1 }
                }
                else {
                    $valueResult = Read-PPJsonString -Text $Text -Pos $i
                }
            }
            else {
                # Fast path for the common plain-integer token (no fraction, no exponent, no
                # leading zero beyond a lone "0") - the dominant remaining per-element cost at this
                # scale was Read-PPJsonNumber's own call overhead, not its body. Anything else
                # (a fraction, an exponent, or a leading zero worth its own JsonSyntax message)
                # still falls back to the real function, unchanged.
                $numScan = $i
                if ($numScan -lt $textLen2 -and $Text[$numScan] -ceq '-') { $numScan++ }
                $numStart = $numScan
                while ($numScan -lt $textLen2 -and $Text[$numScan] -cge '0' -and $Text[$numScan] -cle '9') { $numScan++ }
                $isSimple = ($numScan -gt $numStart) -and (-not ($Text[$numStart] -ceq '0' -and $numScan -gt ($numStart + 1))) -and
                (-not ($numScan -lt $textLen2 -and ($Text[$numScan] -ceq '.' -or $Text[$numScan] -ceq 'e' -or $Text[$numScan] -ceq 'E')))
                if ($isSimple) {
                    $valueResult = [pscustomobject]@{ Value = [long]::Parse($Text.Substring($i, $numScan - $i), [cultureinfo]::InvariantCulture); Next = $numScan }
                }
                else {
                    $valueResult = Read-PPJsonNumber -Text $Text -Pos $i
                }
            }
        }
        else {
            $valueResult = Read-PPJsonValue -Text $Text -Pos $i -Depth $depth -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $ValueBudget
        }
        [void]$list.Add($valueResult.Value)
        if ($list.Count -gt $MaxItems) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('an array exceeds the maximum size of {0} items.' -f $MaxItems.ToString([cultureinfo]::InvariantCulture))
        }
        $i = $valueResult.Next
        while ($i -lt $Text.Length) {
            $wc = $Text[$i]
            if ($wc -ceq ' ' -or $wc -ceq "`t" -or $wc -ceq "`r" -or $wc -ceq "`n") { $i++ } else { break }
        }
        if ($i -ge $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'unterminated array.' }
        if ($Text[$i] -ceq ',') {
            # A trailing comma (",]") is not special-cased here with an extra whitespace-skip
            # (performance: this loop runs once per array element) - the
            # next iteration's Read-PPJsonValue naturally rejects ']' as "unexpected character",
            # still Profile.JsonSyntax, just with a more generic message.
            $i++
            continue
        }
        if ($Text[$i] -ceq ']') { return [pscustomobject]@{ Value = (ConvertTo-PPJsonArrayValue -Data $list); Next = $i + 1 } }
        Invoke-PPJsonSyntaxError -Text $Text -Offset $i -Reason 'expected '','' or '']''.'
    }
}

function ConvertFrom-PPStrictJson {
    # Own recursive-descent reader (never ConvertFrom-Json). RFC 8259 grammar only:
    # no comments, no trailing commas, no single quotes, no NaN; depth > MaxDepth ->
    # Profile.JsonDepth; case-insensitive duplicate member names -> Profile.JsonDuplicateKey; any
    # array/object over MaxItems elements/members -> Profile.TooLarge, checked while reading;
    # a container nested past the schema's own real depth,
    # or the whole document parsing more than $MaxValues JSON values in total -> refused before
    # finishing, whichever fires first.
    [CmdletBinding()]
    [OutputType([object])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $MaxDepth, [Parameter(Mandatory)] [int] $MaxItems, [Parameter(Mandatory)] [int] $MaxValues)

    $valueBudget = @{ Count = 0; Limit = $MaxValues }
    $start = Measure-PPJsonWhitespace -Text $Text -Pos 0
    if ($start -ge $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $start -Reason 'the document is empty.' }
    $result = Read-PPJsonValue -Text $Text -Pos $start -Depth 0 -MaxDepth $MaxDepth -MaxItems $MaxItems -ValueBudget $valueBudget
    $tail = Measure-PPJsonWhitespace -Text $Text -Pos $result.Next
    if ($tail -lt $Text.Length) { Invoke-PPJsonSyntaxError -Text $Text -Offset $tail -Reason 'unexpected content after the document.' }
    return $result.Value
}

function Assert-PPLiteralTargetClass {
    # Calls Test-RefusedTargetClass; throws PortProof.RefusedTargetClass. Called by
    # the parser for every row-level literal and by the Expander for every literal a group or CIDR
    # produces.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Net.IPAddress] $Address,
        [Parameter(Mandatory)] [int] $Row,
        [Parameter(Mandatory)] [string] $Field,
        [Parameter(Mandatory)] [string] $Origin
    )

    $verdict = Test-RefusedTargetClass -Address $Address
    if ($verdict.Refused) {
        Invoke-PPRefusal -Code 'RefusedTargetClass' -Row $Row -Message (
            "row {0} {1} '{2}' resolves to {3}: {4}; PortProof refuses this address class" -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field, (Get-PPSafeText -Text $Origin), $verdict.Canonical.ToString(), $verdict.ClassLabel)
    }
}

function Test-PPCredentialLikeName {
    # Flags a CSV column name that looks like it would carry a credential. Lower-cased with
    # ToLowerInvariant first, then matched case-sensitively, so no culture (tr-TR) changes what
    # this matches (the culture-invariant-comparison fix already applied elsewhere in src/).
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string] $Name)

    $lower = $Name.ToLowerInvariant()
    return [bool]($lower -cmatch 'pass|pwd|secret|token|cred|apikey|api_key|private')
}

function Test-PPSameName {
    # Ordinal, case-insensitive equality (never PowerShell's culture-sensitive -ieq/-eq on
    # strings; see 05-Contract.ps1/90-Main.ps1 for the same established fix in this codebase).
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $A, [Parameter(Mandatory)] [AllowEmptyString()] [string] $B)

    return [string]::Equals($A, $B, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-PPTargetGrammar {
    # Shared Source/Target validation for one field of one row:
    # non-empty, not Invalid, literal classes checked before the NonCanonical domain rejection.
    # Returns the PortProof.TargetKind verdict (Kind is 'Group'|'IPv4'|'IPv6'|'Hostname' on success).
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter(Mandatory)] [int] $Row,
        [Parameter(Mandatory)] [string] $Field
    )

    if ([string]::IsNullOrEmpty($Text)) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} is empty.' -f $Row.ToString([cultureinfo]::InvariantCulture), $Field)
    }
    $kind = Get-PPTargetKind -Text $Text
    if ($kind.Kind -ceq 'Invalid') {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} ''{2}'' is not a valid address, host name or group reference: {3}.' -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field, (Get-PPSafeText -Text $Text), $kind.Reason)
    }
    if ($kind.Kind -ceq 'IPv4' -or $kind.Kind -ceq 'IPv6' -or $kind.Kind -ceq 'NonCanonicalLiteral') {
        Assert-PPLiteralTargetClass -Address $kind.Address -Row $Row -Field $Field -Origin $Text
        if ($kind.Kind -ceq 'NonCanonicalLiteral') {
            Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} ''{2}'' is not canonical: {3}.' -f
                $Row.ToString([cultureinfo]::InvariantCulture), $Field, (Get-PPSafeText -Text $Text), $kind.Reason)
        }
    }
    return $kind
}

function Assert-PPFieldLength {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $Max, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [string] $Field)

    if ($Text.Length -gt $Max) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} exceeds the maximum length of {2} characters.' -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field, $Max.ToString([cultureinfo]::InvariantCulture))
    }
}

function Assert-PPNoControlChar {
    # The same control-character rule Source/Target already apply
    # (Get-PPTargetKind's rule 1, [\u0000-\u001F\u007F-\u009F] anywhere -> Invalid) extended to
    # every other free-text profile field - Service and Notes here, matching the profile-level
    # name/version checks in Import-PPProfile, which already carried this rule.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [string] $Field)

    if ($Text -cmatch '[\u0000-\u001F\u007F-\u009F]') {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} {1} contains a control character.' -f
            $Row.ToString([cultureinfo]::InvariantCulture), $Field)
    }
}

function Assert-PPCsvHeader {
    # Validates the CSV header row. Returns @{ Index = <name -> column index dictionary>;
    # Ignored = [string[]]; Warnings = [string[]] }.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Header)

    $required = @('Source', 'Target', 'Port', 'Protocol', 'Required')
    $optional = @('Service', 'Notes')
    $index = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $ignored = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    for ($i = 0; $i -lt $Header.Length; $i++) {
        $name = $Header[$i]
        if ($name -cne $name.Trim()) {
            Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ("column '{0}' has leading or trailing whitespace." -f (Get-PPSafeText -Text $name))
        }
        if ($index.ContainsKey($name)) {
            Invoke-PPRefusal -Code 'Profile.DuplicateColumn' -Message ("column '{0}' is listed twice." -f (Get-PPSafeText -Text $name))
        }
        $index[$name] = $i
    }
    foreach ($name in $required) {
        if (-not $index.ContainsKey($name)) {
            Invoke-PPRefusal -Code 'Profile.MissingColumn' -Message ("required column '{0}' is missing." -f $name)
        }
    }
    foreach ($name in $Header) {
        $isKnown = $false
        foreach ($known in $required) { if (Test-PPSameName -A $known -B $name) { $isKnown = $true } }
        foreach ($known in $optional) { if (Test-PPSameName -A $known -B $name) { $isKnown = $true } }
        if (-not $isKnown) {
            $ignored.Add($name)
            $warning = "column '{0}' is not a known column; its values are ignored." -f (Get-PPSafeText -Text $name)
            if (Test-PPCredentialLikeName -Name $name) { $warning += ' (looks like a credential field; its values were not read)' }
            $warnings.Add($warning)
        }
    }
    [pscustomobject]@{ Index = $index; Ignored = [string[]]$ignored.ToArray(); Warnings = [string[]]$warnings.ToArray() }
}

function Get-PPCsvFieldByName {
    # Looks up one named column's raw value in one CSV data record, '' when the column is absent
    # (an optional column the header did not carry).
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Record, [Parameter(Mandatory)] $HeaderInfo, [Parameter(Mandatory)] [string] $Name)

    $idx = $null
    if ($HeaderInfo.Index.TryGetValue($Name, [ref]$idx)) { return $Record[$idx] }
    return ''
}

function ConvertTo-PPCsvRow {
    # Validates one CSV data record into a PortProof.ProfileRow.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [AllowEmptyString()] [string[]] $Record, [Parameter(Mandatory)] $HeaderInfo, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [hashtable] $Contract)

    $sourceText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Source'
    $targetText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Target'
    $portText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Port'
    $protocolText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Protocol'
    $requiredText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Required'
    $serviceText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Service'
    $notesText = Get-PPCsvFieldByName -Record $Record -HeaderInfo $HeaderInfo -Name 'Notes'

    $null = Assert-PPTargetGrammar -Text $sourceText -Row $Row -Field 'Source'
    $null = Assert-PPTargetGrammar -Text $targetText -Row $Row -Field 'Target'
    Assert-PPFieldLength -Text $sourceText -Max ([int]$Contract.MaxFieldLength.Source) -Row $Row -Field 'Source'
    Assert-PPFieldLength -Text $targetText -Max ([int]$Contract.MaxFieldLength.Target) -Row $Row -Field 'Target'

    if ($portText -cnotmatch '\A[1-9][0-9]{0,4}\z') {
        $reason = 'is not a plain integer'
        if ($portText -cmatch '\A0[0-9]+\z') { $reason = 'has a leading zero' }
        elseif ($portText -cmatch '[-,*]') { $reason = 'has a range, list or wildcard; PortProof has no port ranges' }
        elseif ($portText -cmatch '\A0\z') { $reason = 'is 0, out of range 1..65535' }
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} Port ''{1}'' {2}.' -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $portText), $reason)
    }
    $port = [int]::Parse($portText, [cultureinfo]::InvariantCulture)
    if ($port -lt 1 -or $port -gt 65535) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} Port {1} is out of range 1..65535.' -f $Row.ToString([cultureinfo]::InvariantCulture), $port.ToString([cultureinfo]::InvariantCulture))
    }

    $protocol = $null
    foreach ($known in $Contract.ProfileProtocols) { if (Test-PPSameName -A $known -B $protocolText) { $protocol = $known } }
    if ($null -eq $protocol) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ("row {0} Protocol '{1}' is not TCP or UDP." -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $protocolText))
    }

    $required = $null
    foreach ($known in $Contract.RequiredValues) { if (Test-PPSameName -A $known -B $requiredText) { $required = $known } }
    if ($null -eq $required) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ("row {0} Required '{1}' is not yes or no." -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $requiredText))
    }

    Assert-PPFieldLength -Text $serviceText -Max ([int]$Contract.MaxFieldLength.Service) -Row $Row -Field 'Service'
    Assert-PPFieldLength -Text $notesText -Max ([int]$Contract.MaxFieldLength.Notes) -Row $Row -Field 'Notes'
    Assert-PPNoControlChar -Text $serviceText -Row $Row -Field 'Service'
    Assert-PPNoControlChar -Text $notesText -Row $Row -Field 'Notes'

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.ProfileRow'
        Row        = $Row
        Source     = $sourceText
        Target     = $targetText
        Port       = $port
        Protocol   = $protocol
        Required   = $required
        Service    = $serviceText
        Notes      = $notesText
    }
}

function ConvertTo-PPJsonRow {
    # Validates one JSON row object into a PortProof.ProfileRow.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] $RowObject, [Parameter(Mandatory)] [int] $Row, [Parameter(Mandatory)] [hashtable] $Contract)

    if (-not (Test-PPJsonValueKind -Value $RowObject -Kind 'Object')) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} must be a JSON object.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }
    $data = $RowObject.Data
    $required = @('source', 'target', 'port', 'protocol', 'required')
    $optional = @('service', 'notes')
    $keyIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($key in $data.Keys) { $keyIndex[$key] = $true }
    foreach ($name in $required) {
        if (-not $keyIndex.ContainsKey($name)) {
            Invoke-PPRefusal -Code 'Profile.MissingColumn' -Row $Row -Message ("row {0} is missing required key '{1}'." -f $Row.ToString([cultureinfo]::InvariantCulture), $name)
        }
    }
    foreach ($key in $data.Keys) {
        $known = $false
        foreach ($name in $required) { if (Test-PPSameName -A $name -B $key) { $known = $true } }
        foreach ($name in $optional) { if (Test-PPSameName -A $name -B $key) { $known = $true } }
        if (-not $known) {
            Invoke-PPRefusal -Code 'Profile.UnknownKey' -Row $Row -Message ("row {0} has an unknown key '{1}'." -f $Row.ToString([cultureinfo]::InvariantCulture), (Get-PPSafeText -Text $key))
        }
    }

    $sourceValue = $data['source']
    $targetValue = $data['target']
    if ($sourceValue -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} source must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
    if ($targetValue -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} target must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
    $null = Assert-PPTargetGrammar -Text $sourceValue -Row $Row -Field 'source'
    $null = Assert-PPTargetGrammar -Text $targetValue -Row $Row -Field 'target'
    Assert-PPFieldLength -Text $sourceValue -Max ([int]$Contract.MaxFieldLength.Source) -Row $Row -Field 'source'
    Assert-PPFieldLength -Text $targetValue -Max ([int]$Contract.MaxFieldLength.Target) -Row $Row -Field 'target'

    $portValue = $data['port']
    if ($portValue -is [long]) {
        if ($portValue -lt 1L -or $portValue -gt 65535L) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port {1} is out of range 1..65535, or has a sign, not a bare integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture), $portValue.ToString([cultureinfo]::InvariantCulture))
        }
        $port = [int]$portValue
    }
    elseif ($portValue -is [double]) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port has a fraction or exponent, not a bare integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }
    elseif ($portValue -is [string]) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port is given as a JSON string, not an integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }
    else {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} port must be a JSON integer token.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }

    $protocolValue = $data['protocol']
    $protocol = $null
    if ($protocolValue -is [string]) {
        foreach ($known in $Contract.ProfileProtocols) { if (Test-PPSameName -A $known -B $protocolValue) { $protocol = $known } }
    }
    if ($null -eq $protocol) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} protocol is not TCP or UDP.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }

    $requiredValue = $data['required']
    $requiredOut = $null
    if ($requiredValue -is [string]) {
        foreach ($known in $Contract.RequiredValues) { if (Test-PPSameName -A $known -B $requiredValue) { $requiredOut = $known } }
    }
    if ($null -eq $requiredOut) {
        Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} required must be the string ''yes'' or ''no''.' -f $Row.ToString([cultureinfo]::InvariantCulture))
    }

    $serviceValue = ''
    if ($keyIndex.ContainsKey('service')) {
        if ($data['service'] -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} service must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
        $serviceValue = $data['service']
    }
    $notesValue = ''
    if ($keyIndex.ContainsKey('notes')) {
        if ($data['notes'] -isnot [string]) { Invoke-PPRefusal -Code 'Profile.Domain' -Row $Row -Message ('row {0} notes must be a JSON string.' -f $Row.ToString([cultureinfo]::InvariantCulture)) }
        $notesValue = $data['notes']
    }
    Assert-PPFieldLength -Text $serviceValue -Max ([int]$Contract.MaxFieldLength.Service) -Row $Row -Field 'service'
    Assert-PPFieldLength -Text $notesValue -Max ([int]$Contract.MaxFieldLength.Notes) -Row $Row -Field 'notes'
    Assert-PPNoControlChar -Text $serviceValue -Row $Row -Field 'service'
    Assert-PPNoControlChar -Text $notesValue -Row $Row -Field 'notes'

    [pscustomobject][ordered]@{
        PSTypeName = 'PortProof.ProfileRow'
        Row        = $Row
        Source     = $sourceValue
        Target     = $targetValue
        Port       = $port
        Protocol   = $protocol
        Required   = $requiredOut
        Service    = $serviceValue
        Notes      = $notesValue
    }
}

function Assert-PPNoDuplicateRow {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Collections.Generic.List[object]] $Rows)

    $seen = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $Rows) {
        $key = '{0}|{1}|{2}|{3}' -f $row.Source, $row.Target, $row.Port, $row.Protocol
        if ($seen.ContainsKey($key)) {
            Invoke-PPRefusal -Code 'Profile.DuplicateRow' -Row $row.Row -Message ('row {0} duplicates row {1}.' -f $row.Row.ToString([cultureinfo]::InvariantCulture), $seen[$key].ToString([cultureinfo]::InvariantCulture))
        }
        $seen[$key] = $row.Row
    }
}

function Import-PPProfile {
    # Reads and validates a whole profile file -> PortProof.Profile. $Path is a resolved, existing full provider path.
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)] [string] $Path, [Parameter(Mandatory)] [hashtable] $Contract)

    $fileName = [System.IO.Path]::GetFileName($Path)
    $isJson = (Test-PPSameName -A ([System.IO.Path]::GetExtension($Path)) -B '.json')
    $format = if ($isJson) { 'Json' } else { 'Csv' }

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $read = Read-PPProfileText -Stream $stream -Contract $Contract
    }
    finally {
        $stream.Dispose()
    }
    $sha256 = Get-PPSha256Hex -Bytes $read.Bytes
    $text = $read.Text

    $rows = [System.Collections.Generic.List[object]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $ignoredColumns = [string[]]@()
    $name = ''
    $version = ''
    $groups = [ordered]@{}

    if ($isJson) {
        $docValue = ConvertFrom-PPStrictJson -Text $text -MaxDepth ([int]$Contract.MaxJsonDepth) -MaxItems ([int]$Contract.MaxProfileRows) -MaxValues ([int]$Contract.MaxProfileRows * 16)
        if (-not (Test-PPJsonValueKind -Value $docValue -Kind 'Object')) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message 'the document must be a JSON object.'
        }
        $doc = $docValue.Data
        $topRequired = @('schema', 'name', 'rows')
        $topOptional = @('version', 'groups')
        $topIndex = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $doc.Keys) { $topIndex[$key] = $true }
        foreach ($required in @('schema', 'name')) {
            if (-not $topIndex.ContainsKey($required)) { Invoke-PPRefusal -Code 'Profile.MissingColumn' -Message ("required top-level key '{0}' is missing." -f $required) }
        }
        if (-not $topIndex.ContainsKey('rows')) { Invoke-PPRefusal -Code 'Profile.MissingColumn' -Message "required top-level key 'rows' is missing." }
        foreach ($key in $doc.Keys) {
            $known = $false
            foreach ($allowed in $topRequired) { if (Test-PPSameName -A $allowed -B $key) { $known = $true } }
            foreach ($allowed in $topOptional) { if (Test-PPSameName -A $allowed -B $key) { $known = $true } }
            if (-not $known) { Invoke-PPRefusal -Code 'Profile.UnknownKey' -Message ("unknown top-level key '{0}'." -f (Get-PPSafeText -Text $key)) }
        }

        $schemaValue = $doc['schema']
        if ($schemaValue -isnot [string] -or $schemaValue -cne $Contract.ProfileSchemaId) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message ("schema must be exactly '{0}'." -f $Contract.ProfileSchemaId)
        }
        $nameValue = $doc['name']
        if ($nameValue -isnot [string] -or $nameValue.Length -lt 1 -or $nameValue.Length -gt [int]$Contract.MaxFieldLength.Name -or $nameValue -cmatch '[\u0000-\u001F\u007F-\u009F]') {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message 'name must be 1 to 128 characters with no control characters.'
        }
        $name = $nameValue
        if ($topIndex.ContainsKey('version')) {
            $versionValue = $doc['version']
            if ($versionValue -isnot [string] -or $versionValue.Length -gt [int]$Contract.MaxFieldLength.Version -or $versionValue -cmatch '[\u0000-\u001F\u007F-\u009F]') {
                Invoke-PPRefusal -Code 'Profile.Domain' -Message 'version must be 0 to 64 characters with no control characters.'
            }
            $version = $versionValue
        }
        if ($topIndex.ContainsKey('groups')) {
            $groupsRaw = $doc['groups']
            if (-not (Test-PPJsonValueKind -Value $groupsRaw -Kind 'Object')) {
                Invoke-PPRefusal -Code 'Profile.Domain' -Message 'groups must be a JSON object.'
            }
            $groupsValue = $groupsRaw.Data
            foreach ($key in $groupsValue.Keys) {
                if ($key -cnotmatch '\A[A-Za-z][A-Za-z0-9_]{0,31}\z') {
                    Invoke-PPRefusal -Code 'Profile.Domain' -Message ("groups key '{0}' is not a valid group name." -f (Get-PPSafeText -Text $key))
                }
                $value = $groupsValue[$key]
                if ($value -isnot [string] -or $value.Length -eq 0) {
                    Invoke-PPRefusal -Code 'Profile.Domain' -Message ("groups value for '{0}' must be a non-empty string." -f $key.ToUpperInvariant())
                }
                $groups[$key.ToUpperInvariant()] = $value
            }
        }

        $rowsRaw = $doc['rows']
        if (-not (Test-PPJsonValueKind -Value $rowsRaw -Kind 'Array')) {
            Invoke-PPRefusal -Code 'Profile.Domain' -Message 'rows must be a JSON array.'
        }
        $rowsValue = $rowsRaw.Data
        if ($rowsValue.Count -eq 0) {
            Invoke-PPRefusal -Code 'Profile.Empty' -Message 'the profile has zero data rows.'
        }
        if ($rowsValue.Count -gt [int]$Contract.MaxProfileRows) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has {0} rows; the limit is {1}.' -f $rowsValue.Count.ToString([cultureinfo]::InvariantCulture), ([int]$Contract.MaxProfileRows).ToString([cultureinfo]::InvariantCulture))
        }
        for ($i = 0; $i -lt $rowsValue.Count; $i++) {
            $rowNumber = $i + 1
            $rows.Add((ConvertTo-PPJsonRow -RowObject $rowsValue[$i] -Row $rowNumber -Contract $Contract))
        }
    }
    else {
        $name = [System.IO.Path]::GetFileNameWithoutExtension($Path)
        $records = ConvertFrom-PPCsvText -Text $text -MaxRecords ([int]$Contract.MaxProfileRows + 1)
        if ($records.Count -eq 0) {
            Invoke-PPRefusal -Code 'Profile.Empty' -Message 'the profile is empty.'
        }
        $headerInfo = Assert-PPCsvHeader -Header $records[0]
        foreach ($w in $headerInfo.Warnings) { $warnings.Add($w) }
        $ignoredColumns = $headerInfo.Ignored
        $dataRecords = [System.Collections.Generic.List[object]]::new()
        for ($i = 1; $i -lt $records.Count; $i++) { $dataRecords.Add($records[$i]) }
        if ($dataRecords.Count -eq 0) {
            Invoke-PPRefusal -Code 'Profile.Empty' -Message 'the profile has zero data records.'
        }
        if ($dataRecords.Count -gt [int]$Contract.MaxProfileRows) {
            Invoke-PPRefusal -Code 'Profile.TooLarge' -Message ('the profile has {0} rows; the limit is {1}.' -f $dataRecords.Count.ToString([cultureinfo]::InvariantCulture), ([int]$Contract.MaxProfileRows).ToString([cultureinfo]::InvariantCulture))
        }
        $headerCount = $records[0].Length
        for ($i = 0; $i -lt $dataRecords.Count; $i++) {
            $rowNumber = $i + 2
            $record = $dataRecords[$i]
            if ($record.Length -ne $headerCount) {
                Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0} has fewer or more fields than the header ({1} vs {2}).' -f $rowNumber.ToString([cultureinfo]::InvariantCulture), $record.Length.ToString([cultureinfo]::InvariantCulture), $headerCount.ToString([cultureinfo]::InvariantCulture))
            }
            $allEmpty = $true
            foreach ($field in $record) { if ($field.Length -gt 0) { $allEmpty = $false; break } }
            if ($allEmpty) {
                Invoke-PPRefusal -Code 'Profile.CsvSyntax' -Message ('record {0}: every field is empty.' -f $rowNumber.ToString([cultureinfo]::InvariantCulture))
            }
            $rows.Add((ConvertTo-PPCsvRow -Record $record -HeaderInfo $headerInfo -Row $rowNumber -Contract $Contract))
        }
    }

    Assert-PPNoDuplicateRow -Rows $rows

    [pscustomobject][ordered]@{
        PSTypeName     = 'PortProof.Profile'
        Path           = $Path
        FileName       = $fileName
        Format         = $format
        Sha256         = $sha256
        Name           = $name
        Version        = $version
        Groups         = $groups
        IgnoredColumns = [string[]]$ignoredColumns
        Rows           = [pscustomobject[]]$rows.ToArray()
        Warnings       = [string[]]$warnings.ToArray()
    }
}
