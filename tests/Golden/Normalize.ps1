# Test-only helper: normalises the run-to-run values a rendered
# document carries (RunId, timestamps, OperatorUser, OperatorHost, LatencyMs, ElapsedMs) to fixed
# angle-bracket tokens, so the integration suite can byte-compare an end-to-end run's output against
# a template.
# Never `{{...}}` (that token shape is reserved by AC38 for the release-template mechanism and is
# scanned for elsewhere). The canned golden set in this folder needs no normalisation: every value
# in resultset.json is already fixed, so the renderer's own tests compare output to the golden
# files byte-for-byte with no call to this function.
#
# Scope: RunId and every ISO-8601 timestamp are recognised by shape alone, so the same two regexes
# cover all three output formats. OperatorUser/OperatorHost are free text with no distinctive
# shape, so they are replaced by their known field label in each format (the JSON key, the CSV
# "#Field" header record, or the HTML run-header row) rather than by a pattern that could also
# match unrelated profile-derived text. LatencyMs/ElapsedMs are likewise anchored to their JSON key
# (JSON is the shape most likely to feed an automated comparison); the CSV/HTML per-row LatencyMs
# occurrences are left alone, since a bare integer has no shape that distinguishes it from Port or
# ProfileRow without fully parsing the table - a job for whichever unit builds on this function,
# not for this best-effort helper.

function ConvertTo-PPNormalizedOutput {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text,
        [Parameter(Mandatory)] [ValidateSet('Html', 'Csv', 'Json')] [string] $Format
    )

    $result = $Text
    $result = [regex]::Replace($result, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', '<RUNID>')
    $result = [regex]::Replace($result, '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(Z|[+-]\d{2}:\d{2})', '<TIMESTAMP>')

    switch -CaseSensitive ($Format) {
        'Json' {
            $result = [regex]::Replace($result, '("OperatorUser":\s*)"[^"]*"', '${1}"<OPERATORUSER>"')
            $result = [regex]::Replace($result, '("OperatorHost":\s*)"[^"]*"', '${1}"<OPERATORHOST>"')
            $result = [regex]::Replace($result, '("LatencyMs":\s*)(-?[0-9]+|null)', '${1}"<LATENCYMS>"')
            $result = [regex]::Replace($result, '("ElapsedMs":\s*)-?[0-9]+', '${1}"<ELAPSEDMS>"')
        }
        'Csv' {
            $result = [regex]::Replace($result, '("#OperatorUser",)"[^"]*"', '${1}"<OPERATORUSER>"')
            $result = [regex]::Replace($result, '("#OperatorHost",)"[^"]*"', '${1}"<OPERATORHOST>"')
        }
        'Html' {
            $result = [regex]::Replace($result, '(<td>OperatorUser</td><td>)[^<]*(</td>)', '${1}<OPERATORUSER>${2}')
            $result = [regex]::Replace($result, '(<td>OperatorHost</td><td>)[^<]*(</td>)', '${1}<OPERATORHOST>${2}')
        }
    }
    return $result
}
