<#
    .SYNOPSIS
        AC14 - the HTML report is self-contained: no remote reference in any resource-loading
        position.

    .DESCRIPTION
        Scope and limits: a static regex scan over one rendered HTML file, run at build/CI time -
        not a full HTML parse and not a proof against a determined insider with commit access. The
        backstop for anything this check still misses is the independent pre-release security review.

        Attribute-scoped (AC14): every `src=`, `href=` (except a
        same-document `#...` anchor), `srcset=` attribute value, every `url(` and `@import` inside
        a `<style>` block or a `style=` attribute, and any `<script`, `<link`, `<iframe`,
        `<object`, `<embed`, `<img` tag opening, is a finding. Text content is ignored: this is a
        regex-based scan (no HTML parser dependency is available/permitted), so it only recognises
        literal attribute/tag syntax, not escaped text that merely looks like it - which matches
        the design's own reasoning ("escaped text cannot open a tag").

    .PARAMETER Path
        Path to the HTML file to scan (the rendered report, or a planted-violation fixture).
#>
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Path)

. (Join-Path $PSScriptRoot 'StaticScan.ps1')

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Test-HtmlSelfContained: file not found: $Path"
}

$text = [System.IO.File]::ReadAllText($Path)
$findings = New-Object System.Collections.Generic.List[string]

function Add-PPHtmlFinding {
    param([System.Collections.Generic.List[string]] $Sink, [string] $Path, [string] $Text, [int] $Index, [string] $RawText)
    $line = Get-PPLineNumber -Text $RawText -Offset $Index
    $Sink.Add((Format-PPFinding -Path $Path -Line $line -Rule 'AC14.RemoteReference' -Text $Text))
}

# Forbidden tags outright.
foreach ($tag in @('script', 'link', 'iframe', 'object', 'embed', 'img')) {
    $hits = [regex]::Matches($text, "<$tag\b", [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $hits) {
        Add-PPHtmlFinding -Sink $findings -Path $Path -Text "forbidden tag '<$tag'" -Index $m.Index -RawText $text
    }
}

# src=/href=/srcset= attribute values.
$attrPattern = '(?is)\b(src|href|srcset)\s*=\s*(["''])(.*?)\2'
foreach ($m in [regex]::Matches($text, $attrPattern)) {
    $attrName = $m.Groups[1].Value
    $value = $m.Groups[3].Value.Trim()
    if ($value -eq '' ) { continue }
    if ($attrName -ieq 'href' -and $value.StartsWith('#')) { continue }
    Add-PPHtmlFinding -Sink $findings -Path $Path -Text "$attrName='$value'" -Index $m.Index -RawText $text
}

# url(/@import inside <style> blocks.
foreach ($styleBlock in [regex]::Matches($text, '(?is)<style\b[^>]*>(.*?)</style>')) {
    $blockText = $styleBlock.Groups[1].Value
    $blockOffset = $styleBlock.Groups[1].Index
    foreach ($m in [regex]::Matches($blockText, '(?i)url\s*\(|@import\b')) {
        Add-PPHtmlFinding -Sink $findings -Path $Path -Text "'$($m.Value)' inside <style>" -Index ($blockOffset + $m.Index) -RawText $text
    }
}

# url(/@import inside a style="..." attribute.
foreach ($m in [regex]::Matches($text, '(?is)\bstyle\s*=\s*(["''])(.*?)\1')) {
    $value = $m.Groups[2].Value
    $valueOffset = $m.Groups[2].Index
    foreach ($inner in [regex]::Matches($value, '(?i)url\s*\(|@import\b')) {
        Add-PPHtmlFinding -Sink $findings -Path $Path -Text "'$($inner.Value)' inside a style= attribute" -Index ($valueOffset + $inner.Index) -RawText $text
    }
}

foreach ($f in $findings) { Write-Output $f }
if ($findings.Count -gt 0) { exit 1 } else { exit 0 }
