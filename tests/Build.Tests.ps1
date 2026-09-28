# Build tests (AC2 mechanism, AC32). Synthetic parts are generated in
# $TestDrive at run time; the real build/parts.txt is only read.

BeforeAll {
    $script:Root = Split-Path -Parent $PSScriptRoot
    $script:BuildScript = Join-Path $script:Root 'build/Build-PortProof.ps1'

    function Invoke-Build {
        # Runs the build in-process; captures its error output and exit code.
        param([string] $BuildRoot, [string] $OutFile = 'dist/PortProof.ps1', [string] $PartsFile = 'build/parts.txt')
        $writer = [System.IO.StringWriter]::new()
        $previous = [Console]::Error
        [Console]::SetError($writer)
        try {
            $global:LASTEXITCODE = 0
            $output = @(& $script:BuildScript -Root $BuildRoot -OutFile $OutFile -PartsFile $PartsFile)
            $code = $LASTEXITCODE
        }
        finally {
            [Console]::SetError($previous)
        }
        [pscustomobject]@{ ExitCode = $code; Output = ($output -join "`n"); ErrorText = $writer.ToString() }
    }

    function Initialize-Tree {
        # A synthetic repository: src/<name> for each entry of $Parts (name -> bytes) and a part list.
        param([string] $Name, [System.Collections.Specialized.OrderedDictionary] $Parts, [string] $List)
        $dir = Join-Path $TestDrive $Name
        $null = [System.IO.Directory]::CreateDirectory((Join-Path $dir 'src'))
        $null = [System.IO.Directory]::CreateDirectory((Join-Path $dir 'build'))
        foreach ($key in $Parts.Keys) { [System.IO.File]::WriteAllBytes((Join-Path $dir "src/$key"), [byte[]]$Parts[$key]) }
        if ([string]::IsNullOrEmpty($List)) { $List = (@($Parts.Keys | ForEach-Object { "src/$_" }) -join "`n") + "`n" }
        [System.IO.File]::WriteAllText((Join-Path $dir 'build/parts.txt'), $List)
        $dir
    }

    function ConvertTo-Utf8 {
        param([string] $Text, [switch] $Bom)
        $body = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        if ($Bom) { return [byte[]](@(0xEF, 0xBB, 0xBF) + $body) }
        return [byte[]]$body
    }

    function Get-Sha256 {
        param([string] $Path)
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    $script:PartA = "param([string] `$A)`n# first part, caf$([char]0xE9)`n`$x = 1`n"
    $script:PartB = "function Get-B {`n    'b'`n}`n"
}

Describe 'Build determinism and encoding policy (AC32)' -Tag 'Portable' {
    It 'LF, CRLF, CR, BOM and no-BOM parts build to identical bytes' {
        $variants = [ordered]@{
            lf       = @{ A = (ConvertTo-Utf8 $script:PartA); B = (ConvertTo-Utf8 $script:PartB) }
            crlf     = @{ A = (ConvertTo-Utf8 $script:PartA.Replace("`n", "`r`n")); B = (ConvertTo-Utf8 $script:PartB.Replace("`n", "`r`n")) }
            bomcrlf  = @{ A = (ConvertTo-Utf8 $script:PartA.Replace("`n", "`r`n") -Bom); B = (ConvertTo-Utf8 $script:PartB -Bom) }
            cr       = @{ A = (ConvertTo-Utf8 $script:PartA.Replace("`n", "`r")); B = (ConvertTo-Utf8 $script:PartB.Replace("`n", "`r")) }
            noeol    = @{ A = (ConvertTo-Utf8 $script:PartA.TrimEnd("`n")); B = (ConvertTo-Utf8 $script:PartB.TrimEnd("`n")) }
        }
        $hashes = @()
        foreach ($name in $variants.Keys) {
            $parts = [ordered]@{ '00-A.ps1' = $variants[$name].A; '05-B.ps1' = $variants[$name].B }
            $dir = Initialize-Tree -Name "v-$name" -Parts $parts
            $r = Invoke-Build -BuildRoot $dir
            $r.ExitCode | Should -Be 0 -Because $r.ErrorText
            $hashes += Get-Sha256 -Path (Join-Path $dir 'dist/PortProof.ps1')
        }
        @($hashes | Select-Object -Unique).Count | Should -Be 1
    }

    It 'writes a UTF-8 BOM, CRLF only, a trailing CRLF, a banner before every later part, and nothing else' {
        $dir = Initialize-Tree -Name 'shape' -Parts ([ordered]@{ '00-A.ps1' = (ConvertTo-Utf8 $script:PartA); '05-B.ps1' = (ConvertTo-Utf8 $script:PartB -Bom) })
        (Invoke-Build -BuildRoot $dir).ExitCode | Should -Be 0
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $dir 'dist/PortProof.ps1'))
        ($bytes[0..2] -join ',') | Should -BeExactly '239,187,191'
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            if ($bytes[$i] -eq 10) { $bytes[$i - 1] | Should -Be 13 }
            if ($bytes[$i] -eq 13) { $bytes[$i + 1] | Should -Be 10 }
        }
        $bytes[-2] | Should -Be 13
        $bytes[-1] | Should -Be 10
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes, 3, $bytes.Length - 3)
        $expected = ($script:PartA + "# ---- src/05-B.ps1 ----`n" + $script:PartB).Replace("`n", "`r`n")
        $text | Should -BeExactly $expected
        $text | Should -Not -Match '# ---- src/00-A.ps1'
    }

    It 'two builds of the same tree hash equal and the printed hash is the file hash' {
        $dir = Initialize-Tree -Name 'twice' -Parts ([ordered]@{ '00-A.ps1' = (ConvertTo-Utf8 $script:PartA); '05-B.ps1' = (ConvertTo-Utf8 $script:PartB) })
        $r1 = Invoke-Build -BuildRoot $dir -OutFile 'out1/x.ps1'
        $r2 = Invoke-Build -BuildRoot $dir -OutFile (Join-Path $TestDrive 'abs/y.ps1')
        $h1 = Get-Sha256 -Path (Join-Path $dir 'out1/x.ps1')
        $h2 = Get-Sha256 -Path (Join-Path $TestDrive 'abs/y.ps1')
        $h1 | Should -BeExactly $h2
        $r1.Output | Should -BeLike "$h1  *"
        $r2.Output | Should -BeLike "$h2  *"
    }

    It 'builds the real src/ parts deterministically' {
        $dir = Join-Path $TestDrive 'real'
        $null = [System.IO.Directory]::CreateDirectory((Join-Path $dir 'src'))
        $null = [System.IO.Directory]::CreateDirectory((Join-Path $dir 'build'))
        foreach ($name in '00-Header.ps1', '05-Contract.ps1', '90-Main.ps1') {
            Copy-Item -LiteralPath (Join-Path $script:Root "src/$name") -Destination (Join-Path $dir "src/$name")
        }
        [System.IO.File]::WriteAllText((Join-Path $dir 'build/parts.txt'), "# comment`n`nsrc/00-Header.ps1`nsrc/05-Contract.ps1`nsrc/90-Main.ps1`n")
        (Invoke-Build -BuildRoot $dir -OutFile 'a.ps1').ExitCode | Should -Be 0
        (Invoke-Build -BuildRoot $dir -OutFile 'b.ps1').ExitCode | Should -Be 0
        Get-Sha256 -Path (Join-Path $dir 'a.ps1') | Should -BeExactly (Get-Sha256 -Path (Join-Path $dir 'b.ps1'))
        $tokens = $null; $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $dir 'a.ps1'), [ref]$tokens, [ref]$errors)
        @($errors).Count | Should -Be 0
    }
}

Describe 'Build refusals (exit 1 with a message)' -Tag 'Portable' {
    It 'fails on <Label>' -ForEach @(
        @{ Label = 'an orphan part'; Files = @('00-A.ps1', '05-B.ps1', '07-Orphan.ps1'); List = "src/00-A.ps1`nsrc/05-B.ps1`n"; Text = 'src/07-Orphan.ps1' }
        @{ Label = 'a missing part'; Files = @('00-A.ps1'); List = "src/00-A.ps1`nsrc/05-B.ps1`n"; Text = 'does not exist' }
        @{ Label = 'a duplicate listing'; Files = @('00-A.ps1', '05-B.ps1'); List = "src/00-A.ps1`nsrc/05-B.ps1`nsrc/00-A.ps1`n"; Text = 'more than once' }
        @{ Label = 'a case-variant duplicate'; Files = @('00-A.ps1', '05-B.ps1'); List = "src/00-A.ps1`nsrc/05-B.ps1`nsrc/00-a.ps1`n"; Text = 'more than once' }
        @{ Label = 'an upper-case SRC prefix'; Files = @('00-A.ps1'); List = "SRC/00-A.ps1`n"; Text = 'src/<name>.ps1' }
        @{ Label = 'a non-ASCII look-alike in a part name'; Files = @('00-A.ps1'); List = ("src/00-A.ps1`nsrc/0" + [char]0x212A + ".ps1`n"); Text = 'src/<name>.ps1' }
        @{ Label = 'a backslash separator'; Files = @('00-A.ps1'); List = "src\00-A.ps1`n"; Text = "'/' separators" }
        @{ Label = 'a path outside src'; Files = @('00-A.ps1'); List = "src/00-A.ps1`nbuild/Build-PortProof.ps1`n"; Text = 'src/<name>.ps1' }
        @{ Label = 'a parent-directory path'; Files = @('00-A.ps1'); List = "src/../src/00-A.ps1`n"; Text = 'src/<name>.ps1' }
        @{ Label = 'an empty list'; Files = @('00-A.ps1'); List = "# nothing`n"; Text = 'names no parts' }
    ) {
        $parts = [ordered]@{}
        foreach ($f in $Files) { $parts[$f] = ConvertTo-Utf8 "'$f'`n" }
        $dir = Initialize-Tree -Name ('fail-' + [guid]::NewGuid().ToString('N')) -Parts $parts -List $List
        $r = Invoke-Build -BuildRoot $dir
        $r.ExitCode | Should -Be 1
        $r.ErrorText | Should -BeLike ('Build-PortProof: *' + [WildcardPattern]::Escape($Text) + '*')
        Test-Path -LiteralPath (Join-Path $dir 'dist/PortProof.ps1') | Should -BeFalse
    }

    It 'fails on a part that is not valid UTF-8' {
        $dir = Initialize-Tree -Name 'badutf8' -Parts ([ordered]@{ '00-A.ps1' = [byte[]](0x27, 0xC3, 0x28, 0x27, 0x0A) })
        $r = Invoke-Build -BuildRoot $dir
        $r.ExitCode | Should -Be 1
        $r.ErrorText | Should -BeLike '*not valid UTF-8*'
    }
}

Describe 'The real part list (AC2 prerequisite)' -Tag 'Portable' {
    It 'lists exactly the 14 design parts in order' {
        $lines = @(Get-Content -LiteralPath (Join-Path $script:Root 'build/parts.txt') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' -and -not $_.StartsWith('#') })
        ($lines -join ',') | Should -BeExactly (@(
                'src/00-Header.ps1', 'src/05-Contract.ps1', 'src/10-Parser.ps1', 'src/20-Expander.ps1', 'src/30-Resolver.ps1',
                'src/35-Gate.ps1', 'src/40-Scheduler.ps1', 'src/50-Probe.Tcp.ps1', 'src/55-Probe.Udp.ps1', 'src/58-Probe.Icmp.ps1',
                'src/70-Render.Html.ps1', 'src/72-Render.Csv.ps1', 'src/74-Render.Json.ps1', 'src/90-Main.ps1') -join ',')
    }
}
