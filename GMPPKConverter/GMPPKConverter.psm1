<#
    .SYNOPSIS
        Convert PPK key format to OpenSSH key format or Private key format
    .SYNOPSIS
        Convert PPK key format to OpenSSH key format or Private key format
        Provate key UNENCRYPTED
    .PARAMETER KeyContent
        PPK key file content
    .PARAMETER AsPrivate
        Output key in private key format
    .PARAMETER AsOpenSSH
        Output key in openssh key format
    .PARAMETER Password
        PPK Key Password
    .PARAMETER CodePage
        PPK Key content codepage, if 0 - use current console codepage
            Note: It mandatory under linux because modern default linux codepage is utf-8
            and Putty save file under windows non-utf code page, for example 1251
    .OUTPUTS
        Converted key
    .EXAMPLE
        # ppk password from user input
        $c = Get-Credential xxx
        # default windows cyrillic encoding
        $encoding = [Text.Encoding]::getEncoding(1251)
        # Read key from file and convert it to OpenSSH format
        $content = Get-Content /home/username/test.ppk -Encoding $encoding
        ConvertFrom-PPK -AsOpenSSH -Password $c.Password -KeyContent $content -CodePage 1251
    .EXAMPLE
        # ppk password from user input
        $c = Get-Credential xxx
        # default windows cyrillic encoding
        $encoding = [Text.Encoding]::getEncoding(1251)
        # Read key from file and send it to convert to Private key format thru pipeline
        Get-Content /home/username/test.ppk -Encoding $encoding |
            ConvertFrom-PPK -AsPrivate -Password $c.Password -CodePage 1251
    .EXAMPLE
        # ppk password from user input
        $c = Get-Credential xxx
        # default windows cyrillic encoding
        $encoding = [Text.Encoding]::getEncoding(1251)
        # Read key from file and send it to convert to Private key format thru pipeline
        "PuTTY-User-Key-File-2: ecdsa-sha2-nistp384
        Encryption: aes256-cbc
        Comment: test тест
        Public-Lines: 3
        AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBGxV9kTEQnAU
        HV1Xvyz6VpGp5uDlcHEYxyz+FsWgEASLKrGTJtfWPLNUUR6wiJV0e1AbO6G3fUxN
        e/SKTi2LBrSu5bxbwFV5BLJH/JU9ce/q29rwQ25w9d0BWKeAA6FAhA==
        Private-Lines: 2
        FRV4NgRMeOI9yILJko1WP6LZbChiEl+SxvGkto4gcMPovyN47gmM5My186IMrVh7
        8224AVCFz61Vhby3JsIHBA==
        Private-MAC: 6f85e47ea4ef3083110eb0ab700e4f8201348b8a
        " -split "\n" | ConvertFrom-PPK -AsPrivate -Password $c.Password -CodePage 1251
#>
function ConvertFrom-PPK {
[CmdletBinding()]
param(
    [Parameter(Position=0, ValueFromPipeline)]
    [string[]]$KeyContent,
    [Parameter(ParameterSetName="p")]
    [switch]$AsPrivate,
    [Parameter(ParameterSetName="o")]
    [switch]$AsOpenSSH,
    [Parameter(Position=1)]
    [SecureString]$Password,
    [int]$CodePage = 0
)
    BEGIN {
        $Key = New-Object System.Collections.ArrayList
    }
    PROCESS {
        $Key.AddRange($KeyContent)
    }
    END {
        try {
            [void][GMax.Security.KeyConverter]
        }
        catch {
            Add-Type -Path "$PSScriptRoot\GMPPKConverter.dll"
        }
        try {
            $ppk = New-Object GMax.Security.KeyConverter $CodePage
            $ppk.ImportPPK($key, $password)
            if ($PSCmdlet.ParameterSetName -eq 'p') {
                $ppk.ExportPrivateKey()
            }
            else {
                $ppk.ExportOpenSSH()
            }
        }
        catch {
            throw
        }
    }
}
