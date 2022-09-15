<#
    .SYNOPSIS
        Convert PPK key format to OpenSSH key format or Private(PEM) key format
    .DESCRIPTION
        Convert PPK key format to OpenSSH key format or Private(PEM) key format
        Converted key can be used with, for example, Posh-SSH module as -KeyString parameter value
    .PARAMETER KeyContent
        PPK key file content
    .PARAMETER AsPEM
        Output key in PEM(private) key format
    .PARAMETER AsOpenSSH
        Output key in OpenSSH key format
    .PARAMETER Password
        PPK Key Password
            Note. Non-ASCII passwords does not work under linux
    .PARAMETER OutPassword
        PEM/OpenSSH Key Password
        if not set, uses Password
            Note. Non-ASCII passwords does not work under linux
    .PARAMETER CodePage
        PPK Key content codepage, 0 - use current console codepage
            Note. This parameter is required on Linux because the modern Linux code page is utf-8 by default.
            but Putty saves the key file under windows with non-utf codepage, like 1251
    .PARAMETER Unprotected
        Out UNPROTECTED key
    .OUTPUTS
        Private key converted to PEM/OpenSSH
    .EXAMPLE
        # Read key from file and use it with New-SSHSession

        # ppk password from user input
        $cred = Get-Credential

        # Read key from file and convert it to OpenSSH format
        $KeyString = Get-Content D:\Putty.ppk | ConvertFrom-PPK -AsPEM -Password $cred.Password

        # Use converted key for opening SSH Session
        New-SSHSession -ComputerName my-server -Credentials $cred -KeyString $KeyString
    .EXAMPLE
        # Read key from file with selected encoding and convert in to OpenSSH format

        # default windows cyrillic encoding
        $encoding = [Text.Encoding]::getEncoding(1251)

        $c = Get-Credential xxx
        $content = Get-Content /home/username/test.ppk -Encoding $encoding
        ConvertFrom-PPK -AsOpenSSH -Password $c.Password -KeyContent $content -CodePage $encoding.CodePage
    .EXAMPLE
        # Read key from file and convert in to PEM format thru pipeline with different password

        $c = Get-Credential xxx
        $out_c = Get-Credential out
        Get-Content /home/username/test.ppk |
            ConvertFrom-PPK -AsPEM -Password $c.Password -OutPassword $out_c.Password
    .EXAMPLE
        # Read key from string and convert in to PEM format thru pipeline with selected encoding

        $c = Get-Credential xxx

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
        " -split "\n" |
            ConvertFrom-PPK -AsPEM -Password $c.Password -CodePage 1251
#>
function ConvertFrom-PPK {
[CmdletBinding()]
param(
    [Parameter(Position=0, ValueFromPipeline)]
    [string[]]$KeyContent,
    [Parameter(ParameterSetName="pem")]
    [Alias('AsPrivate')]
    [switch]$AsPEM,
    [Parameter(ParameterSetName="openssh")]
    [switch]$AsOpenSSH,
    [Parameter(Position=1)]
    [SecureString]$Password,
    [SecureString]$OutPassword = $null,
    [bool]$Unprotected = $false,
    [Parameter()]
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
            Write-Verbose "Use CodePage $CodePage"
            $ppk = New-Object GMax.Security.KeyConverter $CodePage
            $ppk.ImportPPK($key, $Password)
            if (-not $Unprotected -and -not $OutPassword) {
                Write-Verbose "Use Password as Output Password"
                $OutPassword = $Password
            }
            elseif ($Unprotected) {
                Write-Warning "Output key is UNPROTECTED"
            }
            if ($PSCmdlet.ParameterSetName -in 'pem', "pem_unprot") {
                Write-Verbose "Export private key in PEM format"
                $ppk.ExportPrivateKey($OutPassword)
            }
            else {
                Write-Verbose "Export private key in OpenSSH format"
                $ppk.ExportOpenSSH($OutPassword)
            }
        }
        catch {
            throw
        }
    }
}
