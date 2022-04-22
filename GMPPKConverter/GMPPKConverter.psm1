function ConvertFrom-PPK {
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position=0, ValueFromPipeline)]
    [string[]]$KeyContent,
    [Parameter(ParameterSetName="p")]
    [switch]$AsPrivate,
    [Parameter(ParameterSetName="o")]
    [switch]$AsOpenSSH,
    [Parameter(Position=1)]
    [SecureString]$Password
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
            $ppk = New-Object GMax.Security.KeyConverter
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
