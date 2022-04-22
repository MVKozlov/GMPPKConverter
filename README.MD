# Powershell Module: Putty key parser/converter

Putty key converter as _c# class_ can read [putty](https://www.putty.org/) v2/v3 keys and convert it to **UNPROTECTED** keys suitable to use with .NET SSH modules such as [Renci.SshNet](https://github.com/sshnet/SSH.NET/)

Powershell module was written as companion to [Posh-SSH](https://github.com/darkoperator/Posh-SSH) module

As well as _Posh-SSH_ this module is for Windows PowerShell 5.1 or PowerShell 7.x., On Windows Server, version 1709 or older .Net Framework 4.8 or above is required for the proper loading of the module.

## Usage example

``` powershell
$cred = Get-Credential
$KeyString = Get-Content D:\Putty.ppk | ConvertFrom-PPK -AsPrivate -Password $cred.Password
New-SSHSession -ComputerName myserver -Credentials $cred -KeyString $KeyString
```

## Once again, output is **UNENCRYPTED**, so do not write it on disk

### Notes

- [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography) used for ppk v3 decryption used as source in library, it modified to disable hardware acceleration to work without _System.Numerics.Vectors_ which not available to _netstandard2.0_

### TODO

- Back Conversion
- Key Encryption... may be... someday
