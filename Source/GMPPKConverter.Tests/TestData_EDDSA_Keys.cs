using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        internal static string EDDSA_25519_PPK2_no_pass = @"
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: eddsa-key-20220915
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIAP8SDjmmx+b9rIFB9qBeKsYHyEGjB9GfiIxuR3m
L5io
Private-Lines: 1
AAAAIFg/uugb9aRFLAAfarKWIaK3crG2vaQdNn/pclwO2WEf
Private-MAC: fbd36c134bdced438cfc6675f2608bf3f1172e48
";

        internal static string EDDSA_25519_PPK3_no_pass = @"
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: eddsa-key-20220915
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIAP8SDjmmx+b9rIFB9qBeKsYHyEGjB9GfiIxuR3m
L5io
Private-Lines: 1
AAAAIFg/uugb9aRFLAAfarKWIaK3crG2vaQdNn/pclwO2WEf
Private-MAC: 6982def8083cab1125d7fa040304fcaab7571648e524b4d242bbfe0b02469ae3
";

        internal static string EDDSA_25519_PPK2_test_pass = @"
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220915
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIAP8SDjmmx+b9rIFB9qBeKsYHyEGjB9GfiIxuR3m
L5io
Private-Lines: 1
YDqj4v2Xo9d/FL9v/HeEwiUCB0FICIfXTh/BKMGZ9QFzyLpyMrM2GGQRkBFAEyET
Private-MAC: 7178c5f0d6310e5ed2f7cbf6a95ac4cf86a597ec
";
        internal static string EDDSA_25519_PPK3_test_pass = @"
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220915
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIAP8SDjmmx+b9rIFB9qBeKsYHyEGjB9GfiIxuR3m
L5io
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 81ef47519c722826575de2cf26d08dc1
Private-Lines: 1
SRjH/6A4IzEnlTXfbOJFc6akon5qbF2JvLPd18JmvTYf+0sOgYZcyW5eEqWB8Qxr
Private-MAC: 5f6d2e3d44d9d0f9c01cde62280d1e3700345e14e8633dc63395ce345d952316
";

        internal static string EDDSA_25519_PPK2_тест_pass = @"
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220915
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIAP8SDjmmx+b9rIFB9qBeKsYHyEGjB9GfiIxuR3m
L5io
Private-Lines: 1
cDSO0+WpNoBnJIWhXryZ74fBXZAlaxe64eXpVlAiGP+ZnkZ69gNRHJOvLLM4FXbX
Private-MAC: c5334d2607db1061e71b4e2151c2fbd77a18bc2b
";

        internal static string EDDSA_25519_PPK3_тест_pass = @"
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220915
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIAP8SDjmmx+b9rIFB9qBeKsYHyEGjB9GfiIxuR3m
L5io
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 3889d3c432b9fe27062ba8e6157d8dfa
Private-Lines: 1
FuwXEMyGV3VT8SAEY+cEOqEZTQ8YFG5yLRj+DuVi1Or/zUEHuOuXjzzDY5V7Q6Px
Private-MAC: 129bc7534c1692b0fcbd5ba43b15d00f404b009324de928a2390eb4cb2f6b54c
";

        internal static byte[][] EDDSA_25519_OpenSSH_rng_no_pass = new byte[][]
        {
            new byte[4] { 0xC5, 0x2E, 0x21, 0x33 },
        };

        internal static string EDDSA_25519_OpenSSH_result_no_pass = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACAD/Eg45psfm/ayBQfagXirGB8hBowfRn4iMbkd5i+YqAAA
AKDFLiEzxS4hMwAAAAtzc2gtZWQyNTUxOQAAACAD/Eg45psfm/ayBQfagXirGB8h
BowfRn4iMbkd5i+YqAAAAEBYP7roG/WkRSwAH2qyliGit3Kxtr2kHTZ/6XJcDtlh
HwP8SDjmmx+b9rIFB9qBeKsYHyEGjB9GfiIxuR3mL5ioAAAAEmVkZHNhLWtleS0y
MDIyMDkxNQECAwQFBgcICQoL
-----END OPENSSH PRIVATE KEY-----
";

        internal static string EDDSA_448_PPK2_no_pass = @"
PuTTY-User-Key-File-2: ssh-ed448
Encryption: none
Comment: eddsa-key-20220915
Public-Lines: 2
AAAACXNzaC1lZDQ0OAAAADnxtytiCv6KDxLGXi/rfqar4KpBkdRx2DenxMpIV5pH
mhhCjZzIKURrGXi60RnXqA/Mg4QBgqKAwgA=
Private-Lines: 2
AAAAOQNzs4vB1/PZdkeRuj9W2iMR4QU384D25IyXxIp1iMPCQwT8ilhVt/XiKCpI
PprVJrj24o9e9+IIAA==
Private-MAC: 00b8619f97731e92db453a8984f7bb40ced9da87
";

        internal static string EDDSA_448_PPK3_no_pass = @"
PuTTY-User-Key-File-3: ssh-ed448
Encryption: none
Comment: eddsa-key-20220915
Public-Lines: 2
AAAACXNzaC1lZDQ0OAAAADnxtytiCv6KDxLGXi/rfqar4KpBkdRx2DenxMpIV5pH
mhhCjZzIKURrGXi60RnXqA/Mg4QBgqKAwgA=
Private-Lines: 2
AAAAOQNzs4vB1/PZdkeRuj9W2iMR4QU384D25IyXxIp1iMPCQwT8ilhVt/XiKCpI
PprVJrj24o9e9+IIAA==
Private-MAC: 5f6b39bf6735246906db52ecc60827c1fb87242d204a4b5f4e4aeef887bf4cd5
";

        internal static byte[][] EDDSA_448_OpenSSH_rng_no_pass = new byte[][]
        {
            new byte[4] { 0x59, 0x8A, 0x73, 0xF7 },
        };

        internal static string EDDSA_448_OpenSSH_result_no_pass = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAAAlz
c2gtZWQ0NDgAAAA58bcrYgr+ig8Sxl4v636mq+CqQZHUcdg3p8TKSFeaR5oYQo2c
yClEaxl4utEZ16gPzIOEAYKigMIAAAAA4FmKc/dZinP3AAAACXNzaC1lZDQ0OAAA
ADnxtytiCv6KDxLGXi/rfqar4KpBkdRx2DenxMpIV5pHmhhCjZzIKURrGXi60RnX
qA/Mg4QBgqKAwgAAAAByA3Ozi8HX89l2R5G6P1baIxHhBTfzgPbkjJfEinWIw8JD
BPyKWFW39eIoKkg+mtUmuPbij1734ggA8bcrYgr+ig8Sxl4v636mq+CqQZHUcdg3
p8TKSFeaR5oYQo2cyClEaxl4utEZ16gPzIOEAYKigMIAAAAAEmVkZHNhLWtleS0y
MDIyMDkxNQEC
-----END OPENSSH PRIVATE KEY-----
";
    }
}
