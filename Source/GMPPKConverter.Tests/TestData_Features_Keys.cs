using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {

        internal static byte[][] ECDSA_256_OpenSSH_rng_test_pass = new byte[][]
        {
            new byte[16] { 0xC7, 0xC0, 0x2B, 0x4B, 0xB0, 0xD7, 0x11, 0x2D, 0x68, 0x27, 0x0D, 0xD5, 0xF3, 0x5D, 0xC7 , 0x80 },
            new byte[4] { 0x11, 0x41, 0x29, 0xF1 },
        };

        internal static string ECDSA_256_OpenSSH_result_test_pass = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDH
wCtLsNcRLWgnDdXzXceAAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAy
NTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+Mh2nvknQKPzfDEGvDfnX1uThUXLJ
4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgRbowGnOtPEnwAAACwX6Saw+MfWznT
NXt8zsYucYpFsB+rI5ria2/dO/F/qxRI/uurXUWlAWI+P2K830C9+m4N/DJ92j1r
56+2T6Gv6e7QZiZy1lgvquX29g+aPv78MJaplBVD3DLXsnbVT7GIIf0Y6UINGByK
UzPBJcsz7hhtyiZC+nX2ER2QeDpz/7wMp7Tf4A53Rl2UxsKFIOA5rZsXFtOWNLHl
ox1VzcQ7/jHQzXW63gyYh9s1NgoT0so=
-----END OPENSSH PRIVATE KEY-----
";


        internal static byte[][] ECDSA_256_PEM_rng_test_pass = new byte[][]
        {
            new byte[16] { 0xC4, 0xC0, 0x4C, 0xE4, 0x2D, 0x30, 0x3E, 0x61, 0x28, 0x33, 0xBF, 0x53, 0xCA, 0x42, 0x99, 0x5F },
        };

        internal static string ECDSA_256_PEM_result_test_pass = @"
-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,C4C04CE42D303E612833BF53CA42995F

KorKE4Yc1CSs3YDfzHKEluebU4kBsTqFpoOwon/ftO9uxDK1Ab0ckX6Gjax/JoIR
0Vdx3GSwFmBRut+QXP3QCokA778gyXgGeSQytRBCHVS8VFUbBbZZFG0nbsHR2n/6
KFN8zwQ/ZlzEyAOavkCINaIHDWXt+6mKpqC5Oyz/ox8=
-----END EC PRIVATE KEY-----
";

        internal const string ECDSA_256_PPK2_no_pass_comment = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: none
Comment: test тест
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Private-Lines: 1
AAAAIQD/Dmo3P7H/k8lThvBm3Z7qSUBeIPIk6+TvDLjzIKDMvQ==
Private-MAC: dca0b59823ca18dd9f1215f3dbf9c69ea00779df
";

        internal const string ECDSA_256_PPK3_no_pass_comment = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
Encryption: none
Comment: test тест
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Private-Lines: 1
AAAAIQD/Dmo3P7H/k8lThvBm3Z7qSUBeIPIk6+TvDLjzIKDMvQ==
Private-MAC: 0889221fe6fde85806f2a387ad690a3e096182855dc08419c869026f249e3926
";

        internal static byte[][] ECDSA_256_OpenSSH_rng_no_pass_comment = new byte[][]
        {
            new byte[4] { 0x78, 0x93, 0x5C, 0x8D },
        };

        internal static string ECDSA_256_OpenSSH_result_no_pass_comment = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNl
Y2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQT5Dt7sAiarfjIdp75J
0Cj83wxBrw3519bk4VFyyePm6aqQOhwDogSHB+xbDZRWKLHAV4eJvDrIEW6MBpzr
TxJ8AAAAsHiTXI14k1yNAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy
NTYAAABBBPkO3uwCJqt+Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH
7FsNlFYoscBXh4m8OsgRbowGnOtPEnwAAAAhAP8Oajc/sf+TyVOG8GbdnupJQF4g
8iTr5O8MuPMgoMy9AAAACXRlc3Qg8uXx8gECAwQFBgcICQoLDA0O
-----END OPENSSH PRIVATE KEY-----
";

    }
}
