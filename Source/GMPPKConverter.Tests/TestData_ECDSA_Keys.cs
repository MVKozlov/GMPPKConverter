using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        internal const string ECDSA_256_PPK2_no_pass = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: none
Comment: ecdsa-key-20220908
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Private-Lines: 1
AAAAIQD/Dmo3P7H/k8lThvBm3Z7qSUBeIPIk6+TvDLjzIKDMvQ==
Private-MAC: 2463a3dc8dd598294be49508440b8953f4909fc9
";

        internal const string ECDSA_256_PPK2_test_pass = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220908
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Private-Lines: 1
9B6R+jkyVCAAmNnpcMc5Jd2JTvI/0JXknKWX/cOf59vxK67gh4StRIm7Z0WOlY/e
Private-MAC: 6803e486f548e55207b4164f2e8ed0d5a7d50707
";

        internal const string ECDSA_256_PPK2_тест_pass = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220908
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Private-Lines: 1
2Tb1i4EbOfBU280qace4Iq3M8PpY2Xj4XXJMIz5X6mZEBJyqy0bXQjjaTuig6twm
Private-MAC: 3df06629df15bc4eac8f1f548097add438f1ffd4
";

        internal const string ECDSA_256_PPK3_no_pass = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
Encryption: none
Comment: ecdsa-key-20220908
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Private-Lines: 1
AAAAIQD/Dmo3P7H/k8lThvBm3Z7qSUBeIPIk6+TvDLjzIKDMvQ==
Private-MAC: e7a5eee8486a17072df68e6faf07ca50cc6ebb1967ea2217f615a65954dbcd92
";

        internal const string ECDSA_256_PPK3_test_pass = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220908
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 13
Argon2-Parallelism: 1
Argon2-Salt: ef8971a4d717cdb8a58e684afbdb739e
Private-Lines: 1
cPppmdKcWPG1S12Juqutqx6t853a2PIAAzK694u/00i2jKHfUXOSb3XCVrMxls1b
Private-MAC: a51776581e2abe1d9ff8f2bebd2b27288dc74f4f8082777e466a7d53bc71fc3a
";

        internal const string ECDSA_256_PPK3_тест_pass = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220908
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPkO3uwCJqt+
Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH7FsNlFYoscBXh4m8OsgR
bowGnOtPEnw=
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: a31f0efd3cd56ff442bf23980ef290e7
Private-Lines: 1
D7qaMVEiFwNyDmP3NkYHTvub1xrVY+xPlGq1/pZObJSDDY3mHvu0bna9H1QXenCp
Private-MAC: f5fe0dcf1b662344b714d75a5c4d5671435d240b910668a1b9a6c54458ab38c7
";

        internal static byte[][] ECDSA_256_OpenSSH_rng_no_pass = new byte[][]
        {
            new byte[4] { 0x46, 0xE1, 0x67, 0xCB },
        };
        internal static string ECDSA_256_OpenSSH_result_no_pass = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNl
Y2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQT5Dt7sAiarfjIdp75J
0Cj83wxBrw3519bk4VFyyePm6aqQOhwDogSHB+xbDZRWKLHAV4eJvDrIEW6MBpzr
TxJ8AAAAsEbhZ8tG4WfLAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy
NTYAAABBBPkO3uwCJqt+Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOiBIcH
7FsNlFYoscBXh4m8OsgRbowGnOtPEnwAAAAhAP8Oajc/sf+TyVOG8GbdnupJQF4g
8iTr5O8MuPMgoMy9AAAAEmVjZHNhLWtleS0yMDIyMDkwOAECAwQF
-----END OPENSSH PRIVATE KEY-----
";

        internal static string ECDSA_256_PEM_result_no_pass = @"
-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQD/Dmo3P7H/k8lThvBm3Z7qSUBeIPIk6+TvDLjzIKDMvaAKBggqhkjO
PQMBB6FEA0IABPkO3uwCJqt+Mh2nvknQKPzfDEGvDfnX1uThUXLJ4+bpqpA6HAOi
BIcH7FsNlFYoscBXh4m8OsgRbowGnOtPEnw=
-----END EC PRIVATE KEY-----
";

        internal static string ECDSA_384_PPK2_no_pass = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp384
Encryption: none
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJ7EXKEsa7Yc
AvwRrxvfytQtXo6wYAMZOocwKWfumByYBMvdRku1N+Em5USqLXeIH1dfFkLN4TjE
gXYESMMQWESEICFgMeAi9YftcWHnOVoeiwbcazbNu4Nr/tyBELD8lQ==
Private-Lines: 2
AAAAMQD9uq//RlCokRvLKWTJJhR5KDv44/ZC2/b3Tkiazz52zL/RJN3TldFxfEbh
v41wRtw=
Private-MAC: ca730c4ec15ceef608fc397c7a4fc0794a0b325e
";

        internal static string ECDSA_384_PPK3_no_pass = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp384
Encryption: none
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBJ7EXKEsa7Yc
AvwRrxvfytQtXo6wYAMZOocwKWfumByYBMvdRku1N+Em5USqLXeIH1dfFkLN4TjE
gXYESMMQWESEICFgMeAi9YftcWHnOVoeiwbcazbNu4Nr/tyBELD8lQ==
Private-Lines: 2
AAAAMQD9uq//RlCokRvLKWTJJhR5KDv44/ZC2/b3Tkiazz52zL/RJN3TldFxfEbh
v41wRtw=
Private-MAC: 4396170e144c512a79375149da93174f3a96b2f0212fd3c36a72f569025fe4d6
";

        internal static byte[][] ECDSA_384_OpenSSH_rng_no_pass = new byte[][]
{
            new byte[4] { 0x43, 0x54, 0x42, 0xAA },
};
        internal static string ECDSA_384_OpenSSH_result_no_pass = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNl
Y2RzYS1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSexFyhLGu2HAL8Ea8b
38rULV6OsGADGTqHMCln7pgcmATL3UZLtTfhJuVEqi13iB9XXxZCzeE4xIF2BEjD
EFhEhCAhYDHgIvWH7XFh5zlaHosG3Gs2zbuDa/7cgRCw/JUAAADgQ1RCqkNUQqoA
AAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAGEEnsRcoSxrthwC
/BGvG9/K1C1ejrBgAxk6hzApZ+6YHJgEy91GS7U34SblRKotd4gfV18WQs3hOMSB
dgRIwxBYRIQgIWAx4CL1h+1xYec5Wh6LBtxrNs27g2v+3IEQsPyVAAAAMQD9uq//
RlCokRvLKWTJJhR5KDv44/ZC2/b3Tkiazz52zL/RJN3TldFxfEbhv41wRtwAAAAS
ZWNkc2Eta2V5LTIwMjIwNDIyAQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";


        internal static string ECDSA_384_PEM_result_no_pass = @"
-----BEGIN EC PRIVATE KEY-----
MIGlAgEBBDEA/bqv/0ZQqJEbyylkySYUeSg7+OP2Qtv2905Ims8+dsy/0STd05XR
cXxG4b+NcEbcoAcGBSuBBAAioWQDYgAEnsRcoSxrthwC/BGvG9/K1C1ejrBgAxk6
hzApZ+6YHJgEy91GS7U34SblRKotd4gfV18WQs3hOMSBdgRIwxBYRIQgIWAx4CL1
h+1xYec5Wh6LBtxrNs27g2v+3IEQsPyV
-----END EC PRIVATE KEY-----
";

        internal static string ECDSA_521_PPK2_no_pass = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp521
Encryption: none
Comment: ecdsa-key-20220422
Public-Lines: 4
AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACzQZE7Mj65
yZINxC4XfoECymgogW7NxUwnF/ATm2v+65x5yK2Npgc+xSDazKvO6qB9iE+2FAeR
mZKOysMaNQfOFwC8pQ5TLphlv5qGyl76SkL80uX4jIuOLUu2aG/MCNU4sV4lIva1
5Kb9w2+acl7F70yURLbhEhEVER1aA5twAQsQJw==
Private-Lines: 2
AAAAQgE+vmr/YyN46wDnsmdzlJC6/epm26LezmyYYM+HXxjiNa79CUgEGBalICEy
Oma4bwKGc3NJo7diy5QJ67cWwY5MLA==
Private-MAC: 646b0fc2a5e6fe2896ef3e4d289755ec0da0008c
";

        internal static string ECDSA_521_PPK3_no_pass = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp521
Encryption: none
Comment: ecdsa-key-20220422
Public-Lines: 4
AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBACzQZE7Mj65
yZINxC4XfoECymgogW7NxUwnF/ATm2v+65x5yK2Npgc+xSDazKvO6qB9iE+2FAeR
mZKOysMaNQfOFwC8pQ5TLphlv5qGyl76SkL80uX4jIuOLUu2aG/MCNU4sV4lIva1
5Kb9w2+acl7F70yURLbhEhEVER1aA5twAQsQJw==
Private-Lines: 2
AAAAQgE+vmr/YyN46wDnsmdzlJC6/epm26LezmyYYM+HXxjiNa79CUgEGBalICEy
Oma4bwKGc3NJo7diy5QJ67cWwY5MLA==
Private-MAC: b87aa5774961a47d2addd0191a822bbbdd6229e18ba136c87791e7fad19607f7
";

        internal static byte[][] ECDSA_521_OpenSSH_rng_no_pass = new byte[][]
        {
            new byte[4] { 0x30, 0xD2, 0x35, 0xD0 },
        };

        internal static string ECDSA_521_OpenSSH_result_no_pass = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNl
Y2RzYS1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQAs0GROzI+ucmSDcQu
F36BAspoKIFuzcVMJxfwE5tr/uucecitjaYHPsUg2syrzuqgfYhPthQHkZmSjsrD
GjUHzhcAvKUOUy6YZb+ahspe+kpC/NLl+IyLji1LtmhvzAjVOLFeJSL2teSm/cNv
mnJexe9MlES24RIRFREdWgObcAELECcAAAEgMNI10DDSNdAAAAATZWNkc2Etc2hh
Mi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAIUEALNBkTsyPrnJkg3ELhd+gQLKaCiB
bs3FTCcX8BOba/7rnHnIrY2mBz7FINrMq87qoH2IT7YUB5GZko7Kwxo1B84XALyl
DlMumGW/mobKXvpKQvzS5fiMi44tS7Zob8wI1TixXiUi9rXkpv3Db5pyXsXvTJRE
tuESERURHVoDm3ABCxAnAAAAQgE+vmr/YyN46wDnsmdzlJC6/epm26LezmyYYM+H
XxjiNa79CUgEGBalICEyOma4bwKGc3NJo7diy5QJ67cWwY5MLAAAABJlY2RzYS1r
ZXktMjAyMjA0MjIBAgMEBQYHCAkKCwwNDg8Q
-----END OPENSSH PRIVATE KEY-----
";

        internal static string ECDSA_521_PEM_result_no_pass = @"
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBPr5q/2MjeOsA57Jnc5SQuv3qZtui3s5smGDPh18Y4jWu/QlIBBgW
pSAhMjpmuG8ChnNzSaO3YsuUCeu3FsGOTCygBwYFK4EEACOhgYkDgYYABACzQZE7
Mj65yZINxC4XfoECymgogW7NxUwnF/ATm2v+65x5yK2Npgc+xSDazKvO6qB9iE+2
FAeRmZKOysMaNQfOFwC8pQ5TLphlv5qGyl76SkL80uX4jIuOLUu2aG/MCNU4sV4l
Iva15Kb9w2+acl7F70yURLbhEhEVER1aA5twAQsQJw==
-----END EC PRIVATE KEY-----
";

    }
}
