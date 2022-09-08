using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        internal static string ppk_ECDSA2 = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: none
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvQs0T8ou1p
Tth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsAQeLJWueib27IWlV1BvPvk1nX
EKK6EVDOFJk=
Private-Lines: 1
AAAAIQC+lNJcq6aurpVZ9M3QecPMCq/DE4872gWjCg7iDiuuag==
Private-MAC: 98864eea1c55f2a28efa7a116f9f243892f3e4dd
";

        internal static string ppk_ECDSA3 = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
Encryption: none
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvQs0T8ou1p
Tth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsAQeLJWueib27IWlV1BvPvk1nX
EKK6EVDOFJk=
Private-Lines: 1
AAAAIQC+lNJcq6aurpVZ9M3QecPMCq/DE4872gWjCg7iDiuuag==
Private-MAC: d19a6a9188ca78d26909512c57ef59262f2692629f2da304b270deaccdb94983
";
        internal static string ppk_ECDSA2_test = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvQs0T8ou1p
Tth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsAQeLJWueib27IWlV1BvPvk1nX
EKK6EVDOFJk=
Private-Lines: 1
HvpWFriPH7qpwPehc7z32FSEG7ag9k1sjCMd6p4qdomSb2WN1bdzOC54XJr7M6TO
Private-MAC: e46f95f1d96fc94c030a7573bec23c3262a40766
";
        internal static string ppk_ECDSA2_тест = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvQs0T8ou1p
Tth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsAQeLJWueib27IWlV1BvPvk1nX
EKK6EVDOFJk=
Private-Lines: 1
UxHZqXy9yOBQIs6V5A+Z68q6Ktyf1qqyrhgyrUPLpC2dUBoJStscrqAmvNtTpeQ9
Private-MAC: 43dea461683fc10bac5620683b1a81c22b4b1dee
";
        internal static string ppk_ECDSA3_test = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvQs0T8ou1p
Tth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsAQeLJWueib27IWlV1BvPvk1nX
EKK6EVDOFJk=
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: cb7917ee92f02a5ae6134228de59ce1f
Private-Lines: 1
rlwFiFdikxIpRKH5a14454YjYhWutYaesT/qFgYMkoEAAYPG/MCnsUN5gbKltuXF
Private-MAC: fa5662bc872b4a0c71affe04a656567835e48643cd31693ffc474bcf27d61c93
";
        internal static string ppk_ECDSA3_тест = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp256
Encryption: aes256-cbc
Comment: ecdsa-key-20220422
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFvQs0T8ou1p
Tth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsAQeLJWueib27IWlV1BvPvk1nX
EKK6EVDOFJk=
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 1447ca0bc38ae65fac065ed6d3fffc3e
Private-Lines: 1
YaKMeute+IEsM5lioh5kx39m3+0FWvp96UtzF77LlFV5lwzcW+MLsEM1z7ry9iOT
Private-MAC: d2cd077b5c0245d99423455d56928b2912ff67b5c4605af29bf2933f1df0f22e
";

        // Patched to checkint
        internal static string result_ECDSA_openssh = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNl
Y2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRb0LNE/KLtaU7YeIji
BtEsJpeB1tW3h2MOP8Wyxs0AsucdDn17AEHiyVrnom9uyFpVdQbz75NZ1xCiuhFQ
zhSZAAAAsO8AAADvAAAAAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy
NTYAAABBBFvQs0T8ou1pTth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsAQeLJ
Wueib27IWlV1BvPvk1nXEKK6EVDOFJkAAAAhAL6U0lyrpq6ulVn0zdB5w8wKr8MT
jzvaBaMKDuIOK65qAAAAEmVjZHNhLWtleS0yMDIyMDQyMgECAwQF
-----END OPENSSH PRIVATE KEY-----
";

        internal static string result_ECDSA_private = @"
-----BEGIN EC PRIVATE KEY-----
MHgCAQEEIQC+lNJcq6aurpVZ9M3QecPMCq/DE4872gWjCg7iDiuuaqAKBggqhkjO
PQMBB6FEA0IABFvQs0T8ou1pTth4iOIG0Swml4HW1beHYw4/xbLGzQCy5x0OfXsA
QeLJWueib27IWlV1BvPvk1nXEKK6EVDOFJk=
-----END EC PRIVATE KEY-----
";


        internal static string ppk_ECDSA2_2 = @"
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

        internal static string ppk_ECDSA3_2 = @"
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

        internal static string result_ECDSA_openssh_2 = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNl
Y2RzYS1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQSexFyhLGu2HAL8Ea8b
38rULV6OsGADGTqHMCln7pgcmATL3UZLtTfhJuVEqi13iB9XXxZCzeE4xIF2BEjD
EFhEhCAhYDHgIvWH7XFh5zlaHosG3Gs2zbuDa/7cgRCw/JUAAADg7wAAAO8AAAAA
AAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAGEEnsRcoSxrthwC
/BGvG9/K1C1ejrBgAxk6hzApZ+6YHJgEy91GS7U34SblRKotd4gfV18WQs3hOMSB
dgRIwxBYRIQgIWAx4CL1h+1xYec5Wh6LBtxrNs27g2v+3IEQsPyVAAAAMQD9uq//
RlCokRvLKWTJJhR5KDv44/ZC2/b3Tkiazz52zL/RJN3TldFxfEbhv41wRtwAAAAS
ZWNkc2Eta2V5LTIwMjIwNDIyAQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";

        internal static string result_ECDSA_private_2 = @"
-----BEGIN EC PRIVATE KEY-----
MIGlAgEBBDEA/bqv/0ZQqJEbyylkySYUeSg7+OP2Qtv2905Ims8+dsy/0STd05XR
cXxG4b+NcEbcoAcGBSuBBAAioWQDYgAEnsRcoSxrthwC/BGvG9/K1C1ejrBgAxk6
hzApZ+6YHJgEy91GS7U34SblRKotd4gfV18WQs3hOMSBdgRIwxBYRIQgIWAx4CL1
h+1xYec5Wh6LBtxrNs27g2v+3IEQsPyV
-----END EC PRIVATE KEY-----
";

        internal static string ppk_ECDSA2_3 = @"
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

        internal static string ppk_ECDSA3_3 = @"
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

    internal static string result_ECDSA_openssh_3 = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNl
Y2RzYS1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQAs0GROzI+ucmSDcQu
F36BAspoKIFuzcVMJxfwE5tr/uucecitjaYHPsUg2syrzuqgfYhPthQHkZmSjsrD
GjUHzhcAvKUOUy6YZb+ahspe+kpC/NLl+IyLji1LtmhvzAjVOLFeJSL2teSm/cNv
mnJexe9MlES24RIRFREdWgObcAELECcAAAEQ7wAAAO8AAAAAAAATZWNkc2Etc2hh
Mi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAIUEALNBkTsyPrnJkg3ELhd+gQLKaCiB
bs3FTCcX8BOba/7rnHnIrY2mBz7FINrMq87qoH2IT7YUB5GZko7Kwxo1B84XALyl
DlMumGW/mobKXvpKQvzS5fiMi44tS7Zob8wI1TixXiUi9rXkpv3Db5pyXsXvTJRE
tuESERURHVoDm3ABCxAnAAAAQgE+vmr/YyN46wDnsmdzlJC6/epm26LezmyYYM+H
XxjiNa79CUgEGBalICEyOma4bwKGc3NJo7diy5QJ67cWwY5MLAAAABJlY2RzYS1r
ZXktMjAyMjA0MjI=
-----END OPENSSH PRIVATE KEY-----
";

        internal static string result_ECDSA_private_3 = @"
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
