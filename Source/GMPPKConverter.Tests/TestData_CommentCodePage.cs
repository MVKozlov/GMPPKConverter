using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        internal static string ppk_ECDSA_test_comment_2 = @"
PuTTY-User-Key-File-2: ecdsa-sha2-nistp384
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
";

        internal static string ppk_ECDSA_test_comment_3 = @"
PuTTY-User-Key-File-3: ecdsa-sha2-nistp384
Encryption: aes256-cbc
Comment: test тест
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBGxV9kTEQnAU
HV1Xvyz6VpGp5uDlcHEYxyz+FsWgEASLKrGTJtfWPLNUUR6wiJV0e1AbO6G3fUxN
e/SKTi2LBrSu5bxbwFV5BLJH/JU9ce/q29rwQ25w9d0BWKeAA6FAhA==
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: ba644a09c2d18aa92b01ea346e241330
Private-Lines: 2
myiXXPIsOnFdMy/tY1z/k03/HghCOBuw1yk3+K5EPu3R+TS+ntNNJ91F6A27dvOF
ArvIcM6fJlptV5LCe0ZCeA==
Private-MAC: 1dcf7ec83fac40ee98419bb7aa015b633d003fd3deff46c4815e04931505db35
";

        internal static string result_ECDSA_test_comment = @"
-----BEGIN EC PRIVATE KEY-----
MIGlAgEBBDEAm+LU21am+LIJkmHNUvaqxlaseMs0p30lrYc4TPzoA+SWtqLUdtl/
6/yBTHevSoRtoAcGBSuBBAAioWQDYgAEbFX2RMRCcBQdXVe/LPpWkanm4OVwcRjH
LP4WxaAQBIsqsZMm19Y8s1RRHrCIlXR7UBs7obd9TE179IpOLYsGtK7lvFvAVXkE
skf8lT1x7+rb2vBDbnD13QFYp4ADoUCE
-----END EC PRIVATE KEY-----
";
    }
}
