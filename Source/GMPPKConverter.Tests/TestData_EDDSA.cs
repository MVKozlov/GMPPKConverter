using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        internal static string ppk_EDDSA2 = @"
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: eddsa-key-20220422
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIJ95m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1K
Coig
Private-Lines: 1
AAAAIOg0z7HntPXFH0iDi8any6GjYhdgzIlLhQRppLW1m90j
Private-MAC: 315431b04ad0cbad6603e2f48ee6f7c6d453fe67
";

        internal static string ppk_EDDSA3 = @"
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: eddsa-key-20220422
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIJ95m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1K
Coig
Private-Lines: 1
AAAAIOg0z7HntPXFH0iDi8any6GjYhdgzIlLhQRppLW1m90j
Private-MAC: 68b9d38fd42bef6ddc4640ecad04380559863a4d8bd7739e918a4ea93e2b72c0
";
        internal static string ppk_EDDSA2_test = @"
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220422
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIJ95m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1K
Coig
Private-Lines: 1
VPjGHzBRbY46GhBG57jY8v6jg/vNmQPFK+AQFUKzEziQdbCTONxFKq1My5lVy0x0
Private-MAC: e093e77e16919fea12f417f3785b0862af63dc9f
";
        internal static string ppk_EDDSA2_тест = @"
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220422
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIJ95m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1K
Coig
Private-Lines: 1
hn0jkCKOTTswubflG7H3A+Bl25TMCUHfWimXnNSAn6Lltg/c4GW8KZ2oe7QvyEnG
Private-MAC: bbaf2b3b2741ee869b461a3dd94ec4ed84f56692
";
        internal static string ppk_EDDSA3_test = @"
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220422
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIJ95m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1K
Coig
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: ec2650bac37c97f76219d62de9b20201
Private-Lines: 1
S+Ahe1AXYUMkMIDfS4iuEz4BEzf2K6wJjA1CcdU5Z8L3GWpmHS1KJpQgFT1Exvko
Private-MAC: 7a8fc025802136b85149b9dcf793d026d07ae3ef66c6f9b395740a0305aa508b
";
        internal static string ppk_EDDSA3_тест = @"
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: eddsa-key-20220422
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIJ95m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1K
Coig
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 21
Argon2-Parallelism: 1
Argon2-Salt: 75605ff7e52eac0b1c0acaf3ea5b9ddf
Private-Lines: 1
pTi23kcTiMBIH5oxPWRN/KHj+rRdRPIbxyH7R1ey9oU6p7KcSPfJK82Dx0RxFgmq
Private-MAC: e5c43b4c4d66d507bc384e3f4bff1003438b29b09802367657b7c542626aeeba
";

        // Patched to checkint
        internal static string result_EDDSA_openssh = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACCfeZuk/wegfkdR1NcA+UOEVgdoBd1U3+efjHGNSgqIoAAA
AKDvAAAA7wAAAAAAAAtzc2gtZWQyNTUxOQAAACCfeZuk/wegfkdR1NcA+UOEVgdo
Bd1U3+efjHGNSgqIoAAAAEDoNM+x57T1xR9Ig4vGp8uho2IXYMyJS4UEaaS1tZvd
I595m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1KCoigAAAAEmVkZHNhLWtleS0y
MDIyMDQyMgECAwQFBgcICQoL
-----END OPENSSH PRIVATE KEY-----
";

        internal static string result_EDDSA_private = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACCfeZuk/wegfkdR1NcA+UOEVgdoBd1U3+efjHGNSgqIoAAA
AKDvAAAA7wAAAAAAAAtzc2gtZWQyNTUxOQAAACCfeZuk/wegfkdR1NcA+UOEVgdo
Bd1U3+efjHGNSgqIoAAAAEDoNM+x57T1xR9Ig4vGp8uho2IXYMyJS4UEaaS1tZvd
I595m6T/B6B+R1HU1wD5Q4RWB2gF3VTf55+McY1KCoigAAAAEmVkZHNhLWtleS0y
MDIyMDQyMgECAwQFBgcICQoL
-----END OPENSSH PRIVATE KEY-----
";

        // Seems on 04.2022 openssh still do not support it

        internal static string ppk_EDDSA2_2 = @"
PuTTY-User-Key-File-2: ssh-ed448
Encryption: none
Comment: eddsa-key-20220422
Public-Lines: 2
AAAACXNzaC1lZDQ0OAAAADkTj4bgSUcOjuf4JKU2Z4sVkoAaewLmhvdTDHg4XOt0
fwRnhMIB59Xsy/z5h1yBbSPe/QocRKilCAA=
Private-Lines: 2
AAAAOU2RiQaWJ/TYhbs/kHwPW+ZVdDmXBGQuLiVIb2cMW9N0l3RQSIc5NSGbodmg
fYotT4YX/429KVMHAA==
Private-MAC: 195932ef1a1ea8a1957c1fa603dba92910de91a5
";

        internal static string ppk_EDDSA3_2 = @"
PuTTY-User-Key-File-3: ssh-ed448
Encryption: none
Comment: eddsa-key-20220422
Public-Lines: 2
AAAACXNzaC1lZDQ0OAAAADkTj4bgSUcOjuf4JKU2Z4sVkoAaewLmhvdTDHg4XOt0
fwRnhMIB59Xsy/z5h1yBbSPe/QocRKilCAA=
Private-Lines: 2
AAAAOU2RiQaWJ/TYhbs/kHwPW+ZVdDmXBGQuLiVIb2cMW9N0l3RQSIc5NSGbodmg
fYotT4YX/429KVMHAA==
Private-MAC: 4bb5fbaa82b2b415712d08b3f29e4ba94690870bd1aa4d392b40e6115e4862a4
";

        internal static string result_EDDSA_openssh_2 = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAAAlz
c2gtZWQ0NDgAAAA5E4+G4ElHDo7n+CSlNmeLFZKAGnsC5ob3Uwx4OFzrdH8EZ4TC
AefV7Mv8+YdcgW0j3v0KHESopQgAAAAA4O8AAADvAAAAAAAACXNzaC1lZDQ0OAAA
ADkTj4bgSUcOjuf4JKU2Z4sVkoAaewLmhvdTDHg4XOt0fwRnhMIB59Xsy/z5h1yB
bSPe/QocRKilCAAAAAByTZGJBpYn9NiFuz+QfA9b5lV0OZcEZC4uJUhvZwxb03SX
dFBIhzk1IZuh2aB9ii1Phhf/jb0pUwcAE4+G4ElHDo7n+CSlNmeLFZKAGnsC5ob3
Uwx4OFzrdH8EZ4TCAefV7Mv8+YdcgW0j3v0KHESopQgAAAAAEmVkZHNhLWtleS0y
MDIyMDQyMgEC
-----END OPENSSH PRIVATE KEY-----
";

        internal static string result_EDDSA_private_2 = @"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAASgAAAAlz
c2gtZWQ0NDgAAAA5E4+G4ElHDo7n+CSlNmeLFZKAGnsC5ob3Uwx4OFzrdH8EZ4TC
AefV7Mv8+YdcgW0j3v0KHESopQgAAAAA4O8AAADvAAAAAAAACXNzaC1lZDQ0OAAA
ADkTj4bgSUcOjuf4JKU2Z4sVkoAaewLmhvdTDHg4XOt0fwRnhMIB59Xsy/z5h1yB
bSPe/QocRKilCAAAAAByTZGJBpYn9NiFuz+QfA9b5lV0OZcEZC4uJUhvZwxb03SX
dFBIhzk1IZuh2aB9ii1Phhf/jb0pUwcAE4+G4ElHDo7n+CSlNmeLFZKAGnsC5ob3
Uwx4OFzrdH8EZ4TCAefV7Mv8+YdcgW0j3v0KHESopQgAAAAAEmVkZHNhLWtleS0y
MDIyMDQyMgEC
-----END OPENSSH PRIVATE KEY-----
";
    }
}
