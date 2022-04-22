using System.Collections.Generic;
using System.Security;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        internal static SecureString GetPassword(string password) {
            if (password == null)
                return null;
            SecureString result = new SecureString();
            foreach (char c in password)
            {
                result.AppendChar(c);
            }
            return result;
        }

        public static IEnumerable<object[]> Data_RSA => new List<object[]>
        {
            new object[] { ppk_RSA2, null },
            new object[] { ppk_RSA2, "" },
            new object[] { ppk_RSA2, "test" },
            new object[] { ppk_RSA2, "тест" },
            new object[] { ppk_RSA2_test, "test" },
            new object[] { ppk_RSA2_тест, "тест" },
            new object[] { ppk_RSA3, null },
            new object[] { ppk_RSA3, "" },
            new object[] { ppk_RSA3, "test" },
            new object[] { ppk_RSA3, "тест" },
            new object[] { ppk_RSA3_test, "test" },
            new object[] { ppk_RSA3_тест, "тест" },
        };

        public static IEnumerable<object[]> Data_DSA => new List<object[]>
        {
            new object[] { ppk_DSA2, null },
            new object[] { ppk_DSA2, "" },
            new object[] { ppk_DSA2, "test" },
            new object[] { ppk_DSA2, "тест" },
            new object[] { ppk_DSA2_test, "test" },
            new object[] { ppk_DSA2_тест, "тест" },
            new object[] { ppk_DSA3, null },
            new object[] { ppk_DSA3, "" },
            new object[] { ppk_DSA3, "test" },
            new object[] { ppk_DSA3, "тест" },
            new object[] { ppk_DSA3_test, "test" },
            new object[] { ppk_DSA3_тест, "тест" },
        };

        public static IEnumerable<object[]> Data_ECDSA => new List<object[]>
        {
            new object[] { ppk_ECDSA2, null },
            new object[] { ppk_ECDSA2, "" },
            new object[] { ppk_ECDSA2, "test" },
            new object[] { ppk_ECDSA2, "тест" },
            new object[] { ppk_ECDSA2_test, "test" },
            new object[] { ppk_ECDSA2_тест, "тест" },
            new object[] { ppk_ECDSA3, null },
            new object[] { ppk_ECDSA3, "" },
            new object[] { ppk_ECDSA3, "test" },
            new object[] { ppk_ECDSA3, "тест" },
            new object[] { ppk_ECDSA3_test, "test" },
            new object[] { ppk_ECDSA3_тест, "тест" },
        };
        public static IEnumerable<object[]> Data_ECDSA_2 => new List<object[]>
        {
            new object[] { ppk_ECDSA2_2, null },
            new object[] { ppk_ECDSA3_2, null },
        };
        public static IEnumerable<object[]> Data_ECDSA_3 => new List<object[]>
        {
            new object[] { ppk_ECDSA2_3, null },
            new object[] { ppk_ECDSA3_3, null },
        };

        public static IEnumerable<object[]> Data_EDDSA => new List<object[]>
        {
            new object[] { ppk_EDDSA2, null },
            new object[] { ppk_EDDSA2, "" },
            new object[] { ppk_EDDSA2, "test" },
            new object[] { ppk_EDDSA2, "тест" },
            new object[] { ppk_EDDSA2_test, "test" },
            new object[] { ppk_EDDSA2_тест, "тест" },
            new object[] { ppk_EDDSA3, null },
            new object[] { ppk_EDDSA3, "" },
            new object[] { ppk_EDDSA3, "test" },
            new object[] { ppk_EDDSA3, "тест" },
            new object[] { ppk_EDDSA3_test, "test" },
            new object[] { ppk_EDDSA3_тест, "тест" },
        };
        public static IEnumerable<object[]> Data_EDDSA_2 => new List<object[]>
        {
            new object[] { ppk_EDDSA2_2, null },
            new object[] { ppk_EDDSA3_2, null },
        };
    }

}
