using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        public static IEnumerable<object[]> EDDSA_Data_OpenSSH => new List<object[]>
        {
            new object[] {
                EDDSA_25519_PPK2_no_pass,
                "",
                EDDSA_25519_OpenSSH_rng_no_pass,
                EDDSA_25519_OpenSSH_result_no_pass,
            },

            new object[] {
                EDDSA_25519_PPK3_no_pass,
                "",
                EDDSA_25519_OpenSSH_rng_no_pass,
                EDDSA_25519_OpenSSH_result_no_pass,
            },

            new object[] {
                EDDSA_25519_PPK2_test_pass,
                "test",
                EDDSA_25519_OpenSSH_rng_no_pass,
                EDDSA_25519_OpenSSH_result_no_pass,
            },

            new object[] {
                EDDSA_25519_PPK3_test_pass,
                "test",
                EDDSA_25519_OpenSSH_rng_no_pass,
                EDDSA_25519_OpenSSH_result_no_pass,
            },

            new object[] {
                EDDSA_25519_PPK2_тест_pass,
                "тест",
                EDDSA_25519_OpenSSH_rng_no_pass,
                EDDSA_25519_OpenSSH_result_no_pass,
            },

            new object[] {
                EDDSA_25519_PPK3_тест_pass,
                "тест",
                EDDSA_25519_OpenSSH_rng_no_pass,
                EDDSA_25519_OpenSSH_result_no_pass,
            },

            new object[] {
                EDDSA_448_PPK2_no_pass,
                "",
                EDDSA_448_OpenSSH_rng_no_pass,
                EDDSA_448_OpenSSH_result_no_pass,
            },

            new object[] {
                EDDSA_448_PPK3_no_pass,
                "",
                EDDSA_448_OpenSSH_rng_no_pass,
                EDDSA_448_OpenSSH_result_no_pass,
            },

        };
    }
}
