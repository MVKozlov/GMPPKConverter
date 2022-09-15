using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        public static IEnumerable<object[]> ECDSA_Data_OpenSSH => new List<object[]>
        {
            new object[] {
                ECDSA_256_PPK2_no_pass,
                "",
                ECDSA_256_OpenSSH_rng_no_pass,
                ECDSA_256_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK3_no_pass,
                "",
                ECDSA_256_OpenSSH_rng_no_pass,
                ECDSA_256_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK2_test_pass,
                "test",
                ECDSA_256_OpenSSH_rng_no_pass,
                ECDSA_256_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK3_test_pass,
                "test",
                ECDSA_256_OpenSSH_rng_no_pass,
                ECDSA_256_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK2_тест_pass,
                "тест",
                ECDSA_256_OpenSSH_rng_no_pass,
                ECDSA_256_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK3_тест_pass,
                "тест",
                ECDSA_256_OpenSSH_rng_no_pass,
                ECDSA_256_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_384_PPK2_no_pass,
                "",
                ECDSA_384_OpenSSH_rng_no_pass,
                ECDSA_384_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_384_PPK3_no_pass,
                "",
                ECDSA_384_OpenSSH_rng_no_pass,
                ECDSA_384_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_521_PPK2_no_pass,
                "",
                ECDSA_521_OpenSSH_rng_no_pass,
                ECDSA_521_OpenSSH_result_no_pass,
            },

            new object[] {
                ECDSA_521_PPK3_no_pass,
                "",
                ECDSA_521_OpenSSH_rng_no_pass,
                ECDSA_521_OpenSSH_result_no_pass,
            },

        };

        public static IEnumerable<object[]> ECDSA_Data_PEM => new List<object[]>
        {
            new object[] {
                ECDSA_256_PPK2_no_pass,
                "",
                ECDSA_256_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK3_no_pass,
                "",
                ECDSA_256_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK2_test_pass,
                "test",
                ECDSA_256_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK3_test_pass,
                "test",
                ECDSA_256_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK2_тест_pass,
                "тест",
                ECDSA_256_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_256_PPK3_тест_pass,
                "тест",
                ECDSA_256_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_384_PPK2_no_pass,
                "",
                ECDSA_384_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_384_PPK3_no_pass,
                "",
                ECDSA_384_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_521_PPK2_no_pass,
                "",
                ECDSA_521_PEM_result_no_pass,
            },

            new object[] {
                ECDSA_521_PPK3_no_pass,
                "",
                ECDSA_521_PEM_result_no_pass,
            },

        };


    }
}
