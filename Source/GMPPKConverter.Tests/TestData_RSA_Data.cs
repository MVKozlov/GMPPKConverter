using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        public static IEnumerable<object[]> RSA_Data_OpenSSH => new List<object[]>
        {
            new object[] {
                RSA_1024_PPK2_no_pass,
                "",
                RSA_1024_OpenSSH_rng_no_pass,
                RSA_1024_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK3_no_pass,
                "",
                RSA_1024_OpenSSH_rng_no_pass,
                RSA_1024_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK2_test_pass,
                "test",
                RSA_1024_OpenSSH_rng_no_pass,
                RSA_1024_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK3_test_pass,
                "test",
                RSA_1024_OpenSSH_rng_no_pass,
                RSA_1024_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK2_тест_pass,
                "тест",
                RSA_1024_OpenSSH_rng_no_pass,
                RSA_1024_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK3_тест_pass,
                "тест",
                RSA_1024_OpenSSH_rng_no_pass,
                RSA_1024_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_2048_PPK2_no_pass,
                "",
                RSA_2048_OpenSSH_rng_no_pass,
                RSA_2048_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_2048_PPK3_no_pass,
                "",
                RSA_2048_OpenSSH_rng_no_pass,
                RSA_2048_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_4096_PPK2_no_pass,
                "",
                RSA_4096_OpenSSH_rng_no_pass,
                RSA_4096_OpenSSH_result_no_pass,
            },

            new object[] {
                RSA_4096_PPK3_no_pass,
                "",
                RSA_4096_OpenSSH_rng_no_pass,
                RSA_4096_OpenSSH_result_no_pass,
            },

        };

        public static IEnumerable<object[]> RSA_Data_PEM => new List<object[]>
        {
            new object[] {
                RSA_1024_PPK2_no_pass,
                "",
                RSA_1024_PEM_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK3_no_pass,
                "",
                RSA_1024_PEM_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK2_test_pass,
                "test",
                RSA_1024_PEM_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK3_test_pass,
                "test",
                RSA_1024_PEM_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK2_тест_pass,
                "тест",
                RSA_1024_PEM_result_no_pass,
            },

            new object[] {
                RSA_1024_PPK3_тест_pass,
                "тест",
                RSA_1024_PEM_result_no_pass,
            },

            new object[] {
                RSA_2048_PPK2_no_pass,
                "",
                RSA_2048_PEM_result_no_pass,
            },

            new object[] {
                RSA_2048_PPK3_no_pass,
                "",
                RSA_2048_PEM_result_no_pass,
            },

            new object[] {
                RSA_4096_PPK2_no_pass,
                "",
                RSA_4096_PEM_result_no_pass,
            },

            new object[] {
                RSA_4096_PPK3_no_pass,
                "",
                RSA_4096_PEM_result_no_pass,
            },

        };
    }
}
