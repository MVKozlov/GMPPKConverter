using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GMPPKConverter.Tests
{
    public static partial class TestData
    {
        public static IEnumerable<object[]> ECDSA_Data_OpenSSH_pass => new List<object[]>
        {
            new object[] {
                ECDSA_256_PPK2_no_pass,
                "test",
                ECDSA_256_OpenSSH_rng_test_pass,
                ECDSA_256_OpenSSH_result_test_pass,
            },
        };

        public static IEnumerable<object[]> ECDSA_Data_PEM_pass => new List<object[]>
        {
            new object[] {
                ECDSA_256_PPK2_no_pass,
                "test",
                ECDSA_256_PEM_rng_test_pass,
                ECDSA_256_PEM_result_test_pass,
            },
        };

        
        public static IEnumerable<object[]> ECDSA_Data_OpenSSH_comment => new List<object[]>
        {
            new object[] {
                ECDSA_256_PPK2_no_pass_comment,
                ECDSA_256_OpenSSH_rng_no_pass_comment,
                ECDSA_256_OpenSSH_result_no_pass_comment,
            },

            new object[] {
                ECDSA_256_PPK3_no_pass_comment,
                ECDSA_256_OpenSSH_rng_no_pass_comment,
                ECDSA_256_OpenSSH_result_no_pass_comment,
            },
        };

    }
}
