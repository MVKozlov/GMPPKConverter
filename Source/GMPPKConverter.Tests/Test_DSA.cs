using System;
using System.Linq;
using System.Security;
using GMax.Security;
using Xunit;

namespace GMPPKConverter.Tests
{
    public class Test_DSA
    {
        [Theory]
        [MemberData(nameof(TestData.Data_DSA), MemberType =typeof(TestData))]
        public void Test_DSA_PrivateKey(string keyData, string password)
        {
            // arrange
            SecureString secPass = TestData.GetPassword(password);
            string[] key = keyData.TrimStart().Split("\r\n");
            string expected = TestData.result_DSA_private.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.ImportPPK(key, secPass);
            string result = ppk.ExportPrivateKey();

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [MemberData(nameof(TestData.Data_DSA), MemberType = typeof(TestData))]
        public void Test_DSA_OpenSSH(string keyData, string password)
        {
            // arrange
            SecureString secPass = TestData.GetPassword(password);
            string[] key = keyData.TrimStart().Split("\r\n");
            string expected = TestData.result_DSA_openssh.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.ImportPPK(key, secPass);
            string result = ppk.ExportOpenSSH();

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("тест")]
        public void Test2_EncryptedDSA_BadPassword(string password)
        {
            // arrange
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_DSA2_test.TrimStart().Split("\r\n");

            // act
            var ppk = new KeyConverter();
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Bad password", exception.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Test3_EncryptedDSA_ArgonBadPassword(string password)
        {
            // arrange
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_DSA3_test.TrimStart().Split("\r\n");

            // act
            var ppk = new KeyConverter();
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Argon2 needs a password set (Parameter 'password')", exception.Message);
        }

        [Theory]
        [InlineData("тест")]
        public void Test3_EncryptedDSA_BadPassword(string password)
        {
            // arrange
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_DSA3_test.TrimStart().Split("\r\n");

            // act
            var ppk = new KeyConverter();
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Bad password", exception.Message);
        }
    }
}
