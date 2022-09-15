using System;
using System.Linq;
using System.Security;
using GMax.Security;
using Moq;
using Xunit;

namespace GMPPKConverter.Tests
{
    public class Test_Features
    {

        [Theory]
        [MemberData(nameof(TestData.ECDSA_Data_OpenSSH_pass), MemberType = typeof(TestData))]
        public void Test_ECDSA_OpenSSH_pass(string keyData, string outPassword, byte[][] RngData, string Result)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            // arrange
            var rngMock = TestData.SetupRngMock(RngData);
            string[] key = keyData.TrimStart().Split("\r\n");
            SecureString outPass = (string.IsNullOrEmpty(outPassword)) ? null : TestData.GetPassword(outPassword);
            string expected = Result.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.Rng = rngMock.Object;
            ppk.ImportPPK(key);
            string result = ppk.ExportOpenSSH(outPass);

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [MemberData(nameof(TestData.ECDSA_Data_PEM_pass), MemberType = typeof(TestData))]
        public void Test_ECDSA_PEM_pass(string keyData, string outPassword, byte[][] RngData, string Result)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            // arrange
            var rngMock = TestData.SetupRngMock(RngData);
            string[] key = keyData.TrimStart().Split("\r\n");
            SecureString outPass = (string.IsNullOrEmpty(outPassword)) ? null : TestData.GetPassword(outPassword);
            string expected = Result.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.Rng = rngMock.Object;
            ppk.ImportPPK(key);
            string result = ppk.ExportPrivateKey(outPass);

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Test_ECDSA_3_null_pass(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ECDSA_256_PPK3_test_pass.TrimStart().Split("\r\n");

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
        public void Test_ECDSA_3_bad_pass(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ECDSA_256_PPK3_test_pass.TrimStart().Split("\r\n");

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
        [InlineData("тест")]
        public void Test_ECDSA_2_bad_pass(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ECDSA_256_PPK2_test_pass.TrimStart().Split("\r\n");

            // act
            var ppk = new KeyConverter();
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Bad password", exception.Message);
        }

        [Theory]
        [MemberData(nameof(TestData.ECDSA_Data_OpenSSH_comment), MemberType = typeof(TestData))]
        public void Test_ECDSA_OpenSSH_comment(string keyData, byte[][] RngData, string Result)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            // arrange
            var rngMock = TestData.SetupRngMock(RngData);
            string[] key = keyData.TrimStart().Split("\r\n");
            string expected = Result.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter(1251);
            ppk.Rng = rngMock.Object;
            ppk.ImportPPK(key);
            string result = ppk.ExportOpenSSH();

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [MemberData(nameof(TestData.ECDSA_Data_OpenSSH_comment), MemberType = typeof(TestData))]
        public void Test_ECDSA_OpenSSH_modified_comment(string keyData, byte[][] RngData, string Result)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            // arrange
            var rngMock = TestData.SetupRngMock(RngData);
            string[] key = keyData.TrimStart().Replace("Comment: test", "Comment: tst").Split("\r\n");
            string expected = Result.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter(1251);
            ppk.Rng = rngMock.Object;
            Action act = () => ppk.ImportPPK(key);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Key was modified", exception.Message);
        }

        [Theory]
        [MemberData(nameof(TestData.ECDSA_Data_OpenSSH_comment), MemberType = typeof(TestData))]
        public void Test_ECDSA_OpenSSH_bad_codepage_comment(string keyData, byte[][] RngData, string Result)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            // arrange
            var rngMock = TestData.SetupRngMock(RngData);
            string[] key = keyData.TrimStart().Split("\r\n");
            string expected = Result.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter(1252);
            ppk.Rng = rngMock.Object;
            Action act = () => ppk.ImportPPK(key);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Key was modified", exception.Message);
        }

    }
}
