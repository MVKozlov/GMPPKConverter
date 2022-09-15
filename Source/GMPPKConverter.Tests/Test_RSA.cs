using System;
using System.Linq;
using System.Security;
using GMax.Security;
using Xunit;

namespace GMPPKConverter.Tests
{
    public class Test_RSA
    {
        [Theory]
        [MemberData(nameof(TestData.RSA_Data_OpenSSH), MemberType = typeof(TestData))]
        public void Test_RSA_OpenSSH(string keyData, string inPassword, byte[][] RngData, string Result)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            // arrange
            var rngMock = TestData.SetupRngMock(RngData);
            string[] key = keyData.TrimStart().Split("\r\n");
            SecureString inPass = (string.IsNullOrEmpty(inPassword)) ? null : TestData.GetPassword(inPassword);
            string expected = Result.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.Rng = rngMock.Object;
            ppk.ImportPPK(key, inPass);
            string result = ppk.ExportOpenSSH();

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [MemberData(nameof(TestData.RSA_Data_PEM), MemberType = typeof(TestData))]
        public void Test_RSA_PEM(string keyData, string inPassword, string Result)
        {
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            // arrange
            string[] key = keyData.TrimStart().Split("\r\n");
            SecureString inPass = (string.IsNullOrEmpty(inPassword)) ? null : TestData.GetPassword(inPassword);
            string expected = Result.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.ImportPPK(key, inPass);
            string result = ppk.ExportPrivateKey();

            // assert
            Assert.Equal(expected, result);
        }
    }
}
