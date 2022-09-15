using System;
using System.Linq;
using System.Security;
using GMax.Security;
using Xunit;

namespace GMPPKConverter.Tests
{
    public class Test_EDDSA
    {
        [Theory]
        [MemberData(nameof(TestData.EDDSA_Data_OpenSSH), MemberType = typeof(TestData))]
        public void Test_EDDSA_OpenSSH(string keyData, string inPassword, byte[][] RngData, string Result)
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
    }
}
