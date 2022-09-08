using System;
using System.Linq;
using System.Security;
using GMax.Security;
using Xunit;

namespace GMPPKConverter.Tests
{
    public class Test_CommentCodePage
    {
        [Theory]
        [InlineData("test")]
        public void Test3_EncryptedECDSA_Loose_Comment_2(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_ECDSA_test_comment_2.TrimStart().Split("\r\n");
            string expected = TestData.result_ECDSA_test_comment.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.ImportPPK(key, secPass);
            string result = ppk.ExportPrivateKey();

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("test")]
        public void Test3_EncryptedECDSA_Loose_Comment_3(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_ECDSA_test_comment_3.TrimStart().Split("\r\n");
            string expected = TestData.result_ECDSA_test_comment.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            ppk.ImportPPK(key, secPass);
            string result = ppk.ExportPrivateKey();

            // assert
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("badtest")]
        public void Test3_EncryptedECDSA_Bad_Comment_2(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_ECDSA_test_comment_2.TrimStart().Split("\r\n");
            string expected = TestData.result_ECDSA_test_comment.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Bad password", exception.Message);
        }

        [Theory]
        [InlineData("badtest")]
        public void Test3_EncryptedECDSA_Comment_3(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_ECDSA_test_comment_3.TrimStart().Split("\r\n");
            string expected = TestData.result_ECDSA_test_comment.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter();
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Bad password", exception.Message);
        }

        [Theory]
        [InlineData("test")]
        public void Test3_EncryptedECDSA_Bad_Comment_2_cp(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_ECDSA_test_comment_2.TrimStart().Split("\r\n");
            string expected = TestData.result_ECDSA_test_comment.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter(1252);
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Bad password", exception.Message);
        }

        [Theory]
        [InlineData("test")]
        public void Test3_EncryptedECDSA_Comment_3_cp(string password)
        {
            // arrange
            System.Text.Encoding.RegisterProvider(System.Text.CodePagesEncodingProvider.Instance);
            SecureString secPass = TestData.GetPassword(password);
            string[] key = TestData.ppk_ECDSA_test_comment_3.TrimStart().Split("\r\n");
            string expected = TestData.result_ECDSA_test_comment.Replace("\r", "").TrimStart();

            // act
            var ppk = new KeyConverter(1252);
            Action act = () => ppk.ImportPPK(key, secPass);

            // assert
            ArgumentException exception = Assert.Throws<ArgumentException>(act);
            //The thrown exception can be used for even more detailed assertions.
            Assert.Equal("Bad password", exception.Message);
        }
    }
}
