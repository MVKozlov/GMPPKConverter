using System;
using System.Collections.Generic;
using System.Security;
using Moq;

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
        delegate void SubmitMockCallback(byte[] buffer);
        public static Mock<GMax.Security.IRandomNumberGenerator> SetupRngMock(byte[][] testData)
        {
            var rngMock = new Mock<GMax.Security.IRandomNumberGenerator>();
            var sequence = new MockSequence();

            foreach (var param in testData)
            {
                rngMock.InSequence(sequence).Setup(f =>
                        f.Fill(It.Is<byte[]>(a => a.Length == param.Length))
                ).
                Callback(
                    new SubmitMockCallback((byte[] buf) => Array.Copy(param, buf, buf.Length))
                );
            }
            return rngMock;
        }

    }

}
