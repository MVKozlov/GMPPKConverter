using System.Security.Cryptography;

namespace GMax.Security
{
    internal class AesManagedCtr : SymmetricAlgorithm
    {
        private readonly byte[] _counter;
        private readonly AesManaged _aes;

        public AesManagedCtr(byte[] counter)
        {
            // counter size must be same as block size!
            _aes = new AesManaged
            {
                Mode = CipherMode.ECB,
                Padding = PaddingMode.None
            };

            _counter = counter;
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] ignoredParameter)
        {
            return new CounterModeCryptoTransform(_aes, rgbKey, _counter);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] ignoredParameter)
        {
            return new CounterModeCryptoTransform(_aes, rgbKey, _counter);
        }

        public override void GenerateKey()
        {
            _aes.GenerateKey();
        }

        public override void GenerateIV()
        {
            // IV not needed in Counter Mode
        }
    }
}