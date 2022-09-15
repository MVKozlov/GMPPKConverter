using System.Collections.Generic;
using System.Security.Cryptography;

namespace GMax.Security
{
    internal class CounterModeCryptoTransform : ICryptoTransform
    {
        private readonly byte[] _counter;
        private readonly ICryptoTransform _counterEncryptor;
        private readonly Queue<byte> _xorMask = new Queue<byte>();
        private readonly SymmetricAlgorithm _symmetricAlgorithm;

        public CounterModeCryptoTransform(SymmetricAlgorithm symmetricAlgorithm, byte[] key, byte[] counter)
        {
            // Counter size must be same as block size !
            _symmetricAlgorithm = symmetricAlgorithm;
            _counter = counter;

            var zeroIv = new byte[_symmetricAlgorithm.BlockSize / 8];
            _counterEncryptor = symmetricAlgorithm.CreateEncryptor(key, zeroIv);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var output = new byte[inputCount];
            TransformBlock(inputBuffer, inputOffset, inputCount, output, 0);
            return output;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            for (var i = 0; i < inputCount; i++)
            {
                if (NeedMoreXorMaskBytes()) EncryptCounterThenIncrement();

                var mask = _xorMask.Dequeue();
                outputBuffer[outputOffset + i] = (byte)(inputBuffer[inputOffset + i] ^ mask);
            }

            return inputCount;
        }

        private bool NeedMoreXorMaskBytes()
        {
            return _xorMask.Count == 0;
        }

        private void EncryptCounterThenIncrement()
        {
            var counterModeBlock = new byte[_symmetricAlgorithm.BlockSize / 8];

            _counterEncryptor.TransformBlock(_counter, 0, _counter.Length, counterModeBlock, 0);
            IncrementCounter();

            foreach (var b in counterModeBlock)
            {
                _xorMask.Enqueue(b);
            }
        }

        private void IncrementCounter()
        {
            for (var i = _counter.Length - 1; i >= 0; i--)
            {
                if (++_counter[i] != 0)
                    break;
            }
        }

        public int InputBlockSize { get { return _symmetricAlgorithm.BlockSize / 8; } }
        public int OutputBlockSize { get { return _symmetricAlgorithm.BlockSize / 8; } }
        public bool CanTransformMultipleBlocks { get { return true; } }
        public bool CanReuseTransform { get { return false; } }

        public void Dispose()
        {
        }

    }
}