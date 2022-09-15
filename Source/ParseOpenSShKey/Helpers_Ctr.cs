using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace GMax.Security
{
    internal static partial class Helpers
    {
        public static byte[] AESDecryptCtr(byte[] Data, byte[] IV, byte[] keyBytes)
        {
            var decrypted = new byte[Data.Length];
            using (var cipher = new AesManagedCtr(IV))
            {
                using (ICryptoTransform decryptor = cipher.CreateEncryptor(keyBytes, null))
                {
                    decrypted = decryptor.TransformFinalBlock(Data, 0, Data.Length);
                }
            }
            return decrypted;
        }

        public static byte[] AESEncryptCtr(byte[] Data, byte[] IV, byte[] keyBytes)
        {
            var encrypted = new byte[Data.Length];
            using (var cipher = new AesManagedCtr(IV))
            {
                using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, null))
                {
                    encrypted = encryptor.TransformFinalBlock(Data, 0, Data.Length);
                }
            }
            return encrypted;
        }
    }
}
