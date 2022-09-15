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
        internal static byte[] AESDecrypt(byte[] Data, byte[] IV, byte[] keyBytes)
        {
            byte[] decrypted;

            using (AesManaged cipher = new AesManaged())
            {
                cipher.KeySize = 256;
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.None;
                cipher.Key = keyBytes;
                cipher.IV = IV;
                using (ICryptoTransform decryptor = cipher.CreateDecryptor())
                {
                    decrypted = decryptor.TransformFinalBlock(Data, 0, Data.Length);
                }
                return decrypted;
            }
        }

        internal static byte[] AESEncrypt(byte[] Data, byte[] IV, byte[] keyBytes)
        {
            byte[] encrypted;

            using (AesManaged cipher = new AesManaged())
            {
                cipher.KeySize = 256;
                cipher.Mode = CipherMode.CBC;
                cipher.Padding = PaddingMode.None;
                cipher.Key = keyBytes;
                cipher.IV = IV;
                using (ICryptoTransform encryptor = cipher.CreateEncryptor())
                {
                    encrypted = encryptor.TransformFinalBlock(Data, 0, Data.Length);
                }
                return encrypted;
            }
        }

        // https://git.tartarus.org/?p=simon/putty.git;a=blob;f=import.c;hb=75cd6c8b2703137e574223d90d2f3ead9ca34acc
        //  777 static bool openssh_pem_write(
        //  986     if (passphrase) {
        internal static byte[] CryptPEM(byte[] Data, byte[] IV, SecureString securePassword)
        {
            byte[] keyBytes;
            byte[] salt = new byte[8];
            Array.Copy(IV, salt, 8);
            using (MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider())
            {
                keyBytes = ProcessSecureStringAnsi(securePassword,
                    (passwordBytes) =>
                    {
                        var keyBuffer = new byte[32];
                        var tmp = new byte[16 + passwordBytes.Length + salt.Length];
                        passwordBytes.CopyTo(tmp, 16);
                        salt.CopyTo(tmp, 16 + passwordBytes.Length);
                        var pass1 = md5.ComputeHash(tmp, 16, tmp.Length - 16);
                        pass1.CopyTo(keyBuffer, 0);
                        pass1.CopyTo(tmp, 0);
                        var pass2 = md5.ComputeHash(tmp);
                        pass2.CopyTo(keyBuffer, 16);
                        return keyBuffer;
                    }
                );
            }
            // make padding
            byte padCount = (byte)(16 - Data.Length % 16);
            if (padCount == 0) padCount = 16;
            var buffer = new byte[Data.Length + padCount];
            Data.CopyTo(buffer, 0);
            for (int i = Data.Length; i < buffer.Length; i++)
            {
                buffer[i] = padCount;
            }
            var encrypted = AESEncrypt(buffer, IV, keyBytes);
            return encrypted;
        }

        internal static byte[] CryptOpenSSH(byte[] Data, byte[] salt, int rounds, SecureString securePassword)
        {
            byte[] keyBytes = ProcessSecureStringAnsi(securePassword,
                (passwordBytes) =>
                {
                    byte[] keyiv = new byte[48];
                    new BCrypt().Pbkdf(passwordBytes, salt, rounds, keyiv);
                    return keyiv;
                }
            );

            byte[] key = new byte[32];
            Array.Copy(keyBytes, 0, key, 0, 32);
            byte[] iv = new byte[16];
            Array.Copy(keyBytes, 32, iv, 0, 16);

            byte[] encryptedBytes = null;
            //encryptedBytes = AESEncryptCtr(Data, iv, key);
            encryptedBytes = AESEncrypt(Data, iv, key);
            return encryptedBytes;
        }
        internal static T ProcessSecureStringAnsi<T>(SecureString src, Func<byte[], T> func, byte[] arrayPrefix = null)
        {
            IntPtr unmanagedBytes = IntPtr.Zero;
            byte[] workArray = null;
            GCHandle? handle = null; // Hats off to Tobias Bauer
            try
            {
                if (src == null)
                {
                    handle = GCHandle.Alloc(workArray, GCHandleType.Pinned);
                    if (arrayPrefix == null) {
                        return func(new byte[0]);
                    }
                    else
                    {
                        workArray = new byte[arrayPrefix.Length];
                        arrayPrefix.CopyTo(workArray, 0);
                        return func(workArray);
                    }                    
                }
                else
                {
                    unmanagedBytes = Marshal.SecureStringToGlobalAllocAnsi(src);
                    unsafe
                    {
                        byte* byteArray = (byte*)unmanagedBytes;
                        int startIndex;
                        if (arrayPrefix == null)
                        {
                            workArray = new byte[src.Length];
                            startIndex = 0;
                        }
                        else
                        {
                            workArray = new byte[src.Length + arrayPrefix.Length];
                            arrayPrefix.CopyTo(workArray, 0);
                            startIndex = arrayPrefix.Length;
                        }
                        handle = GCHandle.Alloc(workArray, GCHandleType.Pinned); // Hats off to Tobias Bauer
                        for (int i = startIndex; i < workArray.Length; i++)
                            workArray[i] = *byteArray++;
                    }
                    return func(workArray);
                }
            }
            finally
            {
                if (workArray != null)
                    for (int i = 0; i < workArray.Length; i++)
                        workArray[i] = 0;
                if (unmanagedBytes != IntPtr.Zero)
                    Marshal.ZeroFreeGlobalAllocAnsi(unmanagedBytes);
                handle?.Free();
            }
        }

        // https://stackoverflow.com/questions/18392538/securestring-to-byte-c-sharp
        // https://social.msdn.microsoft.com/Forums/vstudio/en-US/f6710354-32e3-4486-b866-e102bb495f86/converting-a-securestring-object-to-byte-array-in-net
        internal static T ProcessSecureStringUni<T>(SecureString src, Func<byte[], T> func, byte[] arrayPrefix = null)
        {
            IntPtr bstr = IntPtr.Zero;
            byte[] workArray = null;
            GCHandle? handle = null; // Hats off to Tobias Bauer
            try
            {
                if (src == null)
                {
                    handle = GCHandle.Alloc(workArray, GCHandleType.Pinned);
                    workArray = new byte[arrayPrefix.Length];
                    arrayPrefix.CopyTo(workArray, 0);
                    return func(workArray);
                }
                else
                {
                    /*** PLAINTEXT EXPOSURE BEGINS HERE ***/
                    bstr = Marshal.SecureStringToBSTR(src);
                    unsafe
                    {
                        byte* byteArray = (byte*)bstr;
                        int startIndex;
                        if (arrayPrefix == null)
                        {
                            workArray = new byte[src.Length * 2];
                            startIndex = 0;
                        }
                        else
                        {
                            workArray = new byte[src.Length * 2 + arrayPrefix.Length];
                            arrayPrefix.CopyTo(workArray, 0);
                            startIndex = arrayPrefix.Length;
                        }
                        handle = GCHandle.Alloc(workArray, GCHandleType.Pinned); // Hats off to Tobias Bauer
                        for (int i = startIndex; i < workArray.Length; i++)
                            workArray[i] = *byteArray++;
                    }
                    return func(workArray);
                }
            }
            finally
            {
                if (workArray != null)
                    for (int i = 0; i < workArray.Length; i++)
                        workArray[i] = 0;
                if (bstr != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(bstr);
                handle?.Free();
                /*** PLAINTEXT EXPOSURE ENDS HERE ***/
            }
        }

        internal static void Dump(string header, byte[] data)
        {
            int i = 0;
            StringBuilder hex = new StringBuilder();
            StringBuilder text = new StringBuilder();
            Console.WriteLine(header);
            while (i < data.Length)
            {
                if ((i & 15) == 0)
                {
                    Console.Write(hex.ToString());
                    Console.WriteLine(text.ToString());
                    hex = new StringBuilder(string.Format("{0:X8} ", i));
                    text = new StringBuilder("    ");
                }
                hex.Append(string.Format("{0:X2} ", data[i]));
                if (data[i] == 9 || data[i] == 10 || data[i] == 13)
                    text.Append(" ");
                else
                    text.Append(string.Format("{0}", (char)data[i]));
                i++;
            }
            Console.Write(hex.ToString().PadRight(57));
            Console.WriteLine(text.ToString());
        }
        internal static string SplitBase64(byte[] data, int length)
        {
            var s = Convert.ToBase64String(data);
            return string.Join("\n", Regex.Matches(s, ".{1," + length + "}").Cast<Match>().Select(m => m.Value).ToArray());
        }

    }
}