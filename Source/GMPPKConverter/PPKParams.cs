using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace GMax.Security
{
    internal class PPKParams
    {
        public int Version { get; set; } = 0;
        public string KeyType { get; set; } = string.Empty;
        public string Encryption { get; set; } = string.Empty;
        public string Comment { get; set; } = string.Empty;
        public string PrivateMAC { get; set; } = string.Empty;

        public byte[] publicPart;
        public byte[] privatePart;
        public Argon2Params Argon2Params { get; set; }

        private byte[] argon2Hash = new byte[0];

        public void Decrypt(SecureString securePassword)
        {
            if (Encryption.Equals("aes256-cbc"))
            {
                switch (Version)
                {
                    case 2:
                        {
                            byte[] IV = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                            using (SHA1Managed sha1 = new SHA1Managed())
                            {
                                var keyBytes = Helpers.ProcessSecureStringAnsi(securePassword,
                                    (passwordBytes) =>
                                    {
                                        var buffer = new byte[32];
                                        sha1.ComputeHash(passwordBytes).CopyTo(buffer, 0);
                                        passwordBytes[3] = 1;
                                        sha1.ComputeHash(passwordBytes).Take(12).ToArray().CopyTo(buffer, 20);
                                        return buffer;
                                    },
                                    new byte[] { 0, 0, 0, 0 }
                                );
                                //Helpers.Dump("keyBytes", keyBytes);
                                privatePart = Helpers.AESDecrypt(privatePart, IV, keyBytes);
                                //Helpers.Dump("privatePart", privatePart);
                            }
                            break;
                        }
                    case 3:
                        {
                            // Konscious.Security.Cryptography only, other write garbage after byte[32]                            
                            var keyBytes = new byte[32];
                            var IV = new byte[16];                            
                            argon2Hash = Helpers.ProcessSecureStringAnsi(securePassword, (passwordBytes) =>
                            {
                                Konscious.Security.Cryptography.Argon2 argon2;
                                switch (Argon2Params.KeyDerivation)
                                {
                                    case Argon2Type.Argon2i:
                                        argon2 = new Konscious.Security.Cryptography.Argon2i(passwordBytes);
                                        break;
                                    case Argon2Type.Argon2d:
                                        argon2 = new Konscious.Security.Cryptography.Argon2d(passwordBytes);
                                        break;
                                    case Argon2Type.Argon2id:
                                        argon2 = new Konscious.Security.Cryptography.Argon2id(passwordBytes);
                                        break;
                                    default:
                                        throw new ArgumentException("Unknown argon2 type");
                                };
                                argon2.Salt = Argon2Params.Salt;
                                argon2.DegreeOfParallelism = Argon2Params.Parallelism;
                                argon2.Iterations = Argon2Params.Passes;
                                argon2.MemorySize = Argon2Params.Memory;
                                var argonHashBytes = argon2.GetBytes(80);
                                //Helpers.Dump("argonHashBytes", argonHashBytes);
                                var hashBytes = new byte[32];

                                Array.Copy(argonHashBytes, 0, keyBytes, 0, keyBytes.Length);
                                Array.Copy(argonHashBytes, 32, IV, 0, IV.Length);
                                Array.Copy(argonHashBytes, 48, hashBytes, 0, hashBytes.Length);
                                return hashBytes;
                            });
                            privatePart = Helpers.AESDecrypt(privatePart, IV, keyBytes);
                            //Helpers.Dump("privatePart", privatePart);
                            break;
                        }
                    default:
                        throw new CryptographicException("Unsupported encryption Version");
                }
            }
            else if (Encryption == "none")
            {
            }
            else
            {
                new CryptographicException("Unknown Encryption");
            }
        }

        public string ComputeHash(SecureString securePassword, Encoding commentEncoding)
        {
            string hash;

            byte[] bytesToHash;
            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms))
                {
                    AsymmetricKeyHelpers.WriteWithLength(bw, Encoding.ASCII.GetBytes(KeyType));
                    AsymmetricKeyHelpers.WriteWithLength(bw, Encoding.ASCII.GetBytes(Encryption));
                    AsymmetricKeyHelpers.WriteWithLength(bw, commentEncoding.GetBytes(Comment));
                    AsymmetricKeyHelpers.WriteWithLength(bw, publicPart);
                    AsymmetricKeyHelpers.WriteWithLength(bw, privatePart);
                }
                bytesToHash = ms.ToArray();
            }
            switch (Version)
            {
                case 2:
                    {
                        using (var csp = new SHA1CryptoServiceProvider())
                        {
                            hash = Helpers.ProcessSecureStringAnsi(securePassword,
                                (passwordBytes) =>
                                {
                                    using (HMACSHA1 hmacsha1 = new HMACSHA1(csp.ComputeHash(passwordBytes)))
                                    {
                                        return string.Join("", hmacsha1.ComputeHash(bytesToHash).Select(x => string.Format("{0:x2}", x)));
                                    }
                                },
                                Encoding.ASCII.GetBytes("putty-private-key-file-mac-key")
                            );
                            break;
                        }
                    }

                case 3:
                    {
                        using (HMACSHA256 hmacsha256 = new HMACSHA256(argon2Hash))
                        {
                            hash = string.Join("", hmacsha256.ComputeHash(bytesToHash).Select(x => string.Format("{0:x2}", x)));
                            break;
                        }
                    }
                default:
                    throw new ArgumentException("Usupported MAC version");
            }
            return hash;
        }
    }
}
