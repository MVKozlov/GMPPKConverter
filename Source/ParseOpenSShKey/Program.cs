using System;
using System.IO;
using System.Text;

namespace GMax.Security.ParseOpenSShKey
{
    internal class Program
    {
        static long ReadInt(BinaryReader br)
        {
            var buf = br.ReadBytes(4);
            var i = (long)buf[0] << 24 | (long)buf[1] << 16 | (long)buf[2] << 8 | (long)buf[3];
            return i;
        }


        static byte[] ReadBlock(BinaryReader br, long len = 0)
        {
            if (len == 0)
            {
                len = ReadInt(br);
            }
            var bytes = br.ReadBytes((int)len);
            return bytes;
        }

        static string ReadString(BinaryReader br, long len = 0)
        {
            return System.Text.Encoding.ASCII.GetString(ReadBlock(br, len));
        }

        private static string AES256_CBC = "aes256-cbc";
        private static string AES256_CTR = "aes256-ctr";

        private static byte[] DecryptPrivateKeySection(
            string cipher,
            byte[] Data, byte[] salt, int rounds, string passPhrase
        )
        {
            //extracting key/iv from kdf was adapted from and inspired by the SSHj library (https://github.com/hierynomus/sshj)
            var passPhraseBytes = Encoding.UTF8.GetBytes(passPhrase);
            byte[] keyiv = new byte[48];
            new BCrypt().Pbkdf(passPhraseBytes, salt, rounds, keyiv);
            byte[] key = new byte[32];
            Array.Copy(keyiv, 0, key, 0, 32);
            byte[] iv = new byte[16];
            Array.Copy(keyiv, 32, iv, 0, 16);

            byte[] decryptedBytes = null;
            if (cipher == AES256_CBC)
            {
                decryptedBytes = Helpers.AESDecrypt(Data, iv, key);
            }
            else if (cipher == AES256_CTR)
            {
                decryptedBytes = Helpers.AESDecryptCtr(Data, iv, key);
            }
            return decryptedBytes;
        }

        private static byte[] EncryptPrivateKeySection(
            string cipher,
            byte[] Data, byte[] salt, int rounds, string passPhrase
        )
        {
            var passPhraseBytes = Encoding.UTF8.GetBytes(passPhrase);
            byte[] keyiv = new byte[48];
            new BCrypt().Pbkdf(passPhraseBytes, salt, rounds, keyiv);
            byte[] key = new byte[32];
            Array.Copy(keyiv, 0, key, 0, 32);
            byte[] iv = new byte[16];
            Array.Copy(keyiv, 32, iv, 0, 16);

            byte[] encryptedBytes = null;
            if (cipher == AES256_CBC)
            {
                encryptedBytes = Helpers.AESEncrypt(Data, iv, key);
            }
            else if (cipher == AES256_CTR)
            {
                encryptedBytes = Helpers.AESEncryptCtr(Data, iv, key);
            }

            return encryptedBytes;
        }

        static void Main(string[] args)
        {
            var path = args[0];
            var content = File.ReadAllText(path);
            content = System.Text.RegularExpressions.Regex.Replace(content, @"-----\w+ OPENSSH PRIVATE KEY-----", "");

            var bytes = System.Convert.FromBase64String(content);
            byte[] salt = new byte[16];
            int rounds = 16;
            using (MemoryStream ms = new MemoryStream(bytes))
            {
                using (BinaryReader br = new BinaryReader(ms))
                {
                    Console.Write("{0:X8} - ", br.BaseStream.Position);
                    var marker = ReadString(br, 15);
                    Console.WriteLine("marker: {0}", marker);
                    Console.Write("{0:X8} - ", br.BaseStream.Position);
                    var ciphername = ReadString(br);
                    Console.WriteLine("ciphername: {0}", ciphername);
                    Console.Write("{0:X8} - ", br.BaseStream.Position);
                    var kdfname = ReadString(br);
                    Console.WriteLine("kdfname: {0}", kdfname);
                    Console.Write("{0:X8} - ", br.BaseStream.Position);
                    var options = ReadBlock(br);
                    Console.WriteLine("options:");
                    if (options.Length > 0)
                    {
                        using (MemoryStream ms1 = new MemoryStream(options))
                        {
                            using (BinaryReader br1 = new BinaryReader(ms1))
                            {
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                salt = ReadBlock(br1);
                                Console.WriteLine("salt: {0}", BitConverter.ToString(salt).Replace('-', ' '));
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                rounds = (int)ReadInt(br1);
                                Console.WriteLine("rounds: {0}", rounds);
                            }
                        }
                    }
                    Console.Write("{0:X8} - ", br.BaseStream.Position);
                    var keysnum = ReadInt(br);
                    Console.WriteLine("keysnum: {0}", keysnum);
                    Console.Write("{0:X8} - ", br.BaseStream.Position);
                    var sshpub = ReadBlock(br);
                    Console.WriteLine("sshpub:\r\n{0}", BitConverter.ToString(sshpub).Replace('-', ' '));
                    Console.Write("{0:X8} - ", br.BaseStream.Position);
                    var sshpriv = ReadBlock(br);
                    Console.WriteLine("sshpriv:\r\n{0}", BitConverter.ToString(sshpriv).Replace('-', ' '));
                    using (MemoryStream ms1 = new MemoryStream(sshpriv))
                    {
                        using (BinaryReader br1 = new BinaryReader(ms1))
                        {
                            Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                            var checkint1 = ReadInt(br1);
                            Console.WriteLine("checkint1: {0:X8}", checkint1);
                            Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                            var checkint2 = ReadInt(br1);
                            Console.WriteLine("checkint2: {0:X8}", checkint2);
                        }
                    }
                    if (ciphername != "none")
                    {
                        Console.WriteLine("decrypt {0}", ciphername);
                        var decrypted = DecryptPrivateKeySection(ciphername, sshpriv, salt, rounds, "test");
                        using (MemoryStream ms1 = new MemoryStream(decrypted))
                        {
                            using (BinaryReader br1 = new BinaryReader(ms1))
                            {
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint1 = ReadInt(br1);
                                Console.WriteLine("checkint1: {0:X8}", checkint1);
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint2 = ReadInt(br1);
                                Console.WriteLine("checkint2: {0:X8}", checkint2);
                            }
                        }
                        Console.WriteLine("  decrypted:\r\n{0}", BitConverter.ToString(decrypted).Replace('-', ' '));
                        Console.WriteLine("encrypt {0}", ciphername);
                        var encrypted = EncryptPrivateKeySection(ciphername, decrypted, salt, rounds, "test");
                        using (MemoryStream ms1 = new MemoryStream(encrypted))
                        {
                            using (BinaryReader br1 = new BinaryReader(ms1))
                            {
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint1 = ReadInt(br1);
                                Console.WriteLine("checkint1: {0:X8}", checkint1);
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint2 = ReadInt(br1);
                                Console.WriteLine("checkint2: {0:X8}", checkint2);
                            }
                        }
                        Console.WriteLine("  encrypted alt:\r\n{0}", BitConverter.ToString(encrypted).Replace('-', ' '));
                        
                        // Use alternate encryption
                        ciphername = (ciphername == AES256_CBC) ? AES256_CTR : AES256_CBC;
                        
                        Console.WriteLine("encrypt {0}", ciphername);
                        encrypted = EncryptPrivateKeySection(ciphername, decrypted, salt, rounds, "test");
                        using (MemoryStream ms1 = new MemoryStream(encrypted))
                        {
                            using (BinaryReader br1 = new BinaryReader(ms1))
                            {
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint1 = ReadInt(br1);
                                Console.WriteLine("checkint1: {0:X8}", checkint1);
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint2 = ReadInt(br1);
                                Console.WriteLine("checkint2: {0:X8}", checkint2);
                            }
                        }
                        Console.WriteLine("  encrypted:\r\n{0}", BitConverter.ToString(encrypted).Replace('-', ' '));
                        
                        Console.WriteLine("decrypt {0}", ciphername);
                        decrypted = DecryptPrivateKeySection(ciphername, encrypted, salt, rounds, "test");
                        using (MemoryStream ms1 = new MemoryStream(decrypted))
                        {
                            using (BinaryReader br1 = new BinaryReader(ms1))
                            {
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint1 = ReadInt(br1);
                                Console.WriteLine("checkint1: {0:X8}", checkint1);
                                Console.Write("  {0:X8} - ", br1.BaseStream.Position);
                                var checkint2 = ReadInt(br1);
                                Console.WriteLine("checkint2: {0:X8}", checkint2);
                            }
                        }
                        Console.WriteLine("  decrypted:\r\n{0}", BitConverter.ToString(decrypted).Replace('-', ' '));
                    }
                }
            }
            Console.WriteLine("done");
            Console.ReadKey();
        }
    }
}
