using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;

namespace GMax.Security
{
    public class KeyConverter
    {
        /// <summary>
        /// Imported ppk params
        /// </summary>
        private PPKParams ppkParams;

        /// <summary>
        /// Imported asymmectic key params
        /// </summary>
        private AsymmetricKeyParams keyParams;

        /// <summary>
        /// Global ppk lines index
        /// </summary>
        private int index = 0;

        private Encoding commentEncoding;

        public KeyConverter(int ImportCodePage = 0)
        {
            if (ImportCodePage <= 0)
            {
                ImportCodePage = System.Globalization.CultureInfo.CurrentCulture.TextInfo.ANSICodePage;
            }
            commentEncoding = Encoding.GetEncoding(ImportCodePage);
        }

        #region Private methods
        private (int, string) ReadFirstLine(string[] lines)
        {
            var match = Regex.Match(lines[index++], $@"PuTTY-User-Key-File-(\d):\s+([-\w]+)");
            if (!match.Success)
                throw new FormatException($"Line {index} is invalid, await PuTTY-User-Key-File");
            if (!int.TryParse(match.Groups[1].Value, out int version) || (version != 2 && version != 3))
                throw new FormatException($"Line {index} is invalid, only Version 2 or 3 supported");
            return (version, match.Groups[2].Value);
        }
        private string ReadLine(string[] lines, string Token, bool strictRegex = true)
        {
            var match = strictRegex ? Regex.Match(lines[index++], $@"{Token}:\s+([-\w\.]+)") : Regex.Match(lines[index++], $@"{Token}:\s+(.+)");
            if (match.Success)
                return match.Groups[1].Value;
            else
                throw new FormatException($"Line {index} is invalid, await {Token}");
        }
        private int ReadInt(string[] lines, string Token)
        {
            var match = Regex.Match(lines[index++], $@"{Token}:\s+([-\w]+)");
            if (match.Success)
                if (int.TryParse(match.Groups[1].Value, out int value))
                    return value;
                else
                    throw new FormatException($"Line {index} is invalid, {Token} not int");
            else
                throw new FormatException($"Line {index} is invalid, await {Token}");
        }
        private byte[] ReadBlock(string[] lines, string Token)
        {
            var match = Regex.Match(lines[index++], $@"{Token}:\s+([-\w]+)");
            var sb = new StringBuilder();
            if (!match.Success || !int.TryParse(match.Groups[1].Value, out int l))
                throw new FormatException($"Line {index} is invalid, await {Token}");
            else
            {
                for (int i = 0; i < l; i++)
                {
                    sb.Append(lines[index++]);
                }
            }
            return Convert.FromBase64String(sb.ToString());
        }
        private IEnumerable<byte> ConvertFromHex(string hex)
        {
            for (int i = 0; i < hex.Length; i += 2)
            {
                //yield return Convert.ToByte(hex[i..(i+2)], 16);
                yield return Convert.ToByte(hex.Substring(i, 2), 16);
            }
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Import Asymmetric Keys from PPK lines array
        /// </summary>
        /// <param name="lines">Array of PPK content</param>
        /// <param name="securePassword">PPK passphrase</param>
        /// <exception cref="NotSupportedException">Not supported asymmetric key</exception>
        /// <exception cref="FormatException">PPK format errors</exception>
        public void ImportPPK(string[] lines, SecureString securePassword)
        {
            ppkParams = new PPKParams();

            index = 0;
            (ppkParams.Version, ppkParams.KeyType) = ReadFirstLine(lines);

            if (ppkParams.KeyType.Equals("ssh-rsa"))
            {
                keyParams = new RSAKeyParams(ppkParams.KeyType);
            }
            else if (ppkParams.KeyType.Equals("ssh-dss"))
            {
                keyParams = new DSAKeyParams(ppkParams.KeyType);
            }
            else if (ppkParams.KeyType.Equals("ecdsa-sha2-nistp256"))
            {
                keyParams = new ECDSAKeyParams(ppkParams.KeyType);
            }
            else if (ppkParams.KeyType.Equals("ecdsa-sha2-nistp384"))
            {
                keyParams = new ECDSAKeyParams(ppkParams.KeyType);
            }
            else if (ppkParams.KeyType.Equals("ecdsa-sha2-nistp521"))
            {
                keyParams = new ECDSAKeyParams(ppkParams.KeyType);
            }
            else if (ppkParams.KeyType.Equals("ssh-ed25519"))
            {
                keyParams = new EDDSAKeyParams(ppkParams.KeyType);
            }
            else if (ppkParams.KeyType.Equals("ssh-ed448"))
            {
                keyParams = new EDDSAKeyParams(ppkParams.KeyType);
            }
            else
            {
                throw new NotSupportedException("Not supported key format");
            }

            ppkParams.Encryption = ReadLine(lines, "Encryption");
            ppkParams.Comment = ReadLine(lines, "Comment", strictRegex: false);
            ppkParams.publicPart = ReadBlock(lines, "Public-Lines");

            if (ppkParams.Version >= 3 && !ppkParams.Encryption.Equals("none")) {
                ppkParams.Argon2Params = new Argon2Params();
                string algorithm = ReadLine(lines, "Key-Derivation");
                if (algorithm.Equals("Argon2d"))
                {
                    ppkParams.Argon2Params.KeyDerivation = Argon2Type.Argon2d;
                }
                else if(algorithm.Equals("Argon2i"))
                {
                    ppkParams.Argon2Params.KeyDerivation = Argon2Type.Argon2i;
                }
                else if (algorithm.Equals("Argon2id"))
                {
                    ppkParams.Argon2Params.KeyDerivation = Argon2Type.Argon2id;
                }
                else
                {
                    throw new FormatException($"Line {index} is invalid, await Key-Derivation in [Argon2d, Argon2i, Argon2id]");
                }
                ppkParams.Argon2Params.Memory = ReadInt(lines, "Argon2-Memory");
                ppkParams.Argon2Params.Passes = ReadInt(lines, "Argon2-Passes");
                ppkParams.Argon2Params.Parallelism = ReadInt(lines, "Argon2-Parallelism");
                var salt = ReadLine(lines, "Argon2-Salt");
                ppkParams.Argon2Params.Salt = ConvertFromHex(salt).ToArray();
            }

            ppkParams.privatePart = ReadBlock(lines, "Private-Lines");
            ppkParams.PrivateMAC = ReadLine(lines, "Private-MAC");

            ppkParams.Decrypt(securePassword);

            if (ppkParams.Encryption.Equals("none") && securePassword?.Length > 0)
            {
                securePassword.Clear();
            }

            string hash = ppkParams.ComputeHash(securePassword, commentEncoding);
            if (!hash.Equals(ppkParams.PrivateMAC))
                if (ppkParams.Encryption.Equals("none"))
                    throw new ArgumentException("Key was modified");
                else
                    throw new ArgumentException("Bad password");

            keyParams.ImportKeyParamsFromPPK(ppkParams.publicPart, ppkParams.privatePart);
        }

        /// <summary>
        /// Exports private key to UNPROTECTED PEM form
        /// </summary>
        /// <returns>UNPROTECTED Private Key as multiline string</returns>
        /// <exception cref="NotImplementedException">Unsupported key format</exception>
        public string ExportPrivateKey()
        {
            var sb = new StringBuilder();
            string keyEnd = string.Empty;
            if (keyParams is RSAKeyParams) {
                sb.Append("-----BEGIN RSA PRIVATE KEY-----\n");
                keyEnd = "\n-----END RSA PRIVATE KEY-----\n";
            }
            else if (keyParams is DSAKeyParams) {
                sb.Append("-----BEGIN DSA PRIVATE KEY-----\n");
                keyEnd = "\n-----END DSA PRIVATE KEY-----\n";
            }
            else if (keyParams is ECDSAKeyParams)
            {
                sb.Append("-----BEGIN EC PRIVATE KEY-----\n");
                keyEnd = "\n-----END EC PRIVATE KEY-----\n";
            }
            else if (keyParams is EDDSAKeyParams)
            {
                return ExportOpenSSH();
            }
            else
            {
                throw new NotImplementedException(string.Format("Export of {0} not implemented", keyParams.GetType().Name));
            }

            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms))
                {
                    AsymmetricKeyHelpers.WriteASN1Tag(bw, 0x30,  // SEQUENCE
                        (bw1) => keyParams.ExportPrivateKeyAsASN1(bw1)
                    );
                }
                sb.Append(Helpers.SplitBase64(ms.ToArray(), 64));
            }

            sb.Append(keyEnd);
            return sb.ToString();
        }

        /// <summary>
        /// Exports private key as UNPROTECTED OpenSSH PEM
        /// </summary>
        /// <returns>private key as UNPROTECTED OpenSSH PEM multiline string</returns>
        public string ExportOpenSSH()
        {
            // https://git.tartarus.org/?p=simon/putty.git;a=blob_plain;f=import.c;hb=c0fba758e60e2ff4c1bebd566d9a0e56276d07ec
            // static bool openssh_new_write
            var sb = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            string keyEnd = "\n-----END OPENSSH PRIVATE KEY-----\n";
            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms))
                {
                    // writing info headers
                    bw.Write(Encoding.ASCII.GetBytes("openssh-key-v1\0"));
                    AsymmetricKeyHelpers.WriteWithLength(bw, Encoding.ASCII.GetBytes("none")); //kdfname
                    AsymmetricKeyHelpers.WriteWithLength(bw, Encoding.ASCII.GetBytes("none"));
                    var kdfoptions = new byte[0];
                    AsymmetricKeyHelpers.WriteWithLength(bw, kdfoptions);

                    // bw.Write(BitConverter.GetBytes(N).Reverse().ToArray()); // number of keys N
                    bw.Write(new byte[] { 0, 0, 0, 1 }); // number of keys N = 1

                    // writing public key
                    using (var ms1 = new MemoryStream())
                    {
                        using (var bw1 = new BinaryWriter(ms1))
                        {
                            keyParams.ExportPublicKeyAsOpenSSH(bw1);
                        }
                        AsymmetricKeyHelpers.WriteWithLength(bw, ms1.ToArray());
                    }

                    // writing private key
                    using (var ms1 = new MemoryStream())
                    {
                        // Because key unencrypited checkint is not random
                        var checkint = 0xef;
                        using (var bw1 = new BinaryWriter(ms1))
                        {
                            bw1.Write(BitConverter.GetBytes(checkint), 0, 4);
                            bw1.Write(BitConverter.GetBytes(checkint), 0, 4);
                            keyParams.ExportPrivateKeyAsOpenSSH(bw1);
                            AsymmetricKeyHelpers.WriteWithLength(bw1, Encoding.ASCII.GetBytes(ppkParams.Comment));
                            // pad out the encrypted section
                            byte padvalue = 1;
                            while ((ms1.Length & 15) != 0)
                            {
                                bw1.Write(padvalue++);
                            };
                        }
                        AsymmetricKeyHelpers.WriteWithLength(bw, ms1.ToArray());
                    }
                }
                sb.Append(Helpers.SplitBase64(ms.ToArray(), 64));
            }
            sb.Append(keyEnd);
            return sb.ToString();
        }
        #endregion
    }
}