using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GMax.Security
{
    // asn-1
    // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-tag-bytes
    // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-bit-string
    // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-octet-string
    internal class ECDSAKeyParams : AsymmetricKeyParams
    {
        public ECDSAKeyParams(string Algorithm) : base(Algorithm)
        {
            CurveName = Algorithm.Substring(10);
        }

        public string CurveName { get; set; }
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }

        public override void ExportPrivateKeyAsASN1(BinaryWriter bw)
        {
            /*
            * Structure of asn1:
                 ECPrivateKey ::= SEQUENCE {
                    version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
                    privateKey     OCTET STRING,
                    parameters [0]
                      ECParameters {{ NamedCurve }} OPTIONAL,
                    publicKey  [1]
                      BIT STRING OPTIONAL
                 }
            */
            // https://www.gnupg.org/documentation/manuals/gcrypt/ECC-key-parameters.html
            //byte[] oid;
            int[] oid;
            if (CurveName.Equals("nistp256"))
            {
                // 1.2.840.10045.3.1.7
                //oid = new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
                oid = new int[] { 1, 2, 840, 10045, 3, 1, 7 };
            }
            else if (CurveName.Equals("nistp384"))
            {
                // 1.3.132.0.34
                //oid = new byte[] { 0x2B, 0x81, 0x04, 0x00, 0x22 };
                oid = new int[] { 1, 3, 132, 0, 34 };
            }
            else if (CurveName.Equals("nistp521"))
            {
                // 1.3.132.0.35
                //oid = new byte[] { 0x2B, 0x81, 0x04, 0x00, 0x23 };
                oid = new int[] { 1, 3, 132, 0, 35 };
            }
            else
            {
                throw new NotImplementedException("Invalid curve name in export");
            }

            AsymmetricKeyHelpers.

                        //
                        WriteASN1Integer(bw, new byte[] { 0x01 });
            AsymmetricKeyHelpers.WriteASN1OctetString(bw, PrivateKey);
            AsymmetricKeyHelpers.WriteASN1Tag(bw, 0xA0,  // Tag 0
                (bw1) => AsymmetricKeyHelpers.WriteASN1OidGeneric(bw1, oid)
            );
            AsymmetricKeyHelpers.WriteASN1Tag(bw, 0xA1,  // Tag 1
                (bw1) => AsymmetricKeyHelpers.WriteASN1BitString(bw1, PublicKey)
            );
        }

        public override void ExportPrivateKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.

                        ////put_mp_ssh2(bs, ek->privateKey);
                        ////
                        //put_stringz(bs, ek->curve->name);
                        //933     put_wpoint(bs, ek->publicKey, ek->curve, false);
                        //934     put_mp_ssh2(bs, ek->privateKey);
                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, Encoding.ASCII.GetBytes(CurveName));
            AsymmetricKeyHelpers.WriteWithLength(bw, PublicKey);
            AsymmetricKeyHelpers.WriteWithLength(bw, PrivateKey);
        }

        public override void ExportPublicKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.
                        // https://git.tartarus.org/?p=simon/putty.git;a=blob;f=crypto/ecc-ssh.c;hb=faf1601a5549eda9298f72f7c0f68f39c8f97764
                        //put_stringz(bs, ek->sshk.vt->ssh_id);
                        //769     put_stringz(bs, ek->curve->name);
                        //770     put_wpoint(bs, ek->publicKey, ek->curve, false);
                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, Encoding.ASCII.GetBytes(CurveName));
            AsymmetricKeyHelpers.WriteWithLength(bw, PublicKey);
        }

        public override void ImportKeyParamsFromPPK(byte[] publicData, byte[] privateData)
        {
            using (var ms = new MemoryStream(publicData))
            {
                using (var br = new BinaryReader(ms))
                {
                    AsymmetricKeyHelpers.ReadWithLength(br); // alg. name ecdsa-sha2-nistp256
                    CurveName = Encoding.ASCII.GetString(AsymmetricKeyHelpers.ReadWithLength(br)); // curveName
                    PublicKey = AsymmetricKeyHelpers.ReadWithLength(br);
                }
            }

            using (var ms = new MemoryStream(privateData))
            {
                using (var br = new BinaryReader(ms))
                {
                    PrivateKey = AsymmetricKeyHelpers.ReadWithLength(br);
                }
            }

        }
    }
}
