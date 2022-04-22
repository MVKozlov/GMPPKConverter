using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace GMax.Security
{
    internal class RSAKeyParams : AsymmetricKeyParams
    {
        public RSAKeyParams(string Algorithm) : base(Algorithm)
        {
        }

        /*
         RSAParameters.Exponent (and RSAParameters.Modulus), on the other hand, is an unsigned, big-endian integer using a minimum number of bytes.

         RSAParameters.P (and Q, DP, DQ, InverseQ) is an unsigned, big-endian fixed-width integer
         whose byte[].Length value must be exactly ((RSAParameters.Modulus.Length + 1) / 2).
         And RSAParameters.D must have the same length as RSAParameters.Modulus.
        */
        public byte[] D { get; set; }
        public byte[] P { get; set; }
        public byte[] Q { get; set; }
        public byte[] InverseQ { get; set; }
        public byte[] DP { get; set; }
        public byte[] DQ { get; set; }
        public byte[] Exponent { get; set; }
        public byte[] Modulus { get; set; }

        public override void ExportPrivateKeyAsASN1(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.WriteASN1Integer(bw, new byte[] { 0x00 }); // Version
            AsymmetricKeyHelpers.WriteASN1Integer(bw, Modulus);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, Exponent);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, D);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, P);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, Q);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, DP);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, DQ);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, InverseQ);
        }

        public override void ExportPrivateKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.
                        ////put_mp_ssh2(bs, rsa->private_exponent);
                        ////539     put_mp_ssh2(bs, rsa->p);
                        ////540     put_mp_ssh2(bs, rsa->q);
                        ////541     put_mp_ssh2(bs, rsa->iqmp);
                        ////
                        //put_mp_ssh2(bs, rsa->modulus);
                        //599     put_mp_ssh2(bs, rsa->exponent);
                        //600     put_mp_ssh2(bs, rsa->private_exponent);
                        //601     put_mp_ssh2(bs, rsa->iqmp);
                        //602     put_mp_ssh2(bs, rsa->p);
                        //603     put_mp_ssh2(bs, rsa->q);

                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, Modulus); //, true
            AsymmetricKeyHelpers.WriteWithLength(bw, Exponent);
            AsymmetricKeyHelpers.WriteWithLength(bw, D); //, true
            AsymmetricKeyHelpers.WriteWithLength(bw, InverseQ); //, true
            AsymmetricKeyHelpers.WriteWithLength(bw, P); //, true
            AsymmetricKeyHelpers.WriteWithLength(bw, Q); //, true
        }

        public override void ExportPublicKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.
                        // https://git.tartarus.org/?p=simon/putty.git;a=blob;f=crypto/rsa.c;hb=faf1601a5549eda9298f72f7c0f68f39c8f97764
                        //put_stringz(bs, "ssh-rsa");
                        //530     put_mp_ssh2(bs, rsa->exponent);
                        //531     put_mp_ssh2(bs, rsa->modulus);
                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, Exponent);
            AsymmetricKeyHelpers.WriteWithLength(bw, Modulus); //, true
        }

        public override void ImportKeyParamsFromPPK(byte[] publicData, byte[] privateData)
        {
            if (privateData?.Length == 0)
                throw new CryptographicException("Private key not decoded");
            using (var ms = new MemoryStream(publicData))
            {
                using (var br = new BinaryReader(ms))
                {
                    AsymmetricKeyHelpers.ReadWithLength(br); // alg. name ssh-rsa
                    // exponent
                    Exponent = AsymmetricKeyHelpers.ReadWithLength(br);
                    // modulus
                    Modulus = AsymmetricKeyHelpers.ReadWithLength(br); // FixLength
                }
            }
            using (var ms = new MemoryStream(privateData))
            {
                using (var br = new BinaryReader(ms))
                {
                    //D
                    D = AsymmetricKeyHelpers.ReadWithLength(br); // FixLength
                    //P
                    P = AsymmetricKeyHelpers.ReadWithLength(br); // FixLength
                    //Q
                    Q = AsymmetricKeyHelpers.ReadWithLength(br); // FixLength
                    //InverseQ
                    InverseQ = AsymmetricKeyHelpers.ReadWithLength(br); // FixLength

                    //var d = new BigInteger(rsaParams.D, true, true);
                    //var p = new BigInteger(rsaParams.P, true, true);
                    //var q = new BigInteger(rsaParams.Q, true, true);
                    //var e = new BigInteger(rsaParams.Exponent, true, true);
                    //var iq = new BigInteger(rsaParams.InverseQ, true, true);
                    // Эти записи эквивалентны, но верхний конструктор доступен тольок в netcore 2.1+
                    var d = new BigInteger(AsymmetricKeyHelpers.CopyAndReverse(D));
                    var p = new BigInteger(AsymmetricKeyHelpers.CopyAndReverse(P));
                    var q = new BigInteger(AsymmetricKeyHelpers.CopyAndReverse(Q));
                    var e = new BigInteger(AsymmetricKeyHelpers.CopyAndReverse(Exponent));

                    // DP = D mod(P - 1)
                    // DQ = D mod(Q - 1)

                    var dp = d % (p - 1);
                    var dq = d % (q - 1);

                    DP = AsymmetricKeyHelpers.CopyAndReverse(dp.ToByteArray());  // какого хрена эти не совпадают ?
                    DQ = AsymmetricKeyHelpers.CopyAndReverse(dq.ToByteArray());
                }
            }
        }
    }
}
