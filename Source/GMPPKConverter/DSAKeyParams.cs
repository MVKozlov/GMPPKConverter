using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GMax.Security
{
    internal class DSAKeyParams : AsymmetricKeyParams
    {
        public DSAKeyParams(string Algorithm) : base(Algorithm)
        {
        }

        public byte[] X { get; set; }
        public byte[] Y { get; set; }
        public byte[] P { get; set; }
        public byte[] Q { get; set; }
        public byte[] G { get; set; }

        public override void ExportPrivateKeyAsASN1(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.WriteASN1Integer(bw, new byte[] { 0x00 }); // Version
            AsymmetricKeyHelpers.WriteASN1Integer(bw, P);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, Q);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, G);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, Y);
            AsymmetricKeyHelpers.WriteASN1Integer(bw, X);
        }

        public override void ExportPrivateKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.
                        ////put_mp_ssh2(bs, dsa->x);
                        ////
                        //put_mp_ssh2(bs, dsa->p);
                        //314     put_mp_ssh2(bs, dsa->q);
                        //315     put_mp_ssh2(bs, dsa->g);
                        //316     put_mp_ssh2(bs, dsa->y);
                        //317     put_mp_ssh2(bs, dsa->x);
                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, P);
            AsymmetricKeyHelpers.WriteWithLength(bw, Q);
            AsymmetricKeyHelpers.WriteWithLength(bw, G);
            AsymmetricKeyHelpers.WriteWithLength(bw, Y);
            AsymmetricKeyHelpers.WriteWithLength(bw, X);
        }

        public override void ExportPublicKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.
                        // https://git.tartarus.org/?p=simon/putty.git;a=blob;f=crypto/dsa.c;hb=faf1601a5549eda9298f72f7c0f68f39c8f97764
                        //put_stringz(bs, "ssh-dss");
                        //221     put_mp_ssh2(bs, dsa->p);
                        //222     put_mp_ssh2(bs, dsa->q);
                        //223     put_mp_ssh2(bs, dsa->g);
                        //224     put_mp_ssh2(bs, dsa->y);
                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, P);
            AsymmetricKeyHelpers.WriteWithLength(bw, Q);
            AsymmetricKeyHelpers.WriteWithLength(bw, G);
            AsymmetricKeyHelpers.WriteWithLength(bw, Y);
        }

        public override void ImportKeyParamsFromPPK(byte[] publicData, byte[] privateData)
        {
            //Helpers.Dump("publicData", publicData);
            //Helpers.Dump("privateData", privateData);

            using (var ms = new MemoryStream(publicData))
            {
                using (var br = new BinaryReader(ms))
                {
                    AsymmetricKeyHelpers.ReadWithLength(br); // alg. name ssh-dss
                    P = AsymmetricKeyHelpers.ReadWithLength(br);
                    Q = AsymmetricKeyHelpers.ReadWithLength(br);
                    G = AsymmetricKeyHelpers.ReadWithLength(br);
                    Y = AsymmetricKeyHelpers.ReadWithLength(br);
                }
            }

            using (var ms = new MemoryStream(privateData))
            {
                using (var br = new BinaryReader(ms))
                {
                    X = AsymmetricKeyHelpers.ReadWithLength(br);
                }
            }
        }
    }
}
