using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GMax.Security
{
    internal class EDDSAKeyParams : AsymmetricKeyParams
    {
        public EDDSAKeyParams(string Algorithm) : base(Algorithm)
        {
        }
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }

        public override void ExportPrivateKeyAsASN1(BinaryWriter bw)
        {
            throw new NotImplementedException("ExportOpenSSH should be used");
        }

        public override void ExportPrivateKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.
                        ////put_mp_le_fixedlen(bs, ek->privateKey, ek->curve->fieldBytes);
                        ////
                        //* Encode the public and private points as strings */
                        //883     strbuf* pub_sb = strbuf_new();
                        //884     put_epoint(pub_sb, ek->publicKey, ek->curve, false);
                        //885     ptrlen pub = make_ptrlen(pub_sb->s + 4, pub_sb->len - 4);
                        //886
                        //887     strbuf* priv_sb = strbuf_new_nm();
                        //888     put_mp_le_fixedlen(priv_sb, ek->privateKey, ek->curve->fieldBytes);
                        //889     ptrlen priv = make_ptrlen(priv_sb->s + 4, priv_sb->len - 4);
                        //890
                        //891     put_stringpl(bs, pub);
                        //892
                        //893     /* Encode the private key as the concatenation of the
                        //894      * little-endian key integer and the public key again */
                        //895     put_uint32(bs, priv.len + pub.len);
                        //896     put_datapl(bs, priv);
                        //897     put_datapl(bs, pub);
                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, PublicKey);
            using (var ms = new MemoryStream())
            {
                ms.Write(PrivateKey, 0, PrivateKey.Length);
                ms.Write(PublicKey, 0, PublicKey.Length);
                AsymmetricKeyHelpers.
                                WriteWithLength(bw, ms.ToArray());
            }            
        }

        public override void ExportPublicKeyAsOpenSSH(BinaryWriter bw)
        {
            AsymmetricKeyHelpers.
                        // https://git.tartarus.org/?p=simon/putty.git;a=blob;f=crypto/ecc-ssh.c;hb=faf1601a5549eda9298f72f7c0f68f39c8f97764
                        //put_stringz(bs, ek->sshk.vt->ssh_id);
                        //778     put_epoint(bs, ek->publicKey, ek->curve, false);
                        WriteWithLength(bw, Encoding.ASCII.GetBytes(Algorithm));
            AsymmetricKeyHelpers.WriteWithLength(bw, PublicKey);
        }

        public override void ImportKeyParamsFromPPK(byte[] publicData, byte[] privateData)
        {
            using (var ms = new MemoryStream(publicData))
            {
                using (var br = new BinaryReader(ms))
                {
                    AsymmetricKeyHelpers.ReadWithLength(br); // alg. name ssh-ed25519/ssh-ed448
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
