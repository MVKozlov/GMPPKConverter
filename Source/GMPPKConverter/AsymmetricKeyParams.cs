using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace GMax.Security
{
    internal interface IAsymmetricKeyParams
    {
        void ImportKeyParamsFromPPK(byte[] publicData, byte[] privateData);
        void ExportPublicKeyAsOpenSSH(BinaryWriter bw);
        void ExportPrivateKeyAsOpenSSH(BinaryWriter bw);
        void ExportPrivateKeyAsASN1(BinaryWriter bw);
    }
    internal abstract class AsymmetricKeyParams : IAsymmetricKeyParams
    {
        public string Algorithm { get; set; }

        public AsymmetricKeyParams(string Algorithm)
        {
            this.Algorithm = Algorithm;
        }

        public abstract void ImportKeyParamsFromPPK(byte[] publicData, byte[] privateData);
        public abstract void ExportPublicKeyAsOpenSSH(BinaryWriter bw);
        public abstract void ExportPrivateKeyAsOpenSSH(BinaryWriter bw);
        public abstract void ExportPrivateKeyAsASN1(BinaryWriter bw);

    }
}
