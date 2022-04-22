using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace GMax.Security
{
    internal static class AsymmetricKeyHelpers
    {
        internal static byte[] ReadWithLength(BinaryReader reader, bool skipFirstNull = false)
        {
            var length = BitConverter.ToInt32(reader.ReadBytes(4).Reverse().ToArray(), 0);
            byte[] buffer;
            if (skipFirstNull)
            {
                buffer = new byte[length - 1];
                reader.Read(buffer, 0, 1);
                reader.Read(buffer, 0, length - 1);
            }
            else
            {
                buffer = new byte[length];
                reader.Read(buffer, 0, length);
            }
            return buffer;
        }

        // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-sequence
        // https://github.com/dotnet/corefx/blob/07e9caf00ea0f1893d4c25a5ee287000903fbbe2/src/Common/src/System/Security/Cryptography/DerEncoder.cs
        internal static void WriteASN1Tag(BinaryWriter writer, byte tagId, Action<BinaryWriter> contentWriter)
        {
            writer.Write(tagId);
            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms, Encoding.ASCII, true))
                {
                    contentWriter(bw);
                }
                WriteASN1EncodedLength(writer, (int)ms.Length);
                writer.Write(ms.ToArray(), 0, (int)ms.Length);
            }
        }

        internal static void WriteWithLength(BinaryWriter writer, byte[] bytes, bool addLeadingNull = false)
        {
            writer.Write(BitConverter.GetBytes(bytes.Length + (addLeadingNull ? 1 : 0)).Reverse().ToArray());
            if (addLeadingNull)
                writer.Write(new byte[] { 0x00 });
            writer.Write(bytes);
        }

        internal static byte[] CopyAndReverse(byte[] data)
        {
            byte[] reversed = new byte[data.Length];
            Array.Copy(data, 0, reversed, 0, data.Length);
            Array.Reverse(reversed);
            return reversed;
        }
        internal static byte[] FixLength(byte[] data)
        {
            // remove leading 0, RSA dowsn't like it
            if (data.Length % 2 == 1)
                return data.Skip(1).ToArray();
            else
                return data;
        }

        // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-bit-string
        internal static void WriteASN1BitString(BinaryWriter writer, byte[] value, byte unusedBits = 0)
        {
            writer.Write((byte)0x03); // BIT STRING
            WriteASN1EncodedLength(writer, value.Length + 1);
            writer.Write(unusedBits); // unused bits
            writer.Write(value);
        }

        // https://stackoverflow.com/a/23739932/2860309
        internal static void WriteASN1EncodedLength(BinaryWriter writer, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                writer.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                writer.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    writer.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }

        // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
        internal static void WriteASN1Integer(BinaryWriter writer, byte[] value, bool forceUnsigned = true)
        {
            writer.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                WriteASN1EncodedLength(writer, 1);
                writer.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    WriteASN1EncodedLength(writer, value.Length - prefixZeros + 1);
                    writer.Write((byte)0);
                }
                else
                {
                    WriteASN1EncodedLength(writer, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    writer.Write(value[i]);
                }
            }
        }

        // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-octet-string
        internal static void WriteASN1OctetString(BinaryWriter writer, byte[] value)
        {
            writer.Write((byte)0x04); // OCTET STRING
            WriteASN1EncodedLength(writer, value.Length);
            writer.Write(value);
        }

        internal static void WriteASN1OidCompiled(BinaryWriter writer, byte[] value)
        {
            // now it just as octet string
            writer.Write((byte)0x06); // OBJECT IDENTIFIER
            WriteASN1EncodedLength(writer, value.Length);
            writer.Write(value);
        }

        // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
        internal static void WriteASN1OidGeneric(BinaryWriter writer, int[] value)
        {
            Debug.Assert(value.Length > 2);

            writer.Write((byte)0x06); // OBJECT IDENTIFIER

            using (var ms = new MemoryStream())
            {
                using (var bw = new BinaryWriter(ms))
                {
                    byte v1 = (byte)((value[0] & 127) * 40 + (value[1] & 127));
                    bw.Write(v1);
                    for (int i = 2; i < value.Length; i++)
                    {
                        if (value[i] <= 127)
                        {
                            bw.Write((byte)value[i]);
                        }
                        else
                        {
                            var val = value[i];
                            Stack<byte> littleEndianBytes = new Stack<byte>();
                            byte continuance = 0;
                            do
                            {
                                int remainder;
                                remainder = val % 128;
                                val /= 128;

                                byte octet = (byte)remainder;
                                octet |= continuance;
                                // Any remaining (preceding) bytes need the continuance bit set.
                                continuance = 0x80;

                                littleEndianBytes.Push(octet);
                            }
                            while (val != 0);
                            bw.Write(littleEndianBytes.ToArray());
                        }
                    }
                    var bytes = ms.ToArray();
                    WriteASN1EncodedLength(writer, bytes.Length);
                    writer.Write(bytes);
                }
            }
        }
    }
}