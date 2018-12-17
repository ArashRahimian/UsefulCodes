#region

using System;
using System.Collections;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using Diten.Security.Cryptography;

#endregion

namespace Diten.Security
{
    public class Key
    {
        /// <summary>
        ///     Length types for generating key.
        /// </summary>
        public enum LengthTypes
        {
            K16 = 16,
            K32 = 32,
            K64 = 64,
            K128 = 128,
            K256 = 256,
            K512 = 512,
            K768 = 768,
            K1024 = 1024,
            K2048 = 2048,
            K4094 = 4096,
            K8192 = 8192,
            K16384 = 16384
        }

        private Random _random;

        private byte[] _value;

        public Key(string key)
        {
            Value = Decrypt(key);
        }

        /// <summary>
        ///     Constructor.
        /// </summary>
        /// <param name="length" default="512 bytes key">Length of the ke that must be generated.</param>
        public Key(LengthTypes length = LengthTypes.K512)
        {
            LengthType = length;
        }

        /// <summary>
        ///     Length of the key value.
        /// </summary>
        public int Length => Value.Length;

        private LengthTypes LengthType { get; }

        private Random Random => _random ?? (_random = new Random());

        /// <summary>
        ///     Value of the key.
        /// </summary>
        public byte[] Value
        {
            get
            {
                byte[] Output()
                {
                    var holder = new byte[(int) LengthType * 2];

                    for (var i = 0; i <= holder.Length - 1; i++)
                        holder[i] += BitConverter.GetBytes(Random.Next(0, 255))[0];

                    return holder;
                }

                return _value ?? (_value = Output());
            }
            set => _value = value;
        }

        /// <summary>
        ///     Overlay a key on current value.
        /// </summary>
        /// <param name="value">The key that must be overlaid.</param>
        /// <returns>A key.</returns>
        public Key Apply(Key value)
        {
            Task.Factory.StartNew(() =>
            {
                var val = Task.Factory.StartNew(() => value.Value);

                for (var i = 0; i < val.Result.Length; i += 4)
                {
                    var tmp1 = new short[4];
                    var tmp2 = new short[4];

                    for (var j = 0; j < 4; j++)
                    {
                        tmp1[j] = Value[i + j];
                        tmp2[j] = (short) Random.Next(0, 255);
                    }

                    using (var tmpBitmap1 = new Bitmap(1, 1))
                    {
                        tmpBitmap1.SetPixel(0, 0, Color.FromArgb(tmp1[0], tmp1[1], tmp1[2], tmp1[3]));

                        using (var tmpBitmap2 = new Bitmap(1, 1))
                        {
                            tmpBitmap1.SetPixel(0, 0,
                                Color.FromArgb(tmp2[0], tmp2[1], tmp2[2], tmp2[3]));
                            Graphics.FromImage(tmpBitmap1).DrawImageUnscaled(tmpBitmap2, 0, 0);
                            var color = tmpBitmap1.GetPixel(0, 0);
                            Value[i] = color.A;
                            Value[i + 1] = color.R;
                            Value[i + 2] = color.G;
                            Value[i + 3] = color.B;
                        }
                    }
                }
            });

            return this;
        }

        /// <summary>
        ///     Decrypting received key.
        /// </summary>
        /// <param name="value">Base64Text encrypted text.</param>
        /// <returns>A byte array.</returns>
        public static byte[] Decrypt(string value)
        {
            return Convert.ToBytes(
                new GZipStream(new MemoryStream(Encoding.Unicode.GetBytes(Rc4.Decrypt(
                        Encoding
                            .Unicode
                            .GetBytes(ConstVariables
                                .SystemDefaultPassword),
                        Encoding
                            .Unicode
                            .GetBytes(Base64Text
                                .Decrypt(value))))),
                    CompressionMode.Decompress).BaseStream);
        }

        /// <summary>
        ///     Encrypt current value of the key.
        /// </summary>
        /// <returns>A Base64Text encrypted text.</returns>
        public string Encrypt()
        {
            return
                Base64Text.Encrypt(Rc4
                    .Encrypt(Encoding.Unicode.GetBytes(ConstVariables.SystemDefaultPassword),
                        Convert.ToBytes(new GZipStream(new MemoryStream(Value),
                                CompressionMode.Compress)
                            .BaseStream)));
        }

        /// <summary>
        ///     Control equality with a key.
        /// </summary>
        /// <param name="value">Source key to control.</param>
        /// <returns>True if the source key is equal.</returns>
        public bool Equals(Key value)
        {
            return Equals(value, this);
        }

        /// <summary>
        ///     Control equality between two keys.
        /// </summary>
        /// <param name="primary">Primary key to control.</param>
        /// <param name="secondary">Secondary key to control.</param>
        /// <returns>True if the keys are equal.</returns>
        public bool Equals(Key primary,
            Key secondary)
        {
            return StructuralComparisons.StructuralEqualityComparer.Equals(primary.Value, secondary.Value);
        }

        /// <summary>
        ///     Converting ke to hex.
        /// </summary>
        /// <returns>A hex string number.</returns>
        public string ToHex()
        {
            return Convert.ToHex(BitConverter.ToInt32(Value, 0));
        }
    }
}