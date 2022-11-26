using System;
using System.IO;
using System.Security.Cryptography;
using Bit.Core.Models.Domain;

namespace Bit.Core.Utilities
{
    /// <summary>
    /// This utility provides Pkcs8 decoding capability for .Net Core < 3.1
    /// In Core 3.1 the RSACryptoServiceProvider recieves the method
    /// ImportPkcs8PrivateKey which in all likelyhood deprecates the need for this.
    /// </summary>
    public static class RsaPkcs8
    {
        // Encoded OID sequence for PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
        // as per CRYPT_ALGORITHM_IDENTIFIER structure (wincrypt.h). This byte array includes the
        // sequence byte and terminating encoded null.
        private readonly static byte[] SEQ_OID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

        public struct PemDemark
        {
            public readonly string H;
            public readonly string F;

            public PemDemark(string head, string foot)
            {
                H = head;
                F = foot;
            }
        }

        public static PemDemark PEM_CERTIFICATE = new PemDemark(
            "-----BEGIN CERTIFICATE-----",
            "-----END CERTIFICATE-----"
        );

        public static PemDemark PEM_PRIVATE_KEY = new PemDemark(
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----"
        );

        public static RSACryptoServiceProvider DecodePkcs8PrivateKey(byte[] pkcs8)
        {
            byte[] seq = new byte[SEQ_OID.Length];
            // ---------  Read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            MemoryStream mem = new MemoryStream(pkcs8);
            int streamLen = (int)mem.Length;
            BinaryReader br = new BinaryReader(mem);
            byte bt = 0;
            ushort twoBytes = 0;

            try
            {
                twoBytes = br.ReadUInt16();
                if (twoBytes == 0x8130) // data read as little endian order (actual data order for Sequence is 30 81)
                    br.ReadByte();
                else if (twoBytes == 0x8230)
                    br.ReadInt16();
                else
                    return null;

                bt = br.ReadByte();
                if (bt != 0x02)
                    return null;

                twoBytes = br.ReadUInt16();

                if (twoBytes != 0x0001)
                    return null;

                seq = br.ReadBytes(SEQ_OID.Length);
                if (!CompareBytearrays(seq, SEQ_OID))
                    return null;

                bt = br.ReadByte();
                if (bt != 0x04) // expect an octet string
                    return null;

                bt = br.ReadByte();       // read next byte, or next 2 bytes is 0x81 or 0x82; otherwise bt is the byte count
                if (bt == 0x81)
                    br.ReadByte();
                else
                 if (bt == 0x82)
                    br.ReadUInt16();

                // ------ At this stage, the remaining sequence should be the RSA private key
                byte[] rsaprivkey = br.ReadBytes((int)(streamLen - mem.Position));
                return DecodeRSAPrivateKey(rsaprivkey);
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                br.Close();
            }
        }

        public static byte[] DecodePemCertificate(string certificate)
        {
            return Convert.FromBase64String(StripHeaderFooter(certificate, PEM_CERTIFICATE.H, PEM_CERTIFICATE.F));
        }

        public static byte[] DecodePemPrivateKey(string privateKey)
        {
            return Convert.FromBase64String(StripHeaderFooter(privateKey, PEM_PRIVATE_KEY.H, PEM_PRIVATE_KEY.F));
        }

        public static bool AppearsAsPemCertificate(string certificate)
        {
            return HasHeaderFooter(certificate, PEM_CERTIFICATE.H, PEM_CERTIFICATE.F);
        }

        public static bool AppearsAsPemPrivateKey(string privateKey)
        {
            return HasHeaderFooter(privateKey, PEM_PRIVATE_KEY.H, PEM_PRIVATE_KEY.F);
        }

        private static string StripHeaderFooter(string pem, string header, string footer)
        {
            return pem.Replace(header, null).Replace(footer, null);
        }

        private static bool HasHeaderFooter(string pem, string header, string footer)
        {
            return pem.Contains(header) && pem.Contains(footer);
        }

        private static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
        {
            byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

            // --------- Set up stream to decode the asn.1 encoded RSA private key ------
            MemoryStream mem = new MemoryStream(privkey);
            BinaryReader br = new BinaryReader(mem);
            byte bt = 0;
            ushort twoBytes = 0;
            int elems = 0;
            try
            {
                twoBytes = br.ReadUInt16();
                if (twoBytes == 0x8130) // data read as little endian order (actual data order for Sequence is 30 81)
                    br.ReadByte();
                else if (twoBytes == 0x8230)
                    br.ReadInt16();
                else
                    return null;

                twoBytes = br.ReadUInt16();
                if (twoBytes != 0x0102) // version number
                    return null;
                bt = br.ReadByte();
                if (bt != 0x00)
                    return null;

                // Algorthim type

                // All private key components are integer sequences
                elems = GetIntegerSize(br);
                MODULUS = br.ReadBytes(elems);

                elems = GetIntegerSize(br);
                E = br.ReadBytes(elems);

                elems = GetIntegerSize(br);
                D = br.ReadBytes(elems);

                elems = GetIntegerSize(br);
                P = br.ReadBytes(elems);

                elems = GetIntegerSize(br);
                Q = br.ReadBytes(elems);

                elems = GetIntegerSize(br);
                DP = br.ReadBytes(elems);

                elems = GetIntegerSize(br);
                DQ = br.ReadBytes(elems);

                elems = GetIntegerSize(br);
                IQ = br.ReadBytes(elems);

                CspParameters CspParameters = new CspParameters();
                CspParameters.Flags = CspProviderFlags.UseDefaultKeyContainer;
                RSACryptoServiceProvider RSA = new RSACryptoServiceProvider(1024, CspParameters);
                RSAParameters RSAparams = new RSAParameters();

                RSAparams.Modulus = MODULUS;
                RSAparams.Exponent = E;
                RSAparams.D = D;
                RSAparams.P = P;
                RSAparams.Q = Q;
                RSAparams.DP = DP;
                RSAparams.DQ = DQ;
                RSAparams.InverseQ = IQ;
                RSA.ImportParameters(RSAparams);
                return RSA;
            }
            catch (Exception)
            {
                return null;
            }
            finally
            {
                br.Close();
            }
        }

        private static int GetIntegerSize(BinaryReader br)
        {
            byte bt = 0;
            var count = 0;

            bt = br.ReadByte();
            if (bt != 0x02)
                return 0;

            bt = br.ReadByte();
            if (bt == 0x81)
            {
                count = br.ReadByte();
            }
            else
            {
                if (bt == 0x82)
                {
                    var highbyte = br.ReadByte();
                    var lowbyte = br.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;
                }
            }

            while (br.ReadByte() == 0x00)
            {
                count -= 1;
            }
            br.BaseStream.Seek(-1, SeekOrigin.Current);

            return count;
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                return false;
            int i = 0;
            foreach (byte c in a)
            {
                if (c != b[i])
                    return false;
                i++;
            }
            return true;
        }
    }
}
