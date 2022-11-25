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
            // encoded OID sequence for PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            // this byte[] includes the sequence byte and terminal encoded null 
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] seq = new byte[15];
            // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
            MemoryStream mem = new MemoryStream(pkcs8);
            int lenstream = (int)mem.Length;
            BinaryReader binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;

            try
            {

                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();   //advance 2 bytes
                else
                    return null;


                bt = binr.ReadByte();
                if (bt != 0x02)
                    return null;

                twobytes = binr.ReadUInt16();

                if (twobytes != 0x0001)
                    return null;

                seq = binr.ReadBytes(15);       //read the Sequence OID
                if (!CompareBytearrays(seq, SeqOID))    //make sure Sequence for OID is correct
                    return null;

                bt = binr.ReadByte();
                if (bt != 0x04) //expect an Octet string 
                    return null;

                bt = binr.ReadByte();       //read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
                if (bt == 0x81)
                    binr.ReadByte();
                else
                 if (bt == 0x82)
                    binr.ReadUInt16();
                //------ at this stage, the remaining sequence should be the RSA private key

                byte[] rsaprivkey = binr.ReadBytes((int)(lenstream - mem.Position));
                RSACryptoServiceProvider rsacsp = DecodeRSAPrivateKey(rsaprivkey);
                return rsacsp;
            }

            catch (Exception)
            {
                return null;
            }

            finally { binr.Close(); }

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
            BinaryReader binr = new BinaryReader(mem);  //wrap Memory Stream with BinaryReader for easy reading
            byte bt = 0;
            ushort twobytes = 0;
            int elems = 0;
            try
            {
                twobytes = binr.ReadUInt16();
                if (twobytes == 0x8130) //data read as little endian order (actual data order for Sequence is 30 81)
                    binr.ReadByte();    //advance 1 byte
                else if (twobytes == 0x8230)
                    binr.ReadInt16();    //advance 2 bytes
                else
                    return null;

                twobytes = binr.ReadUInt16();
                if (twobytes != 0x0102) //version number
                    return null;
                bt = binr.ReadByte();
                if (bt != 0x00)
                    return null;

                // algorthim type

                // All private key components are integer sequences
                elems = GetIntegerSize(binr);
                MODULUS = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                E = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                D = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                P = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                Q = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DP = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                DQ = binr.ReadBytes(elems);

                elems = GetIntegerSize(binr);
                IQ = binr.ReadBytes(elems);

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
            catch (Exception ex)
            {
                Console.WriteLine("ex1 :" + ex);
                return null;
            }
            finally
            {
                binr.Close();
            }
        }

        private static int GetIntegerSize(BinaryReader binary)
        {
            byte bt = 0;
            var count = 0;

            bt = binary.ReadByte();
            if (bt != 0x02)
                return 0;

            bt = binary.ReadByte();
            if (bt == 0x81)
            {
                count = binary.ReadByte();
            }
            else
            {
                if (bt == 0x82)
                {
                    var highbyte = binary.ReadByte();
                    var lowbyte = binary.ReadByte();
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    count = BitConverter.ToInt32(modint, 0);
                }
                else
                {
                    count = bt;
                }
            }

            while (binary.ReadByte() == 0x00)
            {
                count -= 1;
            }
            binary.BaseStream.Seek(-1, SeekOrigin.Current);

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