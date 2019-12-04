using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Siginig.Library
{
    class Canonicalize
    {
        public static string XmlHash(XmlDocument myDoc, string algorithm = "sha256")
        {
            byte[] hash;
            Stream stream = GetCanonicalStreamFromXML(myDoc);

            switch(algorithm.ToLower())
            {
                case ("sha1"): {
                        SHA1 hashAlgorithm = SHA1.Create();
                        hash = hashAlgorithm.ComputeHash(stream);
                        //Sha1Digest digest = new Sha1Digest();
                        break;
                    }
                case ("sha256"): {
                        SHA256 hashAlgorithm = SHA256.Create();
                        hash = hashAlgorithm.ComputeHash(stream);
                        //Sha256Digest digest = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
                        break;
                    }
                case ("sha384"): {      //need implementation
                        SHA256 hashAlgorithm = SHA256.Create();
                        hash = hashAlgorithm.ComputeHash(stream);
                        //Sha384Digest digest = new Sha384Digest();
                        break;
                    }
                case ("sha512"): {      //need implementation
                        SHA256 hashAlgorithm = SHA256.Create();
                        hash = hashAlgorithm.ComputeHash(stream);
                        //Sha512Digest digest = new Sha512Digest();
                        break;
                    }
                default: {      //need implementation
                        throw new ArgumentException("Given Hashing Algorithm Not Supported", "original");
                        break;
                    }
            }
            stream.Close();
            return Convert.ToBase64String(hash);
        }

        public static Stream GetCanonicalStreamFromXML(XmlDocument xmlDoc)  //C14N
        {
            XmlDsigC14NTransform transformData = new XmlDsigC14NTransform();
            transformData.LoadInput(xmlDoc);
            return (Stream)transformData.GetOutput(typeof(Stream));
        }

        public static string GetSha256FromStream(string input)
        {
            byte[] data = System.Text.Encoding.UTF8.GetBytes(input);
            Sha256Digest hash = new Sha256Digest();
            hash.BlockUpdate(data, 0, data.Length);
            byte[] result = new byte[hash.GetDigestSize()];
            hash.DoFinal(result, 0);
            return Hex.ToHexString(result);
        }
    }
}
