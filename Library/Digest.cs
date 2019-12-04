using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Siginig.Library
{
    class Digest
    {
        private static X509Certificate2Collection storedSelectedCert = null;
        public static ICollection<string> GetCertChainFromAlias()
        {
            ICollection<X509Certificate> x509CertList = GetCertChainCollectionFromAlias();
            ICollection<string> certHexStringList = new List<string>();
            foreach (X509Certificate x509Cert in x509CertList)
            {
                string x509CertToHexString = x509Cert.GetRawCertDataString();
                certHexStringList.Add(x509CertToHexString);
            }
            return certHexStringList;
        }

        private static ICollection<X509Certificate> GetCertChainCollectionFromAlias()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

            store.Open(OpenFlags.ReadOnly);

            // If you get compilation error after on X509Certificate2UI class, then Project->Add Reference -> Add System.Security 
            X509Certificate2Collection selectedCert = X509Certificate2UI.SelectFromCollection(store.Certificates, null, null, X509SelectionFlag.SingleSelection);
            storedSelectedCert = selectedCert;
            //Org.BouncyCastle.X509.X509Certificate[] chain = null;
            ICollection<X509Certificate> certChain = new List<X509Certificate>();

            /*
            Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
            chain = new Org.BouncyCastle.X509.X509Certificate[] {
                 cp.ReadCertificate(certificate.RawData)};
            foreach (Org.BouncyCastle.X509.X509Certificate c in chain)
                Console.WriteLine(c);
                */

            X509Chain ch = new X509Chain();
            try {
                ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                ch.Build(selectedCert[0]);
                X509ChainElementCollection chainElems = ch.ChainElements;
            } catch(Exception exception) {
                throw exception;
            }
            

            foreach (X509ChainElement element in ch.ChainElements)
            {
                //element.Certificate
                //cp.ReadCertificate(element.Certificate.RawData);
                X509Certificate x509cert = new X509Certificate(element.Certificate.RawData);


                certChain.Add(x509cert);
                Console.WriteLine("Element Subject: {0}", element.Certificate.Subject);
                Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);


                if (ch.ChainStatus.Length > 1)
                {
                    for (int index = 0; index < element.ChainElementStatus.Length; index++)
                    {
                        Console.WriteLine(element.ChainElementStatus[index].Status);
                        Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                    }
                }
            }
            return certChain;
        }

        public static byte[] SignXmlDigest(byte[] dataToSign)
        {
            X509Certificate2Collection collectionCert2s = GetCertCollectionOfChainFromPreviouslySelectedCert();
            Console.WriteLine(collectionCert2s[0].SignatureAlgorithm.FriendlyName);
            if (collectionCert2s[0].SignatureAlgorithm.FriendlyName.Equals("sha1RSA"))
            {
                Console.WriteLine(collectionCert2s[0].SignatureAlgorithm.FriendlyName.Equals("sha1RSA"));
            }
            // string oid = CryptoConfig.MapNameToOID("SHA256");

          //  String hashAlgorithm = "SHA1"; // "SHA-256"
                                           //String hashAlgorithm = "SHA-256"; // "SHA-256"
            // IExternalSignature signature = new X509Certificate2Signature(collectionCert2s[0], hashAlgorithm);
            CmsSigner cmsSigner = new CmsSigner(collectionCert2s[0]);
            ContentInfo contentInfo = new ContentInfo(dataToSign);
            SignedCms signedCms = new SignedCms(contentInfo, true);
          //  CmsSigner cmsSigner = new CmsSigner(cert);
            cmsSigner.SignerIdentifierType = SubjectIdentifierType.IssuerAndSerialNumber;

            signedCms.ComputeSignature(cmsSigner, false);
            return signedCms.Encode();
        }

        private static X509Certificate2Collection GetCertCollectionOfChainFromPreviouslySelectedCert()
        {
            /*X509Chain ch = new X509Chain();
            ch.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            ch.Build(storedSelectedCert[0]);
            X509ChainElementCollection chainElems = ch.ChainElements;
            X509Certificate2Collection collection = new X509Certificate2Collection();
            foreach (X509ChainElement element in ch.ChainElements)
            {
                //element.Certificate
                //cp.ReadCertificate(element.Certificate.RawData);
                X509Certificate2 x509cert = new X509Certificate2(element.Certificate.RawData);


                collection.Add(x509cert);
               
            }
            return collection;
            */
            return storedSelectedCert;
        }

        public static byte[] GetDataToSignByteStreamFromFilePath(string filePath)
        {
            // get the digest from server
            FileStream stream = File.OpenRead(filePath);
            byte[] dataToSign = new byte[stream.Length];

            stream.Read(dataToSign, 0, dataToSign.Length);
            stream.Close();
            return dataToSign;
        }

        public static string ComputeSha256Hash(byte[] bytes)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                //byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));  //string rawData

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
