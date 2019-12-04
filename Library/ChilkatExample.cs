using System.Diagnostics;

namespace Siginig.Library
{
    class ChilkatExample
    {
        public static void Sign()
        {
            //  This example requires the Chilkat API to have been previously unlocked.
            //  See Global Unlock Sample for sample code.

            //  The SOAP XML to be signed in this example contains the following:

            //  <?xml version="1.0" encoding="UTF-8" standalone="no" ?>
            //  <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
            //      <SOAP-ENV:Header>
            //          <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" SOAP-ENV:mustUnderstand="1"></wsse:Security>
            //      </SOAP-ENV:Header>
            //      <SOAP-ENV:Body xmlns:SOAP-SEC="http://schemas.xmlsoap.org/soap/security/2000-12" SOAP-SEC:id="Body">
            //          <z:FooBar xmlns:z="http://example.com" />
            //      </SOAP-ENV:Body>
            //  </SOAP-ENV:Envelope>
            // 

            //  The above XML is available at https://www.chilkatsoft.com/exampleData/soapToSign.xml
            //  Fetch the XML and then sign it..

            string url = "https://www.chilkatsoft.com/exampleData/soapToSign.xml";
            Chilkat.Http http = new Chilkat.Http();
            Chilkat.StringBuilder sbSoapXml = new Chilkat.StringBuilder();
            bool success = http.QuickGetSb(url, sbSoapXml); //Not Working
            if (success != true)
            {
                Debug.WriteLine(http.LastErrorText);
                return;
            }

            //  Load a PFX file containing the certificate + private key.
            Chilkat.Cert cert = new Chilkat.Cert();
            success = cert.LoadPfxFile("E:\\XML\\keystore-demo\\certificate-sha256.pfx", "1234567890");
            if (success != true)
            {
                Debug.WriteLine(cert.LastErrorText);
                return;
            }

            //  Get the RSA private key for signing...
            Chilkat.PrivateKey rsaKey = cert.ExportPrivateKey();
            if (cert.LastMethodSuccess != true)
            {
                Debug.WriteLine(cert.LastErrorText);
                return;
            }

            //  To create the XML digital signature (i.e. embed the signature within
            //  the SOAP XML), we specify what is desired, and then call the method to
            //  create the XML signature.
            // 
            //  For example, the application must provide the following:
            //      - Where to put the signature.
            //      - What to sign.
            //      - The algorithms to be used.
            //      - The key to be used for signing.
            // 

            Chilkat.XmlDSigGen xmlSigGen = new Chilkat.XmlDSigGen();

            //  In this example, we're going to put the signature within the wsse:Security element.
            //  To specify the location, set the SigLocation property to the XML path to this element,
            //  using vertical bar characters to separate tags.
            xmlSigGen.SigLocation = "SOAP-ENV:Envelope|SOAP-ENV:Header|wsse:Security";

            //  An XML digital signature contains one or more references.  These are references to the parts
            //  of the XML document to be signed (a same document reference), or can be external references.
            //  This example will add a single same-document reference.  We'll add a reference to the XML fragment
            //  at SOAP-ENV:Body, which is indicated by providing the value of the "ID" attribute (where "ID" is case
            //  insensitive).  For each same-document reference, we must also indicate the hash algorithm and XML canonicalization
            //  algorithm to be used.  For this example we'll choose SHA-256 and Exclusive XML Canonicalization.
            xmlSigGen.AddSameDocRef("Body", "sha256", "EXCL_C14N", "", "");

            //  Let's provide the RSA key to be used for signing:
            xmlSigGen.SetPrivateKey(rsaKey);

            //  We're leaving the following properties at their default values:
            // 
            //     - SigNamespacePrefix (default is "ds")
            //     - SigningAlg (for RSA keys. The default is PKCS1-v1_5, can be changed to RSASSA-PSS.)
            //     - SignedInfoCanonAlg  (default is EXCL_C14N)
            //     - SignedInfoDigestMethod (default is sha256)
            //     - KeyInfoType (default is "KeyValue", where the RSA public key is included in the Signature)

            //  Note: Each Reference has it's own specified algorithms for XML canonicalization and hashing,
            //  and the actual signature part (the SignedInfo) has it's own algorithms for the same.
            //  They may or may not be the same.  In this example, we use Exclusive XML Canonicalization and SHA-256 throughout.

            //  Finally, we're going to set one property that's optional, but commonly used.
            //  It's the SignedInfoPrefixList.  In this case, we're using Exclusive Canonicalization, and the signature
            //  will be placed in a location within the XML document where namespace prefixes are used in the ancestors.
            //  Specifically, the "wsse" and "SOAP-ENV" namespace prefixes are used.
            xmlSigGen.SignedInfoPrefixList = "wsse SOAP-ENV";

            //  OK, everything's specified, so let's create the XML digital signature:
            //  This in-place signs the XML.  If successful, sbSoapXml will contain the
            //  XML with the digital signature at the specified location.
            success = xmlSigGen.CreateXmlDSigSb(sbSoapXml);
            if (success != true)
            {
                Debug.WriteLine(xmlSigGen.LastErrorText);
                return;
            }

            //  Examine the signed SOAP XML:
            Debug.WriteLine(sbSoapXml.GetAsString());

            //  This is the signed SOAP XML.
            //  Chilkat emits the Signature in compact form on a single line.  Whitespace in XML signatures
            //  matters.  Chilkat's opinion is that writing the Signature without whitespace minimizes the chance
            //  for problems with whatever software might be verifying the signature.

            //  <?xml version="1.0" encoding="UTF-8" standalone="no" ?>
            //  <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">
            //      <SOAP-ENV:Header>
            //          <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" SOAP-ENV:mustUnderstand="1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="wsse SOAP-ENV"/></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#Body"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>OwgHPZNfDkXnZsjpfzXqAcT3RV3HzmTsEy2bP44FJ0M=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>C+7FWngUpJ33Q1yq8uuscjCyPN2IO4cJhpMv03Jrrht1V+4gvJQLIBk6HHjo1uPQyfYj6zji3pg+fOyGUptp17CsRvjCzSpP35vB2lEzHeS8dcY8XfrEtTP/0FNn75LmhhkOPy0wjWkgDVbgzhXpEk9az8r8fQVTM3vrcmXT+WdMWJXKBRFt6PLAhsFt0scOFTWAkLGyCwygzimDKX2nT63TOit9BigtIx7fPRuMkbybMKCGGABq2DiEbvrPOiN3SUYpyMNR9KehRAGN+OWnESaDC6DhOvbKR88XHkM+GeaRe9PWdrRHrwGfp3qgolKjR/wFRSa1YGSBKAhDJFBcdg==</ds:SignatureValue><ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>sXeRhM55P13FbpNcXAMR3olbw2Wa6keZIHu5YTZYUBTlYWId+pNiwUz3zFIEo+0IfYR0H27ybIycQO+1IIzJofUFNMAL3tZps2OKPlsjuCPls6kXpXhv/gvhux8LrCtp4PcKWqJ6QVOZKChc7WAx40qFWzHi57ueqRTv3x0kESqGg/VjsqyTEvb55psJO2RsfhLT7+YVh3hImRM3RDaJdkTkPuOxeFyT6N7VXD09329sLuS3QkUbE9zEKDnz9X3d8dEQdJhSI9ba5fxl8R7fu8pB67ElfzFml96X1jLFtzy1pzOT5Fc4ROcaqlYckVzdBq9sxezm6MYmDBjNAcibRw==</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo></ds:Signature></wsse:Security>
            //      </SOAP-ENV:Header>
            //      <SOAP-ENV:Body xmlns:SOAP-SEC="http://schemas.xmlsoap.org/soap/security/2000-12" SOAP-SEC:id="Body">
            //          <z:FooBar xmlns:z="http://example.com" />
            //      </SOAP-ENV:Body>
            //  </SOAP-ENV:Envelope>

            //  Here's the signature part formatted for easier reading.
            //  (Adding whitespace to the SignedInfo breaks the signature, so you wouldn't want to do this..)

            //      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            //          <ds:SignedInfo>
            //              <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            //                  <InclusiveNamespaces xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="wsse SOAP-ENV" />
            //              </ds:CanonicalizationMethod>
            //              <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
            //              <ds:Reference URI="#Body">
            //                  <ds:Transforms>
            //                      <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            //                  </ds:Transforms>
            //                  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
            //                  <ds:DigestValue>OwgHPZNfDkXnZsjpfzXqAcT3RV3HzmTsEy2bP44FJ0M=</ds:DigestValue>
            //              </ds:Reference>
            //          </ds:SignedInfo>
            //          <ds:SignatureValue>C+7FWngUp....BKAhDJFBcdg==</ds:SignatureValue>
            //          <ds:KeyInfo>
            //              <ds:KeyValue>
            //                  <ds:RSAKeyValue>
            //                      <ds:Modulus>sXeRhM55P13FbpNcXAMR....MYmDBjNAcibRw==</ds:Modulus>
            //                      <ds:Exponent>AQAB</ds:Exponent>
            //                  </ds:RSAKeyValue>
            //              </ds:KeyValue>
            //          </ds:KeyInfo>
            //      </ds:Signature>
        }
    }
}
