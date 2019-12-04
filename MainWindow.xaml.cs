using Siginig.Library;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Xml;

namespace Siginig
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            //Generator.GenerateRSAKeyPair(out publicKey, out privateKey);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            //SignXML.Start();
            //CallDigest();
            ///////////////////////////////////////////////////////
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = false;
            xmlDoc.Load("E:\\XML\\keystore-demo\\small.xml");// Load an XML file into the XmlDocument object.
            string temp = Canonicalize.XmlHash(xmlDoc);
            MessageBox.Show(temp);
            Clipboard.SetText(temp);
        }

        private void CallDigest()
        {
            try
            {
                Digest.GetCertChainFromAlias();
            }
            catch (Exception ex)
            {
                MessageBox.Show("Please select a certificate to sign the XML");
                Console.WriteLine(ex.ToString());
            }
            byte[] signedData = Digest.SignXmlDigest(
                                            Digest.GetDataToSignByteStreamFromFilePath("E:\\XML\\keystore-demo\\big_digest.xml")
                                        );
            File.WriteAllBytes("E:\\XML\\keystore-demo\\big_digest_signed.xml", signedData);
            System.Diagnostics.Process.Start(@"E:\\XML\\keystore-demo\\big_digest_signed.xml");
            MessageBox.Show("Done");
        }
    }
}
