using Microsoft.Win32;
using Siginig.Library;
using System;
using System.IO;
using System.Windows;
using System.Xml;

namespace Siginig
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        static bool flag = false;
        static string selectedFile = null;

        public MainWindow()
        {
            InitializeComponent();
            //Generator.GenerateRSAKeyPair(out publicKey, out privateKey);
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            //ChilkatExample.Sign();
            XmlDocument xmlDoc = LoadXML();

            //Call with Microsoft Library
            string temp = Canonicalize.XmlHash(xmlDoc); //default Sha256, but all supported
            MessageBox.Show(flag + " - " + temp);
            Clipboard.SetText(temp);

            //Call with Bouncy Castle Library
            temp = Canonicalize.GetSha256FromStream(xmlDoc.OuterXml);
            MessageBox.Show(flag + " - " + temp);
            Clipboard.SetText(temp);
        }

        private XmlDocument LoadXML()
        {
            flag = !flag;
            if (selectedFile == null || flag)
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                //openFileDialog.Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*";
                openFileDialog.DefaultExt = "xml";
                openFileDialog.Filter = "XML Files|*.xml";
                if (openFileDialog.ShowDialog() != true)
                    throw new ArgumentException("File Not Selected Exception", "original");
                //selectedFile = File.ReadAllText(openFileDialog.FileName);
                selectedFile = openFileDialog.FileName;
            }

            //SignXML.Start();
            //CallDigest();
            ///////////////////////////////////////////////////////
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.PreserveWhitespace = flag;
            xmlDoc.Load(selectedFile);// Load an XML file into the XmlDocument object.
            return xmlDoc;
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
