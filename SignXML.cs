using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using System.Collections.Generic;
using SD.Ivan.Signning;

namespace TestXMLDSig
{
    public class SignXML
    {

        public static void Main(String[] args)
        {
            try
            {
                // Create a new XML document.
                XmlDocument xmlDoc = new XmlDocument();

                // Load an XML file into the XmlDocument object.
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load(@"D:/1.xml");

                // Get digest for remote sign
                X509Certificate2 cert = new X509Certificate2(@"D:\Certificates.p12", "123456", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
                XmlDocument xmlDocForHash = xmlDoc;
                byte[] digest = DsigSignature.HashForRemote(xmlDoc, cert);
                string b64Digest = System.Convert.ToBase64String(digest);

                // Sign hash
                string b64Signature = SignHash.signHash(digest, cert);

                // Wrap
                DsigGenerator generator = new DsigGenerator();
                generator.WrapCustomerPublishSign(xmlDoc, b64Signature);

                //Save
                xmlDoc.Save(@"D:/4.xml");

                //verify
                XmlDocument xmlDocSigned = new XmlDocument();
                xmlDocSigned.PreserveWhitespace = true;
                xmlDocSigned.Load(@"D:/4.xml");
                bool validate = Verify(xmlDocSigned);

                Console.WriteLine("XML file signed.");


            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        // Sign an XML file. 
        // This document cannot be verified unless the verifying 
        // code has the key with which it was signed.
        public static void SignXml(XmlDocument xmlDoc, RSA Key)
        {
            // Check arguments.
            if (xmlDoc == null)
                throw new ArgumentException("xmlDoc");
            if (Key == null)
                throw new ArgumentException("Key");

            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document.
            signedXml.SigningKey = Key;

            // Create a reference to be signed.
            Reference reference = new Reference();
            reference.Uri = "";

            // Add an enveloped transformation to the reference.
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get signed Info
            var signedInfo = signedXml.SignedInfo.CanonicalizationMethodObject;
            Console.WriteLine(signedInfo);

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Append the element to the XML document.
            xmlDoc.DocumentElement.AppendChild(xmlDoc.ImportNode(xmlDigitalSignature, true));
            Console.ReadLine();
        }

        private static XmlNode GetXmlNode(XmlDocument xDoc, string name, string xPath)
        {
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(xDoc.NameTable);
            nsmgr.AddNamespace("Envelope", name);
            //if (!xPath.StartsWith("/"))
            //    xPath = "Envelope:" + xPath;
            XmlNode re = xDoc.SelectSingleNode(xPath, nsmgr);
            return re;

        }

        public static bool Verify(XmlDocument document)
        {
            if (document == null) return false;

            SignedXml signed = new SignedXml(document);
            XmlNodeList list = document.GetElementsByTagName("Signature");
            if (list == null)
                throw new CryptographicException("The XML document has no signature.");
            if (list.Count > 1)
                throw new CryptographicException("The XML document has more than one signature.");

            signed.LoadXml((XmlElement)list[0]);

            RSA rsa = null;
            foreach (KeyInfoClause clause in signed.KeyInfo)
            {
                RSAKeyValue value = clause as RSAKeyValue;
                if (value == null) continue;
                RSAKeyValue key = value;
                rsa = key.Key;
            }

            return rsa != null && signed.CheckSignature(rsa);
            //return signed.CheckSignature();
        }

        public static string Sign_Enveloped_BH(XmlDocument document, ref string xmlSigned, X509Certificate2 cert, string nodeKy, string sigId, string sigIdProperty, string nodeStart)
        {
            sigId = "sigid";
            sigIdProperty = "proid";
            nodeKy = "CKYDTU_DVI";
            nodeStart = "Envelope";
            try
            {
                //chenhuang custom
                if (cert == null)
                    cert = new X509Certificate2(@"D:\Certificates.p12", "123456", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                XmlElement signaturePropertiesRoot = null;
                xmlSigned = document.OuterXml;
                RSA Key = (RSACryptoServiceProvider)cert.PrivateKey;


                document.PreserveWhitespace = true;
                // Create the SignedXml message.
                SignedXml signedXml = new SignedXml(document);
                signedXml.SigningKey = Key;

                Signature XMLSignature = signedXml.Signature;
                XMLSignature.Id = sigId;
                // Create a reference to be able to package everything into the // message.
                Reference reference = new Reference();

                reference.Uri = "";

                // Add an enveloped transformation to the reference.
                XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);

                XMLSignature.SignedInfo.AddReference(reference);

                // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
                KeyInfo keyInfo = new KeyInfo();
                keyInfo.AddClause(new RSAKeyValue((RSA)Key));


                var c = new KeyInfoX509Data(cert);
                c.AddSubjectName(cert.Subject);
                keyInfo.AddClause(c);
                // Add the KeyInfo object to the Reference object.
                XMLSignature.KeyInfo = keyInfo;
                signaturePropertiesRoot = document.CreateElement("SignatureProperties");

                signaturePropertiesRoot.SetAttribute("Id", sigIdProperty);
                //signaturePropertiesRoot.RemoveAttribute("xmlns");

                System.Security.Cryptography.Xml.DataObject signatureProperties = new System.Security.Cryptography.Xml.DataObject();

                XmlElement signingTime = document.CreateElement("SigningTime", "http://example.org/#signatureProperties");

                //signingTime.SetAttribute("xmlns", "http://example.org/#signatureProperties");
                signingTime.InnerText = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"); // DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

                XmlElement property = document.CreateElement("SignatureProperty");
                property.SetAttribute("Target", "#" + sigId);

                property.AppendChild(signingTime);

                signaturePropertiesRoot.AppendChild(property);

                signatureProperties.Data = signaturePropertiesRoot.SelectNodes(".");
                XMLSignature.AddObject(signatureProperties);

                // Compute the signature.
                signedXml.ComputeSignature();

                XmlElement xmlDigitalSignature = signedXml.GetXml();

                //var nodeCKy = GetXmlNode(document, "", nodeStart + "/" + nodeKy);
                var nodeCKy = document.SelectSingleNode(nodeStart + "/*/" + nodeKy);
                if (nodeCKy == null)
                {
                    nodeCKy = document.CreateNode(XmlNodeType.Element, nodeKy, null);

                    document.SelectSingleNode(nodeStart).AppendChild(nodeCKy);

                }
                nodeCKy.AppendChild(xmlDigitalSignature);
                xmlSigned = document.OuterXml;
                return "";
            }
            catch (Exception ex)
            {
                return string.Format("Mess: {0}             Detail: {1}                      Content xml: {2}", ex.Message, ex.ToString(), xmlSigned);
            }
        }

        public static string Sign_Enveloped_BH(XmlDocument document, ref string xmlSigned)
        {
            string sigId = "sigid";
            string sigIdProperty = "proid";
            string nodeKy = "CKYDTU_DVI";
            string nodeStart = "Envelope";
            X509Certificate2 cert = new X509Certificate2(@"D:\Certificates.p12", "123456", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            //List<string> paths = new List<string>();
            //paths.Add("D:/1.xml");
            //List<string> results = new List<string>();

            //results = IvanSign.SignXML(paths, cert, nodeKy, nodeStart);

            return Sign_Enveloped_BH(document, ref xmlSigned, cert, nodeKy, sigId, sigIdProperty, nodeStart);
        }

    }
}
