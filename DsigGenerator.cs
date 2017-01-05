using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
public class DsigGenerator
{
    /// <summary>
    /// Hàm ghép lại dữ liệu sau khi ký
    /// </summary>
    /// <param name="byteInv">Dữ liệu (invDataWithCus) khi gọi hàm GetDigestForRemote</param>
    /// <param name="RemoteSign">Dữ liệu ký hash</param>
    /// <param name="serial">Serial chứng thư số</param>
    /// <returns></returns>
    public byte[] WrapCustomerPublishSign(byte[] byteInv, byte[] RemoteSign, string serial)
    {
        XmlDocument xdoc = new XmlDocument();
        xdoc.PreserveWhitespace = true;
        xdoc.LoadXml(System.Text.Encoding.UTF8.GetString(byteInv));
        xdoc.GetElementsByTagName("SignatureValue")[0].InnerText = Convert.ToBase64String(RemoteSign);

        byte[] invdata = System.Text.Encoding.UTF8.GetBytes(xdoc.OuterXml);
        //int k = VerifyInvoice(invdata);
        //if (k == 1)
        //{
            return System.Text.Encoding.UTF8.GetBytes(xdoc.OuterXml);
        //}
        //else throw new Exception("wrap error: " + k);
    }

    public void WrapCustomerPublishSign(XmlDocument xdoc, string b64RemoteSign)
    {
        xdoc.GetElementsByTagName("SignatureValue")[0].InnerText = b64RemoteSign;
    }

    /// <summary>
    /// Lấy dữ liệu hash
    /// </summary>
    /// <param name="invdata">Dữ liệu cần hash</param>
    /// <param name="invDataWithCus"></param>
    /// <param name="CustomerCert">Chứng thư số</param>
    /// <returns></returns>
    public byte[] GetDigestForRemote(byte[] invdata, out byte[] invDataWithCus, X509Certificate2 CustomerCert)
    {
        XmlDocument xmlDoc = DsigSignature.AddCustomerDataForRemote(invdata);
        byte[] data = DsigSignature.HashForRemote(xmlDoc, CustomerCert);
        invDataWithCus = System.Text.Encoding.UTF8.GetBytes(xmlDoc.OuterXml);
        return data;
    }
}
class DsigSignature
{
    public enum DsigSignatureMode
    {
        Client,
        Server
    }
    public static XmlNode tempSignature(byte[] base64Digest, byte[] base64SignatureValue, X509Certificate2 CustomerCert, DsigSignatureMode mode)
    {
        string signatureId = "sigid", attRefValue = "Content", signatureValue = "";
        if (mode == DsigSignatureMode.Client)
        {
            signatureId = "cltSig";
            attRefValue = "#ClientSigningData";
            signatureValue = base64SignatureValue == null ? "" : Convert.ToBase64String(base64SignatureValue);
        }
        else if (mode == DsigSignatureMode.Server)
        {
            signatureId = "serSig";
            attRefValue = "#Envelope";
            signatureValue = base64SignatureValue == null ? "" : System.Text.Encoding.UTF8.GetString(base64SignatureValue);
        }
        XmlDocument xdoc = new XmlDocument();

        XmlNode signature = xdoc.CreateElement("Signature");
        XmlAttribute attID = xdoc.CreateAttribute("Id");
        attID.Value = signatureId;
        XmlAttribute attSignature = xdoc.CreateAttribute("xmlns");
        attSignature.Value = "http://www.w3.org/2000/09/xmldsig#";
        signature.Attributes.Append(attID);
        signature.Attributes.Append(attSignature);

        XmlNode signInfo = signature.AppendChild(xdoc.CreateElement("SignedInfo"));
        XmlNode canon = signInfo.AppendChild(xdoc.CreateElement("CanonicalizationMethod"));
        XmlAttribute attCanon = xdoc.CreateAttribute("Algorithm");
        attCanon.Value = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        canon.Attributes.Append(attCanon);

        XmlNode signMethod = signInfo.AppendChild(xdoc.CreateElement("SignatureMethod"));
        XmlAttribute attSign = xdoc.CreateAttribute("Algorithm");
        attSign.Value = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        signMethod.Attributes.Append(attSign);

        XmlNode refe = signInfo.AppendChild(xdoc.CreateElement("Reference"));
        XmlAttribute attRef = xdoc.CreateAttribute("URI");
        attRef.Value = attRefValue;
        refe.Attributes.Append(attRef);

        XmlNode trans = refe.AppendChild(xdoc.CreateElement("Transforms"));
        XmlNode tran1 = trans.AppendChild(xdoc.CreateElement("Transform"));
        XmlAttribute attTran1 = xdoc.CreateAttribute("Algorithm");
        attTran1.Value = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
        tran1.Attributes.Append(attTran1);

        XmlNode digMethod = refe.AppendChild(xdoc.CreateElement("DigestMethod"));
        XmlAttribute attDigMethod = xdoc.CreateAttribute("Algorithm");
        attDigMethod.Value = "http://www.w3.org/2000/09/xmldsig#sha1";
        digMethod.Attributes.Append(attDigMethod);

        XmlNode digVal = refe.AppendChild(xdoc.CreateElement("DigestValue"));
        digVal.InnerText = Convert.ToBase64String(base64Digest);

        XmlNode signValue = signature.AppendChild(xdoc.CreateElement("SignatureValue"));
        signValue.InnerText = base64SignatureValue == null ? "" : signatureValue;

        XmlNode keyInfo = signature.AppendChild(xdoc.CreateElement("KeyInfo"));

        XmlNode xData = keyInfo.AppendChild(xdoc.CreateElement("X509Data"));

        XmlNode xCert = xData.AppendChild(xdoc.CreateElement("X509Certificate"));
        xCert.InnerText = CustomerCert == null ? "" : Convert.ToBase64String(CustomerCert.RawData);

        return xdoc.AppendChild(signature);

    }
    public static byte[] Hash(XmlDocument xd, X509Certificate2 CustomerCert)
    {
        try
        {
            byte[] digest = getDigest(xd);

            XmlNode signature = tempSignature(digest, null, CustomerCert, DsigSignatureMode.Client);

            return PerformHash(xd, signature);
        }
        catch
        {
            throw new Exception("Hash Error!");
        }
    }

    public static byte[] HashForRemote(XmlDocument xd, X509Certificate2 CustomerCert)
    {
        try
        {
            byte[] digest = getDigestForRemote(xd);
            string b64 = System.Convert.ToBase64String(digest);

            XmlNode signature = tempSignature(digest, null, CustomerCert, DsigSignatureMode.Server);

            return PerformHash(xd, signature);
        }
        catch
        {
            throw new Exception("Hash Error!");
        }
    }

    private static byte[] PerformHash(XmlDocument xd, XmlNode signature)
    {
        XmlNode importNode = xd.ImportNode(signature, true);
        xd.DocumentElement.AppendChild(importNode);

        XmlDocument doc = new System.Xml.XmlDocument();
        doc.LoadXml(signature.OuterXml);

        XmlNodeList nodeList = doc.GetElementsByTagName("SignedInfo");

        XmlDocument doc21 = new System.Xml.XmlDocument();
        doc21.LoadXml(nodeList[0].OuterXml);


        XmlDsigC14NTransform t1 = new XmlDsigC14NTransform();
        t1.LoadInput(doc21);
        Stream sss = (Stream)t1.GetOutput(typeof(Stream));
        sss.Position = 0;

        byte[] buffer = new byte[16 * 1024];
        using (MemoryStream ms = new MemoryStream())
        {
            int read;
            while ((read = sss.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
            }
            buffer = ms.ToArray();
        }

        SHA1Managed sha = new SHA1Managed();
        byte[] output = sha.ComputeHash(buffer);
        return output;
    }

    public static XmlDocument AddCustomerData(byte[] invdata)
    {
        string xmlData = System.Text.Encoding.UTF8.GetString(invdata);

        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.LoadXml(xmlData);

        XmlElement e = (XmlElement)xmlDoc.GetElementsByTagName("Signature")[0];
        XmlElement d = (XmlElement)xmlDoc.GetElementsByTagName("Content")[0];
        XmlElement qr = (XmlElement)xmlDoc.GetElementsByTagName("qrCodeData")[0];

        xmlDoc.DocumentElement.RemoveAll();

        XmlNode newnode = xmlDoc.DocumentElement.AppendChild(xmlDoc.CreateElement("ClientData"));
        XmlAttribute xa1 = xmlDoc.CreateAttribute("Id");
        xa1.Value = "ClientSigningData";
        newnode.Attributes.Append(xa1);

        xmlDoc.DocumentElement.AppendChild(newnode);
        xmlDoc.GetElementsByTagName("ClientData")[0].AppendChild(d);

        XmlElement dateNode = (XmlElement)xmlDoc.GetElementsByTagName("ClientData")[0].AppendChild(xmlDoc.CreateElement("Date"));
        dateNode.InnerText = DateTime.Now.ToString("dd/MM/yyyy");
        //HH:mm:ss

        XmlNode xnQr = xmlDoc.ImportNode(qr, true);
        xmlDoc.DocumentElement.AppendChild(xnQr);

        XmlNode xn = xmlDoc.ImportNode(e, true);
        xmlDoc.DocumentElement.AppendChild(xn);

        return xmlDoc;
    }

    public static byte[] getDigest(XmlDocument xmldoc)
    {
        XmlNode xn = xmldoc.GetElementsByTagName("ClientData")[0];

        return PerformGetDigest(xn);
    }

    public static byte[] getDigestForRemote(XmlDocument xmldoc)
    {
        XmlNode xn = xmldoc.GetElementsByTagName("Content")[0];
        return PerformGetDigest(xn);
    }

    private static byte[] PerformGetDigest(XmlNode xn)
    {

        XmlDocument xdoc = new XmlDocument();
        xdoc.LoadXml(xn.OuterXml);

        XmlDsigC14NTransform c14n = new XmlDsigC14NTransform();

        c14n.LoadInput(xdoc);

        //get canonalised stream 
        Stream s1 = (Stream)c14n.GetOutput(typeof(Stream));

        SHA1 sha1 = new SHA1CryptoServiceProvider();
        Byte[] output = sha1.ComputeHash(s1);
        string a = Convert.ToBase64String(output);
        return output;
    }

    public static byte[] PerformGetDigest(XmlDocument xdoc)
    {

        XmlDsigC14NTransform c14n = new XmlDsigC14NTransform();

        c14n.LoadInput(xdoc);

        //get canonalised stream 
        Stream s1 = (Stream)c14n.GetOutput(typeof(Stream));

        SHA1 sha1 = new SHA1CryptoServiceProvider();
        Byte[] output = sha1.ComputeHash(s1);
        string a = Convert.ToBase64String(output);
        return output;
    }

    public static XmlDocument AddCustomerDataForRemote(byte[] invdata)
    {
        string xmlData = System.Text.Encoding.UTF8.GetString(invdata);

        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.PreserveWhitespace = true;
        xmlDoc.LoadXml(xmlData);

        XmlElement dateNode = (XmlElement)xmlDoc.GetElementsByTagName("Content")[0].AppendChild(xmlDoc.CreateElement("SignDate"));
        dateNode.InnerText = DateTime.Now.ToString("dd/MM/yyyy");
        return xmlDoc;
    }
}