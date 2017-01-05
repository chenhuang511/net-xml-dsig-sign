using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace TestXMLDSig
{
    class SignHash
    {
        public static string signHash(byte[] hash, X509Certificate2 xcert)
        {
            RSACryptoServiceProvider csp = null;
            if (xcert == null)
            {
                throw new Exception("Cert is null");
            }

            csp = (RSACryptoServiceProvider)xcert.PrivateKey;

            if (csp == null)

            {

                throw new Exception("No valid cert was found");

            }

            byte[] sig = csp.SignHash(hash, CryptoConfig.MapNameToOID("SHA1"));
            return System.Convert.ToBase64String(sig);
        }

        public static string sign(byte[] hash, X509Certificate2 xcert)
        {
            RSACryptoServiceProvider csp = null;
            if (xcert == null)
            {
                throw new Exception("Cert is null");
            }

            csp = (RSACryptoServiceProvider)xcert.PrivateKey;

            if (csp == null)
            {

                throw new Exception("No valid cert was found");

            }

            byte[] sig = csp.SignData(hash, CryptoConfig.MapNameToOID("SHA1"));
            return System.Convert.ToBase64String(sig);
        }

        //public static void Main(String[] args)
        //{
        //    try
        //    {
        //        X509Certificate2 cert = new X509Certificate2(@"D:\Certificates.p12", "123456", X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
        //        byte[] hash = System.Convert.FromBase64String("LpCk5j5U3nCucCjnOhGyRpYk5N4=");
        //        string sig = sign(hash, cert);
        //        Console.WriteLine(sig);
        //        Console.WriteLine(sig.Length);
        //        Console.ReadLine();
        //    }
        //    catch (Exception e)
        //    {
        //        Console.WriteLine(e.Message);
        //        Console.ReadLine();
        //    }
        //}
    }
}
