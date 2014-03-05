using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Xml;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.IO;

namespace nexusauth.ChallengeResponse
{
    public class Response
    {
        // This class uses the .NET primitives for X509 (System.Security.Cryptography.X509Certificates)

        public byte[] Certificate;
        public X509Certificate2 X509Certificate;
        public string Nonce;
        private bool DisgValid; 

        public Response(string xml, bool base64 = true)
        {
            if (base64)
            {
                xml = Encoding.UTF8.GetString(Convert.FromBase64String(xml));
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = false;
            document.LoadXml(xml);

            SignedXml verifier = new SignedXml();
            verifier.LoadXml(document.DocumentElement);  // root xml element

            this.DisgValid = verifier.CheckSignature();

            using (XmlReader xmlreader = XmlReader.Create(new StringReader(xml)))
            {
                // X509Certificate
                xmlreader.ReadToFollowing("X509Certificate");
                string x509 = xmlreader.ReadElementContentAsString();
                this.Certificate = Convert.FromBase64String(x509);
                this.X509Certificate = new X509Certificate2(this.Certificate);

                // Nonce
                xmlreader.ReadToFollowing("nonce");
                this.Nonce = xmlreader.ReadElementContentAsString();
            }
        }

        public bool Valid(Challenge Chall)
        {
            return this.DisgValid && Chall.challenge64 == this.Nonce;
        }
    }
}