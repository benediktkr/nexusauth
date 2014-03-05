using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using BouncyCastleOCSP = Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System.IO;
using System.Net;
using System.Text;
using System.Collections;
using System.Configuration;

// Borrowed this file from Sverrir
// (c) Sverrir Bergþór Sverrirsson
namespace nexusauth.ChallengeResponse
{
    public enum CertificateStatus { Good = 0, Revoked = 1, Unknown = 2, Error = 3 }; 
    
    public class OcspClient
    {
        public readonly int BufferSize = 4096 * 8;
        private long MaxClockSkew = 864000000000; 
        private byte[] ocspResponse { get; set; }

        public OcspClient()
        {
            

        }

        public OcspClient(byte[] ocspResp)
        {
            ocspResponse = ocspResp;

        }

        public BouncyCastleOCSP.BasicOcspResp getOCSPCertFromResponse()
        {
            if (ocspResponse == null)
            {
                return null;
            }
            else
            {
                Org.BouncyCastle.Ocsp.OcspResp resp = new BouncyCastleOCSP.OcspResp(ocspResponse);
                BouncyCastleOCSP.BasicOcspResp bresp = resp.GetResponseObject() as BouncyCastleOCSP.BasicOcspResp;
                
                return bresp;
            }

        }

        public string GetOCSPResponseStatus(int code)
        {
            // rfs 2560. Status codes are camelCased..
            string status = null;
            switch (code)
            {
                case 0:
                    status = "successful";
                    break;
                case 1:
                    status = "malformedRequest";
                    break;
                case 2:
                    status = "internalError";
                    break;
                case 3:
                    status = "tryLater";
                    break;
                case 5:
                    status = "sigRequired";
                    break;
                case 6:
                    status = "unauthorized";
                    break;
                default:
                    throw new BouncyCastleOCSP.OcspException("Unkonwn error code from OCSP server");
                    break;
            }
            return status;
        }
        
        /// <summary>
        /// Query handles OCSP requests. Requests are sent to an OCSP responder that is defined in the client certificate.
        /// Issuercertificate is the certificate of the issuer of the client certiifcate.
        /// Signercertificate is the certificate of the intended OCSP responder and is used to validate the OCSP response.
        /// </summary>
        /// <param name="ClientCert">Certificate for the client.</param>
        /// <param name="issuerCert">Certificate for the issuer of the client certificate</param>
        /// <param name="signerCert">Certificate for the OCSP responder used to validate the signed response from the server.</param>
        /// <returns>CertificateStatus</returns>        /// 
        /// 

        // signerCert (OCSP cert) isn't being used. BK
        public CertificateStatus Query(X509Certificate ClientCert, X509Certificate issuerCert,X509Certificate signerCert)
        {
            return Query(ClientCert, issuerCert);
        }

        public CertificateStatus Query(X509Certificate ClientCert, X509Certificate issuerCert) 
        {
            // Get the OCSP url from the certificate.
            string ocspUrl = getOCSPUrl(ClientCert);

            if (ocspUrl == "" || ocspUrl == null)
            {
                return CertificateStatus.Error;
            }

            BouncyCastleOCSP.OcspReq req = CreateOcspRequest(issuerCert, ClientCert.SerialNumber);

            ocspResponse = SendtoOCSP(ocspUrl, req.GetEncoded(), "application/ocsp-request", "application/ocsp-response");
            
            return CheckOcspResponse(ClientCert, issuerCert, ocspResponse);
        }


        /// <summary>
        /// PostData sends the actual request to the OCSP responder.
        /// </summary>
        /// <param name="url">URL of the OCSP server</param>
        /// <param name="data">Validation data</param>
        /// <param name="contentType">Mime type of the request</param>
        /// <param name="accept">Accepted Mime type</param>
        /// <returns>OCSP response</returns>
        public byte[] SendtoOCSP(string url, byte[] data, string contentType, string accept)
        {
            //If proxy is used this can be enabled.
            //WebProxy proxy = new WebProxy("proxy.mydomain.is",portnumber);
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "POST";

                //IWebProxy ocspproxy = proxy;
                //request.Proxy = ocspproxy;

                request.ContentType = contentType;
                request.ContentLength = data.Length;
                request.Accept = accept;
                Stream stream = request.GetRequestStream();
                stream.Write(data, 0, data.Length);
                stream.Close();
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                Stream respStream = response.GetResponseStream();
                byte[] ocspResponse = ToByteArray(respStream);
                respStream.Close();

                return ocspResponse;
            }
            catch (Exception e)
            {
                //Logging.
                throw new HttpException(503, "Unable to connect to OCSP server.");
                
            }

        }

        /// <summary>
        /// Converts the Stream data from the OCSP responder to byte array.
        /// </summary>
        /// <param name="stream">Stream from the OCSP responder</param>
        /// <returns>Stream converted to bytearray</returns>
        public byte[] ToByteArray(Stream stream)
        {
            byte[] buffer = new byte[BufferSize];
            MemoryStream ms = new MemoryStream();

            int read = 0;

            while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                ms.Write(buffer, 0, read);
            }

            return ms.ToArray();
        }


        /// <summary>
        /// Checking if the OCSP AIA is in the certifiata and gets the url for the OCSP server.
        /// </summary>
        /// <param name="cert">Client certifiacte</param>
        /// <returns>OCSP url found in certificate</returns>
        public  string getOCSPUrl(X509Certificate cert)
        {
            string ocspUrl = "";

            try
            {
                Asn1Object obj = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);

                if (obj == null)
                {
                    return null;
                }
                
                AuthorityInformationAccess aia = AuthorityInformationAccess.GetInstance(obj);
                //log.LogError(Logger.LogLevel.ERROR, "OCSPURL", aia.ToString());
                
                AccessDescription[] des = aia.GetAccessDescriptions();
                foreach (var item in des)
                {
                    if (item.ToString() == "AccessDescription: Oid(1.3.6.1.5.5.7.48.1)")
                    {
                        GeneralName ocspName = item.AccessLocation;

                        ocspUrl = DerIA5String.GetInstance(ocspName.Name).GetString();
                    }

                }

            }
            catch (Exception e)
            {
                //log.LogError(Logger.LogLevel.ERROR, "OCSPclient - getOCSPUrl", e.Message);
                throw new HttpException(401, "Unable to get the URL for OCSP responder: " + e.Message);
            }

            return ocspUrl;
        }
        /// <summary>
        /// Getting the extension value for given OID.
        /// </summary>
        /// <param name="cert">Client Certificate</param>
        /// <param name="oid">OID of the extension to be parsed</param>
        /// <returns>ASN1 coded of the extension value</returns>
        protected static Asn1Object GetExtensionValue(X509Certificate cert, string oid)
        {
            if (cert == null)
            {
                return null;
            }

            byte[] bytes = cert.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

            if (bytes == null)
            {
                return null;
            }

            Asn1InputStream aIn = new Asn1InputStream(bytes);

            return aIn.ReadObject();
        }

        /// <summary>
        /// Returns the OCSP resoponse from the ocsp responder. Used as validation data and should be stored in DB.
        /// </summary>
        /// <returns>OCSP response</returns>
        public byte[] getResponse()
        {
            return ocspResponse;
        }

        /// <summary>
        /// Checks if the OCSP response from the OCSP responder. Returns the validity of the certificate used to sign the ocsp response and also
        /// if the client certificate is valid, revoked or unknown.
        /// </summary>
        /// <param name="clientCert">Client certificate</param>
        /// <param name="issuerCert">Issuer certificate of the client certificate</param>
        /// <param name="binaryResp">OCSP response</param>
        /// <returns>CertificateStatus</returns>
        private CertificateStatus CheckOcspResponse(X509Certificate clientCert, X509Certificate issuerCert, byte[] binaryResp)
        {
            BouncyCastleOCSP.OcspResp ocspResponse = new BouncyCastleOCSP.OcspResp(binaryResp);
            CertificateStatus certStatus = CertificateStatus.Unknown;

            
            switch (ocspResponse.Status)
            {
                case BouncyCastleOCSP.OcspRespStatus.Successful:
                    BouncyCastleOCSP.BasicOcspResp response = (BouncyCastleOCSP.BasicOcspResp)ocspResponse.GetResponseObject();

                    if (response.Responses.Length == 1)
                    {
                        BouncyCastleOCSP.SingleResp singleResponse = response.Responses[0];

                        ValidateCertificateId(issuerCert, clientCert, singleResponse.GetCertID());
                        ValidateThisUpdate(singleResponse);
                        ValidateNextUpdate(singleResponse); 

                        Object certificateStatus = singleResponse.GetCertStatus();

                        if (certificateStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                        {
                            certStatus = CertificateStatus.Good;
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.RevokedStatus)
                        {
                            certStatus = CertificateStatus.Revoked;
                        }
                        else if (certificateStatus is Org.BouncyCastle.Ocsp.UnknownStatus)
                        {
                            certStatus = CertificateStatus.Unknown;
                        }
                    }
                    break;
                default:
                    {
                        throw new BouncyCastleOCSP.OcspException("Error status: " + this.GetOCSPResponseStatus(ocspResponse.Status));
                    }
            }

            return certStatus;
        }

        /// <summary>
        /// Checks if Next Update value is not null. If not null next update must not be older then current time.
        /// </summary>
        /// <param name="resp">OCSP response</param>

        private void ValidateNextUpdate(BouncyCastleOCSP.SingleResp resp)
        {
            if (resp.NextUpdate != null && resp.NextUpdate.Value != null && resp.NextUpdate.Value.Ticks <= DateTime.Now.Ticks)
            {
                //log.LogError(Logger.LogLevel.ERROR, "ValidateNextUpdate", "Invalid Next Update");
                throw new HttpException(401, "Invalid Next Update");
            }
        }

        /// <summary>
        /// Checks the certificate ID of the response is valid.
        /// </summary>
        /// <param name="issuerCert">Issuer Certificate if the client</param>
        /// <param name="clientCert">Client Certificate</param>
        /// <param name="certificateId">Id of certificate found in OCSP response</param>
        private void ValidateCertificateId(X509Certificate issuerCert, X509Certificate clientCert, BouncyCastleOCSP.CertificateID certificateId)
        {
            BouncyCastleOCSP.CertificateID expectedId = new BouncyCastleOCSP.CertificateID(BouncyCastleOCSP.CertificateID.HashSha1, issuerCert, clientCert.SerialNumber);

            if (!expectedId.SerialNumber.Equals(certificateId.SerialNumber))
            {
                throw new HttpException(401, "Invalid certificate ID in response");
            }

            if (!Org.BouncyCastle.Utilities.Arrays.AreEqual(expectedId.GetIssuerNameHash(), certificateId.GetIssuerNameHash()))
            {
                throw new HttpException(401, "Invalid certificate Issuer in response");
            }

        }

        /// <summary>
        /// Creates the ocsprequest to send to the ocsp responder.
        /// </summary>
        /// <param name="issuerCert">Certificate of the issuer of the client certificate</param>
        /// <param name="serialNumber">Serial number of the client certificate</param>
        /// <returns>Ocsp Request to be sent to OCSP responder</returns>
        private BouncyCastleOCSP.OcspReq CreateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber)
        {
            BouncyCastleOCSP.CertificateID certID = new BouncyCastleOCSP.CertificateID(BouncyCastleOCSP.CertificateID.HashSha1, issuerCert, serialNumber);

            BouncyCastleOCSP.OcspReqGenerator ocspRequestGenerator = new BouncyCastleOCSP.OcspReqGenerator();

            ocspRequestGenerator.AddRequest(certID);

            return ocspRequestGenerator.Generate();
        }

        /// <summary>
        /// Check if the response is too old.
        /// </summary>
        /// <param name="resp">OCSP response</param>
        private void ValidateThisUpdate(BouncyCastleOCSP.SingleResp resp)
        {
            if (Math.Abs(resp.ThisUpdate.Ticks - DateTime.Now.Ticks) > MaxClockSkew)
            {
                throw new HttpException(401, "Resonpse too old.");
            }
        }
    }
}