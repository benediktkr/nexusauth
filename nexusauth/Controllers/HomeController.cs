using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.IO;
using nexusauth.ChallengeResponse;
using Org.BouncyCastle.X509;

namespace nexusauth.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Login()
        {
            // Create a challenge and pass it to the view and store in the session
            Challenge challenge = new Challenge();
            Session["challenge"] = challenge;

            return View(challenge);
        }

        public ActionResult Verify(string xml)
        {
            Response response = new Response(xml);
            Challenge challenge = Session["challenge"] as Challenge;

            if (!response.Valid(challenge))
            {
                return Json(new { error = "Invalid DSIG" }, JsonRequestBehavior.AllowGet);
            }
         
            OcspClient ocspclient = new OcspClient();

            // This uses the BouncyCastle X509 primitives (Org.BouncyCastle.X509)
            X509CertificateParser parser = new X509CertificateParser();
            var fullgiltbytes = System.IO.File.ReadAllBytes(HttpContext.Server.MapPath("~/certs/fullgilt.cer"));
            X509Certificate fullgilt = parser.ReadCertificate(fullgiltbytes);
            X509Certificate user = parser.ReadCertificate(response.Certificate);

            try
            {
                CertificateStatus ocspresonse = ocspclient.Query(user, fullgilt);
                if (ocspresonse != CertificateStatus.Good)
                {
                    return Json(new { error = Enum.GetName(typeof(CertificateStatus), ocspresonse) });
                }
             
                // Do your normal login stuff here. 
                Session["LoggedIn"] = true;
                return Json(new { valid = true, msg = "Login successful" }, JsonRequestBehavior.AllowGet);

            }
            catch (Org.BouncyCastle.Ocsp.OcspException ocspex)
            {
                return Json(new { error = ocspex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        ActionResult Logout()
        {
            Session.Clear();
            Session.Abandon();
            return Redirect("/");
        }
    }
}
