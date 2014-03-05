Dependencies
====

If you are using C# .NET and this boilerplate code, you will need the following:

The OcspClient requires BouncyCastle. Installing with NuGet

    PM> Install-Package BouncyCastle


You will also need IISExpress, since Nexus Personal requires HTTPS, wich Cassini cannot do. Then go to the "Web" tab in Project Settings and check "Use IIS Express". The select your project in the Solution Explorer and set "SSL Enabled" to True in the Properties tab. This example project includes these settings. 

Introduction
====

Some short example-code on how to use the Nexus Personal Authentication Plugin with the certificates from Auðkenni and .NET MVC. 

Nexus Personal provides both a NPAPI browser plugin for "Mozilla-based" browsers and a ActiveX component for MSIE.

The process - how it works
-----

The plugin works as a Challenge-Response protocol, where the server generates a challange that the client then signes (with the XML-DSIG format) and sends back to the server. The server than checks if the XML-DSIG is valid and if the certificate used to sign is both valid and not revoked (with OCSP). 

This process is thus as follows:

 1. The server generates a crypographically random challenge
 2. The client signs this with the Nexus Authentication plugin and sends back XML-DSIG
 3. The server validates the XML-DSIG
 4. The server validates the authenticity of the certificate used to sign with OCSP

Step 4 is crucial, otherwise an adversary could generate a valid response with a forged certificate. Another choice is to build and verify the Certificate Chain ( Islandsrot -> Fulltgilt Audkenni -> User certificate ). This gives you locally competud knowledge of the certificates authenticity, but it doesn't provide you with revocation information. You can combine these two methods. 

The certificates required to build the chain are included in this repository, but you should obtain them from a trusted source, such as a SmartCard issued by Audkenni or the banks. 


Authors
===

Sverrir Bergþór Sverrirsson
Benedikt Kristinsson

(c) Auðkenni ehf.
