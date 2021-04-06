using System.Security.Cryptography.X509Certificates;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth
{
    public interface ICertificateRetriever
    {
        X509Certificate2 Get(string key);
    }
}