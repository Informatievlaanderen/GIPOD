using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth
{
    public class LocalCertificateRetriever : ICertificateRetriever
    {
        public X509Certificate2 Get(string key)
        {
            var localMachineCertificate = fetchFromStore(StoreLocation.LocalMachine, key);
            if (localMachineCertificate.Count > 0)
            {
                return localMachineCertificate[0];
            }

            var userCertificate = fetchFromStore(StoreLocation.CurrentUser, key);
            if (userCertificate.Count > 0)
            {
                return userCertificate[0];
            }

            throw new KeyNotFoundException($"Certificate with thumbprint {key} is not found.");
        }

        private X509Certificate2Collection fetchFromStore(StoreLocation store, string key)
        {
            X509Store localMachineStore = new X509Store(StoreName.My, store);
            localMachineStore.Open(OpenFlags.ReadOnly);
            return localMachineStore.Certificates.Find(X509FindType.FindByThumbprint, key, validOnly: false);
        }
    }
}