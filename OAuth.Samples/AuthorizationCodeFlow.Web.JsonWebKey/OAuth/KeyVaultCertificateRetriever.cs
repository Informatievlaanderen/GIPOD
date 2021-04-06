using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth
{
    public class KeyVaultCertificateRetriever : ICertificateRetriever
    {
        private readonly IConfiguration _configuration;

        public KeyVaultCertificateRetriever(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public X509Certificate2 Get(string key)
        {
            var pfxBase64 = _configuration[key];
            if (string.IsNullOrWhiteSpace(pfxBase64))
            {
                throw new KeyVaultErrorException($"Certificate with secretname '{key}' is not found in keyvault '{_configuration["Vault"]}'.");
            }
            var pfxBytes = Convert.FromBase64String(pfxBase64);
            return new X509Certificate2(pfxBytes);
        }
    }
}