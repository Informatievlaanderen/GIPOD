using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace GenerateJsonWebKey
{
    class Program
    {

        const string privateKeyFileName = "jsonwebkeyprivate.key";
        const string publicKeyFileName = "jsonwebkeypublic.key";

        public static async Task Main()
        {
            var parametersPublic = default(RSAParameters);
            var parametersPrivate = default(RSAParameters);

            Console.WriteLine("Generating RSA key...");
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                parametersPrivate = rsa.ExportParameters(true);
                parametersPublic = rsa.ExportParameters(false);
            }

            var keyId = $"{Guid.NewGuid()}";

            var key = new Microsoft.Azure.KeyVault.WebKey.JsonWebKey(parametersPrivate);
            var keyPublic = new Microsoft.Azure.KeyVault.WebKey.JsonWebKey(parametersPublic);

            key.Kid = keyId;
            keyPublic.Kid = keyId;

            var jsonPrivate = JObject.Parse(key.ToString());
            jsonPrivate.Add("use", "sig");
            jsonPrivate.Add("alg", "RS512");

            var jsonPublic = JObject.Parse(keyPublic.ToString());
            jsonPublic.Add("use", "sig");
            jsonPublic.Add("alg", "RS512");

            Console.WriteLine("Public Key");
            Console.WriteLine(jsonPublic.ToString());

            Console.WriteLine(Environment.NewLine);

            Console.WriteLine("Private key");
            Console.WriteLine(jsonPrivate.ToString());

            Console.WriteLine(Environment.NewLine);

            Console.WriteLine($"Writing public key to file {publicKeyFileName}.");
            await File.WriteAllTextAsync(publicKeyFileName, jsonPublic.ToString());

            Console.WriteLine(Environment.NewLine);

            Console.WriteLine($"Writing private key to file {privateKeyFileName}.");
            await File.WriteAllTextAsync(privateKeyFileName, jsonPrivate.ToString());

            Console.Read();
        }
    }
}
