using System;
using System.Collections.Generic;

namespace ClientCredentialGrant.JsonWebKey
{
    public class OAuthOptions
    {
        public int ClientId { get; set; }
        public List<string> Scopes { get; set; }
        public Uri TokenEndpoint { get; set; }
        public string JsonWebKey { get; set; }
    }
}