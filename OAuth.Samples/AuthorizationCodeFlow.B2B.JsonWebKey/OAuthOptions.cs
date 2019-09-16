using System;
using System.Collections.Generic;

namespace AuthorizationCodeFlow.B2B.JsonWebKey
{
    public class OAuthOptions
    {
        public string AuthorizationCode { get; set; }
        public int ClientId { get; set; }
        public List<string> Scopes { get; set; }
        public Uri TokenEndpoint { get; set; }
        public string JsonWebKey { get; set; }
        public Uri RedirectUri { get; set; }
    }
}