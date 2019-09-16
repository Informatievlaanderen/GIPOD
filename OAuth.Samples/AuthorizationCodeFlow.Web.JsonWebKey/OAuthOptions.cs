using System;
using System.Collections.Generic;

namespace AuthorizationCodeFlow.Web.JsonWebKey
{
    public class OAuthOptions
    {
        public int ClientId { get; set; }
        public string JsonWebKey { get; set; }
        public Uri RedirectUri { get; set; }
        public List<string> Scopes { get; set; }
        public string State { get; set; }
        public Uri AuthorizeEndpoint { get; set; }
        public Uri TokenEndpoint { get; set; }
    }
}
