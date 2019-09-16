using Newtonsoft.Json;

namespace OAuth.Samples.Common
{
    public class AuthorizationCodeFlowResponse: ClientCredentialGrantResponse
    {
        [JsonProperty("refresh_token", Order = 5)]
        public string RefreshToken { get; set; }
    }
}