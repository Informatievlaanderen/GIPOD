using Newtonsoft.Json;

namespace OAuth.Samples.Common
{
    public class OAuthResponse
    {
        public int Id { get; private set; } = 1;
        
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
        [JsonProperty("scope")]
        public string Scope { get; set; }
        [JsonProperty("expires_in")]
        public string ExpiresIn { get; set; }
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
        [JsonProperty("token_type")]
        public string TokenType { get; set; }
    }
}
