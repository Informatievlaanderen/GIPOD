using Newtonsoft.Json;

namespace OAuth.Samples.Common
{
    public class ClientCredentialGrantResponse
    {
        [JsonProperty("access_token", Order = 1)]
        public string AccessToken { get; set; }

        [JsonProperty("token_type", Order = 2)]
        public string TokenType { get; set; }

        [JsonProperty("expires_in", Order = 3)]
        public int ExpiresIn { get; set; }

        [JsonProperty("scope", Order = 4)]
        public string Scope { get; set; }

        public override string ToString()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }
    }
}