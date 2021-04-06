using System;
using Newtonsoft.Json;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth.Models
{
    public class OAuthAccessToken
    {
        [JsonProperty(PropertyName = "access_token")]
        public string AccessToken { get; set; }
        public string Scope { get; set; }
        [JsonProperty(PropertyName = "expires_in")]
        public int ExpiresIn { get; set; }
        [JsonProperty(PropertyName = "refresh_token")]
        public string RefreshToken { get; set; }
        public string Error { get; set; }

        public DateTime CreationTimestampUtc { get; set; }
        public DateTime ExpirationTimestampUtc => CreationTimestampUtc + TimeSpan.FromSeconds(ExpiresIn);
        public bool IsExpired => DateTime.UtcNow > ExpirationTimestampUtc - TimeSpan.FromMinutes(5);

        public static bool TryParse(string accessTokenText, out OAuthAccessToken accessToken)
        {
            accessToken = null;
            try
            {
                accessToken = JsonConvert.DeserializeObject<OAuthAccessToken>(accessTokenText);
                return true;
            }
            catch (JsonException ex)
            {
                Console.WriteLine($"Error parsing access token: {accessTokenText}");
                return false;
            }
        }
    }
}