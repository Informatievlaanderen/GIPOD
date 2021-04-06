using System.Net.Http;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth.Models
{
    public class OAuthRequestInfo
    {
        public OAuthRequestInfo(string url, FormUrlEncodedContent content)
        {
            Url = url;
            Content = content;
        }

        public string Url { get; }
        public FormUrlEncodedContent Content { get; }
    }
}
