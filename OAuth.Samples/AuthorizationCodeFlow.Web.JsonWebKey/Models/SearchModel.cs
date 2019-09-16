using OAuth.Samples.Common;

namespace AuthorizationCodeFlow.Web.JsonWebKey.Models
{
    public class SearchModel
    {
        public string Detours { get; set; }
        public string MobilityHindrances { get; set; }
        public string PublicDomainOccupancies { get; set; }
        public OAuthResponse OAuthResponse { get; set; }
    }
}
