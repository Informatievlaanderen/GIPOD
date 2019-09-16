using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OAuth.Samples.Common;
using OAuth.Samples.Common.Services;

namespace AuthorizationCodeFlow.B2B.JsonWebKey
{
    public class AppHost : IAppHost
    {
        private readonly IConfiguration _configuration;
        private readonly OAuthOptions _oAuthOptions;
        private readonly IDataProvider _dataProvider;
        private const string SpaceSeparator = " ";
        private const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        public AppHost(OAuthOptions oAuthOptions,
            IDataProvider dataProvider,
            IConfiguration configuration)
        {
            _oAuthOptions = oAuthOptions ?? throw new ArgumentNullException(nameof(oAuthOptions));
            _dataProvider = dataProvider ?? throw new ArgumentNullException(nameof(dataProvider));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public async Task RunAsync()
        {
            Console.WriteLine("Retrieving access token...");
            var jsonWebKeyText = Encoding.UTF8.GetString(Convert.FromBase64String(_oAuthOptions.JsonWebKey));
            var jsonWebKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(jsonWebKeyText);
            var accessTokenResponse = await GetAccessTokenAsync(_oAuthOptions, jsonWebKey);
            Console.WriteLine(accessTokenResponse);

            if (accessTokenResponse is AuthorizationCodeFlowResponse authorizationCodeFlowResponse)
            {
                var pdoResult = await CallGipodApi(authorizationCodeFlowResponse.AccessToken);
                Console.WriteLine(JToken.Parse(pdoResult).ToString(Formatting.Indented));

                //This whould be done just before the access token expires.
                Console.WriteLine("Exchanging refresh token...");
                accessTokenResponse = await ExchangeRefreshTokenAsync(_oAuthOptions, jsonWebKey, authorizationCodeFlowResponse.RefreshToken);
                Console.WriteLine(accessTokenResponse);
            }
        }

        private async Task<string> CallGipodApi(string accessToken)
        {
            Console.WriteLine("Calling Gipod API...");
            var searchBaseAddress = _configuration["GipodApiUrl"];
            var queryStringParameters = new Dictionary<string, string>
            {
                {"limit", "5"},
                {"offset", "0"}
            };

            var pdoResult = await _dataProvider.Get(new Uri(searchBaseAddress + "/api/v1/public-domain-occupancies"), queryStringParameters, accessToken);
            return pdoResult;
        }

        private async Task<object> GetAccessTokenAsync(OAuthOptions oAuthOptions,
            Microsoft.IdentityModel.Tokens.JsonWebKey jsonWebKey)
        {
            var clientAssertion = CreateJwtClientAssertion(oAuthOptions, jsonWebKey);

            using (var httpClient = new HttpClient())
            {
                var parameters = new Dictionary<string, string>
                {
                    {"grant_type", "authorization_code"},
                    {"code", oAuthOptions.AuthorizationCode},
                    {"client_assertion", HttpUtility.UrlEncode(clientAssertion)},
                    {"client_assertion_type", ClientAssertionType},
                    {"scope", string.Join(SpaceSeparator, oAuthOptions.Scopes)},
                    {"redirect_uri", oAuthOptions.RedirectUri.AbsoluteUri}
                };

                var httpContent = new FormUrlEncodedContent(parameters);
                var httpResponse = await httpClient.PostAsync(oAuthOptions.TokenEndpoint, httpContent);

                return !httpResponse.IsSuccessStatusCode
                    ? (object)JsonConvert.DeserializeObject<ErrorResponse>(await httpResponse.Content.ReadAsStringAsync())
                    : JsonConvert.DeserializeObject<AuthorizationCodeFlowResponse>(await httpResponse.Content.ReadAsStringAsync());
            }
        }

        private async Task<object> ExchangeRefreshTokenAsync(OAuthOptions oAuthOptions,
            Microsoft.IdentityModel.Tokens.JsonWebKey jsonWebKey,
            string refreshToken)
        {
            var clientAssertion = CreateJwtClientAssertion(oAuthOptions, jsonWebKey);

            using (var httpClient = new HttpClient())
            {
                var parameters = new Dictionary<string, string>
                {
                    {"grant_type", "refresh_token"},
                    {"refresh_token", refreshToken},
                    {"client_assertion", HttpUtility.UrlEncode(clientAssertion)},
                    {"client_assertion_type", ClientAssertionType}
                };

                var httpContent = new FormUrlEncodedContent(parameters);
                var httpResponse = await httpClient.PostAsync(oAuthOptions.TokenEndpoint, httpContent);

                return !httpResponse.IsSuccessStatusCode
                    ? (object)JsonConvert.DeserializeObject<ErrorResponse>(await httpResponse.Content.ReadAsStringAsync())
                    : JsonConvert.DeserializeObject<AuthorizationCodeFlowResponse>(await httpResponse.Content.ReadAsStringAsync());
            }
        }

        private string CreateJwtClientAssertion(OAuthOptions oAuthOptions,
            Microsoft.IdentityModel.Tokens.JsonWebKey jwk)
        {

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddMinutes(960),
                SigningCredentials = new SigningCredentials(jwk, SecurityAlgorithms.RsaSha256Signature),
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim("sub", oAuthOptions.ClientId.ToString()),
                    new Claim("iss", oAuthOptions.ClientId.ToString()),
                    new Claim("jti", Guid.NewGuid().ToString()),
                    new Claim("aud", oAuthOptions.TokenEndpoint.ToString())
                })
            };

            return tokenHandler.WriteToken(tokenHandler.CreateJwtSecurityToken(tokenDescriptor));
        }
    }
}