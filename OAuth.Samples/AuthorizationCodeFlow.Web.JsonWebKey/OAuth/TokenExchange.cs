using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using AuthorizationCodeFlow.Web.JsonWebKey.OAuth.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using OAuth.Samples.Common;
using OAuth.Samples.Common.DataContext;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth
{
    public class TokenExchange
    {
        private readonly ICertificateRetriever _certificateRetriever;
        private readonly OAuthOptions _oAuthOptions;
        private readonly IHttpClientFactory _httpClientFactory;

        
        public TokenExchange(IOptions<OAuthOptions> config, ICertificateRetriever certificateRetriever, IHttpClientFactory httpClientFactory)
        {
            _oAuthOptions = config?.Value ?? throw new ArgumentNullException();
            _certificateRetriever = certificateRetriever ?? throw new ArgumentNullException(nameof(certificateRetriever));
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        }

        private const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        public async Task<IActionResult> Login(string code, OAuthDbContext dbContext, Func<RedirectToActionResult> redirectToAction, Func<ErrorResponse, UnprocessableEntityObjectResult> unprocessable)
        {
            var jsonWebKeyText = Encoding.UTF8.GetString(Convert.FromBase64String(_oAuthOptions.JsonWebKey));
            var jsonWebKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(jsonWebKeyText);
            var clientAssertion = CreateJwtClientAssertion(jsonWebKey, _oAuthOptions.ClientId, _oAuthOptions.TokenEndpoint);

            var postParams = new Dictionary<string, string>
            {
                {"grant_type", "authorization_code"},
                {"code", code},
                {"client_assertion", HttpUtility.UrlEncode(clientAssertion)},
                {"client_assertion_type", ClientAssertionType},
                {"redirect_uri", _oAuthOptions.RedirectUri.AbsoluteUri}
            };

            var httpClient = _httpClientFactory.CreateClient("OAuthClient");
            var httpContent = new FormUrlEncodedContent(postParams);
            var httpResponse = await httpClient.PostAsync(_oAuthOptions.TokenEndpoint, httpContent);

            if (httpResponse.IsSuccessStatusCode)
            {
                var oAuthResponse =
                    JsonConvert.DeserializeObject<OAuthResponse>(await httpResponse.Content.ReadAsStringAsync());

                var accessTokenForUi = oAuthResponse.AccessToken;
                
                OAuthAccessToken accessTokenForApi = await ExchangeAccesToken(accessTokenForUi);
                var oAuthResponseForApi = new OAuthResponse
                {
                    Scope = accessTokenForApi.Scope,
                    AccessToken = accessTokenForApi.AccessToken,
                    ExpiresIn = accessTokenForApi.ExpiresIn.ToString(),
                    RefreshToken = accessTokenForApi.RefreshToken
                };
                
                var dbValue = dbContext.OAuthResponses.Find(1);
                if (dbValue != null)
                {
                    dbContext.Entry(dbValue).State = EntityState.Detached;
                    dbContext.OAuthResponses.Attach(oAuthResponseForApi);
                    dbContext.Entry(oAuthResponseForApi).State = EntityState.Modified;
                }
                else
                {
                    dbContext.OAuthResponses.Add(oAuthResponseForApi);
                }

                dbContext.SaveChanges();
                return redirectToAction();
            }

            var errorResponse = JsonConvert.DeserializeObject<ErrorResponse>(await httpResponse.Content.ReadAsStringAsync());
            return unprocessable(errorResponse);
        }
        
        private string CreateJwtClientAssertion(Microsoft.IdentityModel.Tokens.JsonWebKey jwk, int clientId, Uri tokenEndpoint)
        {

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddMinutes(960),
                SigningCredentials = new SigningCredentials(jwk, SecurityAlgorithms.RsaSha256Signature),
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim("sub", clientId.ToString()),
                    new Claim("iss", clientId.ToString()),
                    new Claim("jti", Guid.NewGuid().ToString()),
                    new Claim("aud", tokenEndpoint.ToString())
                })
            };

            return tokenHandler.WriteToken(tokenHandler.CreateJwtSecurityToken(tokenDescriptor));
        }

        public async Task<OAuthAccessToken> ExchangeAccesToken(string accessToken)
        {
            var sourcePrincipal = await GetIdentity(accessToken);
            var scopes = MapRolesToScopes(sourcePrincipal).ToArray();

            if (!scopes.Any())
            {
                return new OAuthAccessToken
                {
                    CreationTimestampUtc = DateTime.UtcNow,
                    Error = "Principal lacks the required scopes."
                };
            }

            var exchangeClientJsonWebKeyText = Encoding.UTF8.GetString(Convert.FromBase64String(_oAuthOptions.TokenExchange.JsonWebKey));
            var exchangeClientJsonWebKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(exchangeClientJsonWebKeyText);

            var requestForExchangeAccessToken = OAuthRequestBuilder.BuildRequestForExchangeAccessToken(_oAuthOptions.TokenEndpoint.AbsoluteUri, _oAuthOptions.TokenExchange.ClientId, scopes, exchangeClientJsonWebKey, accessToken);

            return await GetOAuthAccessToken(requestForExchangeAccessToken);
        }
        
        private async Task<OAuthAccessToken> GetOAuthAccessToken(OAuthRequestInfo requestInfo)
        {
            var httpClient = _httpClientFactory.CreateClient("OAuthClient");
            var responseForAccessToken = await httpClient.PostAsync(requestInfo.Url, requestInfo.Content);

            if (!OAuthAccessToken.TryParse(await responseForAccessToken.Content.ReadAsStringAsync(), out var accessToken))
            {
                return new OAuthAccessToken
                {
                    CreationTimestampUtc = DateTime.UtcNow,
                    Error = "Cannot parse accessToken"
                };
            }

            accessToken.CreationTimestampUtc = DateTime.UtcNow;
            return accessToken;
        }
        
        private static IEnumerable<string> MapRolesToScopes(ClaimsPrincipal principal)
        {
            var scopes = new List<string>();
            foreach (var role in principal.Claims.Where(c => c.Type.Equals(ClaimTypes.Role, StringComparison.InvariantCultureIgnoreCase)).Select(x => x.Value))
            {
                switch (role.ToLower().Trim())
                {
                    case "gipod raadpleger":
                        scopes.AddRange(new[]
                        {
                            "gipod_pdo_read"
                        });
                        break;
                    case "gipod bijdrager":
                        scopes.AddRange(new[]
                        {
                            "gipod_pdo_write"
                        });
                        break;
                }
            }

            return scopes.Distinct();
        }
        
        public static void SetOAuthToken(HttpRequestHeaders headers, string token, X509Certificate2 signingCertificate)
        {
            if (headers == null)
            {
                throw new ArgumentNullException("headers", "the headers can not be null");
            }

            if (signingCertificate == null)
            {
                throw new ArgumentNullException("signingCertificate", "the signing certificate can not be null");
            }

            headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            headers.Add("X-Client-Cert", Convert.ToBase64String(signingCertificate.Export(X509ContentType.Cert)));
            headers.Add("X-Token-Signature", CreateSignature(token, signingCertificate));
        }
        
        private static string CreateSignature(string data, X509Certificate2 certificate)
        {
            using (var sha1 = new SHA1Managed())
            {
                var encoding = new UnicodeEncoding();
                var hash = sha1.ComputeHash(encoding.GetBytes(data));

                var formatter = new RSAPKCS1SignatureFormatter(certificate.PrivateKey);
                formatter.SetHashAlgorithm("SHA1");
                var signature = formatter.CreateSignature(hash);

                return Convert.ToBase64String(signature).Replace('/', '_').Replace('+', '-');
            }
        }
        
        private async Task<ClaimsPrincipal> GetIdentity(string accessToken)
        {
            var certificate = _certificateRetriever.Get(_oAuthOptions.ResourceServerCertificateKey);

            var httpClient = _httpClientFactory.CreateClient("OAuthClient");
            SetOAuthToken(httpClient.DefaultRequestHeaders, accessToken, certificate);

            var response = await httpClient.GetAsync(_oAuthOptions.IdentityEndpoint);

            var content = response.Content;
            if (content == null)
            {
                Console.WriteLine($"Failed to authenticate using token ({accessToken}) for the identity endpoint ({_oAuthOptions.TokenEndpoint}). Response status code: {response.StatusCode}");
                return new ClaimsPrincipal();
            }

            if (response.StatusCode == HttpStatusCode.OK)
            {
                var token = await content.ReadAsStringAsync();
                try
                {
                    var fixedGeoSecureToken = GeoSecureTokenFixer.Fixit(token);
                    var jsonWebToken = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(fixedGeoSecureToken);

                    var claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(jsonWebToken.Claims, "OAuth"));
                    if (claimsPrincipal.Identity != null && !string.IsNullOrEmpty(claimsPrincipal.Identity.Name) && claimsPrincipal.Identity.IsAuthenticated)
                    {
                        return claimsPrincipal;
                    }

                    return new ClaimsPrincipal();
                }
                catch (Exception)
                {
                    Console.WriteLine($"Failed to authenticate using token ({accessToken}) for the identity endpoint ({_oAuthOptions.TokenEndpoint}). The content contained no valid jwt. Content: {token}");
                }
            }
            else
            {
                Console.WriteLine($"Failed to authenticate using token ({accessToken}) for the identity endpoint ({_oAuthOptions.TokenEndpoint}). Response status code: {response.StatusCode}");
            }

            return new ClaimsPrincipal();
        }
    }
}