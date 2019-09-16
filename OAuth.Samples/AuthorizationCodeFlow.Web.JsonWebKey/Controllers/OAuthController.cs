using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using OAuth.Samples.Common;
using OAuth.Samples.Common.DataContext;

namespace AuthorizationCodeFlow.Web.JsonWebKey.Controllers
{
    [Route("oauth")]
    public class OAuthController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly OAuthDbContext _dbContext;
        private readonly OAuthOptions _oAuthOptions;
        private const string ClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        
        public OAuthController(IOptions<OAuthOptions> config, 
            IHttpClientFactory httpClientFactory, 
            OAuthDbContext dbContext)
        {
            _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException();
            _dbContext = dbContext;
            _oAuthOptions = config?.Value ?? throw new ArgumentNullException();
        }

        [HttpGet]
        [Route("login")]
        public IActionResult Login()
        {
            var queryParameters = new Dictionary<string, string>() {
                {"response_type", "code"},
                {"client_id", _oAuthOptions.ClientId.ToString()},
                {"redirect_uri", _oAuthOptions.RedirectUri.AbsoluteUri},
                {"scope", HttpUtility.UrlEncode(string.Join(" ", _oAuthOptions.Scopes))},
                {"state", _oAuthOptions.State}
            };
            var uri = $"{_oAuthOptions.AuthorizeEndpoint}?";
            var queryString = $"{string.Join("&", queryParameters.Select(kvp => $"{kvp.Key}={kvp.Value}"))}";
            return Redirect(uri + queryString);
        }

        [Route("callback")]
        public async Task<IActionResult> Callback(string code, string state)
        {
            var jsonWebKeyText = Encoding.UTF8.GetString(Convert.FromBase64String(_oAuthOptions.JsonWebKey));
            var jsonWebKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(jsonWebKeyText);
            var clientAssertion = CreateJwtClientAssertion(_oAuthOptions, jsonWebKey);

            var postParams = new Dictionary<string, string> {
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
                var oAuthResponse = JsonConvert.DeserializeObject<OAuthResponse>(await httpResponse.Content.ReadAsStringAsync());

                var dbValue = _dbContext.OAuthResponses.Find(1);
                if (dbValue != null)
                {
                    _dbContext.Entry(dbValue).State = EntityState.Detached;
                    _dbContext.OAuthResponses.Attach(oAuthResponse);
                    _dbContext.Entry(oAuthResponse).State = EntityState.Modified;
                }
                else
                {
                    _dbContext.OAuthResponses.Add(oAuthResponse);
                }

                _dbContext.SaveChanges();
                return RedirectToAction("Index", "Api");
            }

            var errorResponse = JsonConvert.DeserializeObject<ErrorResponse>(await httpResponse.Content.ReadAsStringAsync());
            return UnprocessableEntity(errorResponse);
        }

        [HttpPost]
        public async Task<IActionResult> ExchangeRefreshToken()
        {
            var oauthResponse = _dbContext.OAuthResponses.Find(1);

            if (oauthResponse == null)
            {
                return RedirectToAction("Index", "Home");
            }

            var jsonWebKeyText = Encoding.UTF8.GetString(Convert.FromBase64String(_oAuthOptions.JsonWebKey));
            var jsonWebKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(jsonWebKeyText);
            var clientAssertion = CreateJwtClientAssertion(_oAuthOptions, jsonWebKey);

            var parameters = new Dictionary<string, string>
            {
                {"grant_type", "refresh_token"},
                {"refresh_token", oauthResponse.RefreshToken},
                {"client_assertion", HttpUtility.UrlEncode(clientAssertion)},
                {"client_assertion_type", ClientAssertionType}
            };

            var httpClient = _httpClientFactory.CreateClient("OAuthClient");
            var httpContent = new FormUrlEncodedContent(parameters);
            var httpResponse = await httpClient.PostAsync(_oAuthOptions.TokenEndpoint, httpContent);
            if (httpResponse.IsSuccessStatusCode)
            {
                var responseString = await httpResponse.Content.ReadAsStringAsync();
                var oAuthResponse = JsonConvert.DeserializeObject<OAuthResponse>(responseString);

                var dbValue = _dbContext.OAuthResponses.Find(1);
                if (dbValue != null)
                {
                    _dbContext.Entry(dbValue).State = EntityState.Detached;
                    _dbContext.OAuthResponses.Attach(oAuthResponse);
                    _dbContext.Entry(oAuthResponse).State = EntityState.Modified;
                }
                else
                {
                    _dbContext.OAuthResponses.Add(oAuthResponse);
                }

                _dbContext.SaveChanges();
                return RedirectToAction("Index", "Api");
            }

            var errorResponse = JsonConvert.DeserializeObject<ErrorResponse>(await httpResponse.Content.ReadAsStringAsync());
            return UnprocessableEntity(errorResponse);
        }

        [Route("logout")]
        public async Task<IActionResult> Logout()
        {
            var oAuthResponse = _dbContext.OAuthResponses.Find(1);
            if (oAuthResponse != null)
            {
                _dbContext.OAuthResponses.Remove(oAuthResponse);
                _dbContext.SaveChanges();
            }

            return RedirectToAction("Index", "Home");
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
