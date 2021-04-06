using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using AuthorizationCodeFlow.Web.JsonWebKey.OAuth.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthorizationCodeFlow.Web.JsonWebKey.OAuth
{
    public static class OAuthRequestBuilder
    {
        private const string ResponseTypeKey = "response_type";
        private const string ClientIdKey = "client_id";
        private const string ClientAssertionKey = "client_assertion";
        private const string ClientAssertionTypeKey = "client_assertion_type";
        private const string RedirectUriKey = "redirect_uri";
        private const string GrantTypeKey = "grant_type";
        private const string ScopeKey = "scope";
        private const string StateKey = "state";
        private const string CodeResponseType = "code";
        private const string RefreshTokenGrantType = "refresh_token";
        private const string AuthorizationCodeGrantType = "authorization_code";
        private const string RefreshTokenKey = "refresh_token";
        private const string SubjectTokenKey = "subject_token";
        private const string SubjectTokenTypeKey = "subject_token_type";
        private const string ActorTokenKey = "actor_token";
        private const string ActorTokenTypeKey = "actor_token_type";
        private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
        private const string ExchangeTokenGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
        private const string ClientAssertionTypeValue = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        private const string OauthAuthorizationEndpoint = "ws/oauth/v2/authorization";
        private const string OauthTokenEndpoint = "ws/oauth/v2/token";

        public static string BuildRequestForAuthorizationCode(string oAuthServiceEndpoint, string clientId, string[] scopes, string redirectUri, string state)
        {
            if (clientId == null) throw new ArgumentNullException(nameof(clientId));
            if (scopes == null || scopes.All(string.IsNullOrWhiteSpace)) throw new ArgumentNullException(nameof(scopes));
            if (redirectUri == null) throw new ArgumentNullException(nameof(redirectUri));


            var url = $"{oAuthServiceEndpoint}{OauthAuthorizationEndpoint}" +
                      $"?{ResponseTypeKey}={CodeResponseType}" +
                      $"&{ClientIdKey}={clientId}" +
                      $"&{RedirectUriKey}={HttpUtility.UrlEncode(redirectUri)}" +
                      $"&{ScopeKey}={string.Join(" ", scopes)}";

            if (!string.IsNullOrWhiteSpace(state))
            {
                url = $"{url}&{StateKey}={HttpUtility.UrlEncode(state)}";
            }

            return url;
        }

        public static OAuthRequestInfo BuildRequestForAccessToken(string oAuthServiceEndpoint, string clientId, X509Certificate2 certificate, string authorizationCode, string redirectUri)
        {
            if (clientId == null) throw new ArgumentNullException(nameof(clientId));
            if (authorizationCode == null) throw new ArgumentNullException(nameof(authorizationCode));
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));
            if (redirectUri == null) throw new ArgumentNullException(nameof(redirectUri));

            var oAuthServiceTokenEndpoint = $"{oAuthServiceEndpoint}{OauthTokenEndpoint}";


            var formContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>(GrantTypeKey, AuthorizationCodeGrantType),
                new KeyValuePair<string, string>(ClientAssertionKey, CreateJwtClientAssertion(certificate, clientId, oAuthServiceTokenEndpoint)),
                new KeyValuePair<string, string>(ClientAssertionTypeKey, ClientAssertionTypeValue),

                new KeyValuePair<string, string>(RedirectUriKey, redirectUri),
                new KeyValuePair<string, string>(CodeResponseType, authorizationCode)
            });

            return new OAuthRequestInfo(oAuthServiceTokenEndpoint, formContent);
        }

        public static OAuthRequestInfo BuildRequestForExchangeRefreshToken(string oAuthServiceEndpoint, string clientId, X509Certificate2 certificate, string refreshToken)
        {
            if (clientId == null) throw new ArgumentNullException(nameof(clientId));
            if (refreshToken == null) throw new ArgumentNullException(nameof(refreshToken));
            if (certificate == null) throw new ArgumentNullException(nameof(certificate));

            var oAuthServiceTokenEndpoint = $"{oAuthServiceEndpoint}{OauthTokenEndpoint}";

            var formContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>(GrantTypeKey, RefreshTokenGrantType),
                new KeyValuePair<string, string>(ClientAssertionKey, CreateJwtClientAssertion(certificate, clientId, oAuthServiceTokenEndpoint)),
                new KeyValuePair<string, string>(ClientAssertionTypeKey, ClientAssertionTypeValue),

                new KeyValuePair<string, string>(RefreshTokenKey, refreshToken)
            });

            return new OAuthRequestInfo(oAuthServiceTokenEndpoint, formContent);
        }

        private static string CreateJwtClientAssertion(Microsoft.IdentityModel.Tokens.JsonWebKey jwk, int clientId, string tokenEndpoint)
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
                    new Claim("aud", tokenEndpoint)
                })
            };

            return tokenHandler.WriteToken(tokenHandler.CreateJwtSecurityToken(tokenDescriptor));
        }
        
        public static OAuthRequestInfo BuildRequestForExchangeAccessToken(string oAuthServiceEndpoint, int clientId, string[] scopes, Microsoft.IdentityModel.Tokens.JsonWebKey jsonWebKey, string accessToken)
        {
            if (clientId <= 0) throw new ArgumentOutOfRangeException(nameof(clientId));
            if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));
            if (jsonWebKey == null) throw new ArgumentNullException(nameof(jsonWebKey));
            if (scopes == null) throw new ArgumentNullException(nameof(scopes));
            if (scopes.All(string.IsNullOrWhiteSpace)) throw new ArgumentException($"List of scopes cannot be empty", nameof(scopes));

            var oAuthServiceTokenEndpoint = $"{oAuthServiceEndpoint}{OauthTokenEndpoint}";

            var formContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>(GrantTypeKey, ExchangeTokenGrantType),

                new KeyValuePair<string, string>(ClientAssertionKey, CreateJwtClientAssertion(jsonWebKey, clientId, oAuthServiceTokenEndpoint)),
                new KeyValuePair<string, string>(ClientAssertionTypeKey, ClientAssertionTypeValue),

                new KeyValuePair<string, string>(SubjectTokenKey, accessToken),
                new KeyValuePair<string, string>(SubjectTokenTypeKey, AccessTokenType),

                new KeyValuePair<string, string>(ActorTokenKey, accessToken),
                new KeyValuePair<string, string>(ActorTokenTypeKey, AccessTokenType),

                new KeyValuePair<string, string>(ScopeKey, string.Join(" ", scopes))
            });

            return new OAuthRequestInfo(oAuthServiceTokenEndpoint, formContent);
        }

        private static string CreateJwtClientAssertion(X509Certificate2 certificate, string clientId, string endpoint)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddMinutes(960),
                SigningCredentials = new SigningCredentials(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSha256Signature),
                Subject = new ClaimsIdentity(new List<Claim>
                {
                    new Claim("sub", clientId),
                    new Claim("iss", clientId),
                    new Claim("jti", Guid.NewGuid().ToString()),
                    new Claim("aud", endpoint)
                })
            };

            return tokenHandler.WriteToken(tokenHandler.CreateJwtSecurityToken(tokenDescriptor));
        }
    }
}
