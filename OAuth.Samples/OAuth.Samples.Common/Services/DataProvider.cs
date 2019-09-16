using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using OAuth.Samples.Common.DataContext;

namespace OAuth.Samples.Common.Services
{
    public class DataProvider : IDataProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly OAuthDbContext _dbContext;

        public DataProvider(IHttpClientFactory httpClientFactory, OAuthDbContext dbContext)
        {
            _httpClientFactory = httpClientFactory;
            _dbContext = dbContext;
        }

        public async Task<string> Get(Uri apiUri, Dictionary<string, string> queryStringParameters, string accessToken = null, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                var oauthResponse = _dbContext.OAuthResponses.Find(1);
                accessToken = oauthResponse.AccessToken;
            }

            var client = _httpClientFactory.CreateClient("GET");
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            var result = await client.GetAsync(apiUri, cancellationToken);
            return await result.Content.ReadAsStringAsync();
        }
    }
}
