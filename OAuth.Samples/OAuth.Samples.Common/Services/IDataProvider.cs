using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace OAuth.Samples.Common.Services
{
    public interface IDataProvider
    {
        Task<string> Get(Uri apiUri, Dictionary<string, string> queryStringParameters, string accessToken = null, CancellationToken cancellationToken = default(CancellationToken));
    }
}