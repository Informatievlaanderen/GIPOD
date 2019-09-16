using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OAuth.Samples.Common;
using OAuth.Samples.Common.DataContext;
using OAuth.Samples.Common.Services;

namespace ClientCredentialGrant.JsonWebKey
{
    class Program
    {
        public static async Task Main()
        {
            IConfiguration config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddUserSecrets<Program>(optional: true)
                .Build();

            var serviceProvider = new ServiceCollection()
                .AddSingleton(config.GetSection("OAuth").Get<OAuthOptions>())
                .AddSingleton<IAppHost, AppHost>()
                .AddSingleton(config)
                .AddHttpClient()
                .AddDbContext<OAuthDbContext>(options => options.UseInMemoryDatabase(databaseName: "OAuthDB"))
                .AddScoped<IDataProvider, DataProvider>()
                .BuildServiceProvider();

            await serviceProvider.GetService<IAppHost>().RunAsync();

            Console.Read();
        }
    }
}
