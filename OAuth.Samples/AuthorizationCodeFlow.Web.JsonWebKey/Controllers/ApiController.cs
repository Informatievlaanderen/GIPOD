using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthorizationCodeFlow.Web.JsonWebKey.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OAuth.Samples.Common.DataContext;
using OAuth.Samples.Common.Services;

namespace AuthorizationCodeFlow.Web.JsonWebKey.Controllers
{
    public class ApiController : Controller
    {
        private readonly IConfiguration _configuration;
        private readonly OAuthDbContext _dbContext;
        private readonly IDataProvider _dataProvider;

        public ApiController(IDataProvider dataProvider, 
            OAuthDbContext dbContext,
            IConfiguration configuration)
        {
            _dataProvider = dataProvider ?? throw new ArgumentNullException(nameof(dataProvider));
            _dbContext = dbContext ?? throw new ArgumentNullException(nameof(dbContext));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public async Task<IActionResult> Index()
        {
            var oauthResponse = _dbContext.OAuthResponses.Find(1);

            if(oauthResponse == null)
            {
                return RedirectToAction("Index", "Home");
            }

            var searchBaseAddress = _configuration["GipodApiUrl"];
            var queryStringParameters = new Dictionary<string, string>
            {
                {"limit", "5"},
                { "offset", "0"}
            };
            var detoursResult = await _dataProvider.Get(new Uri(searchBaseAddress + "/api/v1/detours"), queryStringParameters);
            var mobilityHindranceResult = await _dataProvider.Get(new Uri(searchBaseAddress + "/api/v1/mobility-hindrances"), queryStringParameters);
            var pdoResult = await _dataProvider.Get(new Uri(searchBaseAddress + "/api/v1/public-domain-occupancies"), queryStringParameters);

            var searchModel = new SearchModel() {
                Detours = JToken.Parse(detoursResult).ToString(Formatting.Indented),
                MobilityHindrances = JToken.Parse(mobilityHindranceResult).ToString(Formatting.Indented),
                PublicDomainOccupancies = JToken.Parse(pdoResult).ToString(Formatting.Indented),
                OAuthResponse = oauthResponse
            };

            return View(searchModel);
        }


    }
}