using Microsoft.AspNetCore.Mvc;

namespace AuthorizationCodeFlow.Web.JsonWebKey.Controllers
{
    public class HomeController : Controller
    {
        // GET: Home
        public IActionResult Index()
        {
            return View();
        }
    }
}