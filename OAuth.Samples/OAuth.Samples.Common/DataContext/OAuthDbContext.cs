using Microsoft.EntityFrameworkCore;

namespace OAuth.Samples.Common.DataContext
{
    public class OAuthDbContext : DbContext
    {
        public OAuthDbContext(DbContextOptions<OAuthDbContext> options) : base(options)
        {
        }

        public DbSet<OAuthResponse> OAuthResponses { get; set; }
    }
}
