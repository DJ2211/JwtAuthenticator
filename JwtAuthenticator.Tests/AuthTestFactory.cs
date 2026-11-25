using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Hosting;
using JwtAuthenticator.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace JwtAuthenticator.Tests;
public class AuthTestFactory : WebApplicationFactory<Program>
{
    private readonly string _testDbPath = Path.Combine(Path.GetTempPath(), $"jwt_auth_test_{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.ConfigureServices(services =>
        {
            //Remove the production/dev DbContext registration
            var descriptor = services.SingleOrDefault(
                d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));

            if(descriptor is not null)
            {
                services.Remove(descriptor);
            }

            // Register isolated SQLite DB for this test factory
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlite($"Data Source={_testDbPath}"));

            //Ensure schema is created before DbSeeder runs
            using var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            db.Database.EnsureCreated();
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (File.Exists(_testDbPath))
        {
            try { File.Delete(_testDbPath); } catch { /* ignore file lock on cleanup */ }
        }
    }
}
