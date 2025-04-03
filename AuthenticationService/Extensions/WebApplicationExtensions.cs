using AuthenticationService.Middleware;
using AuthenticationService.Storage;
using AuthenticationService.Storage.Seed;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationService.Extensions;

public static class WebApplicationExtensions
{
    public static WebApplication ConfigureApplication(this WebApplication app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(opt =>
        {
            opt.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
        });

        app.RunMigrations();
        app.RuntimeDbSeed();
        
        if (!app.Environment.IsDevelopment())
        {
            app.UseExceptionHandler("/Error");
            app.UseHsts();
        }
        
        app.UseHttpsRedirection();
        app.UseStaticFiles();
        app.UseApplicationMiddleware();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseRateLimiter();
        app.MapControllers();
        app.MapRazorPages();

        return app;
    }

    public static WebApplication UseApplicationMiddleware(this WebApplication app)
    {
        app.UseMiddleware<RevokedTokenMiddleware>();
        return app;
    }

    public static WebApplication RunMigrations(this WebApplication app)
    {
        using (var scope = app.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            dbContext.Database.Migrate();
        }

        return app;
    }
}
