using AuthenticationService.Entities;
using AuthenticationService.JwtFeatures;
using AuthenticationService.Services;
using AuthenticationService.Settings;
using AuthenticationService.Validators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AuthenticationService;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddAutoMapper(typeof(Program));

        builder.Services.AddDbContext<DatabaseContext>(opt => 
        {
            opt.UseMySQL(builder.Configuration.GetConnectionString("MySQL"));
        });

        builder.Services.AddIdentity<User, Role>(opt =>
        {
            opt.Password.RequiredLength = 8;
            opt.User.RequireUniqueEmail = true;
            opt.Lockout.AllowedForNewUsers = true;
            opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(2);
            opt.Lockout.MaxFailedAccessAttempts = 3;
        })
            .AddEntityFrameworkStores<DatabaseContext>()
            .AddPasswordValidator<CustomPasswordValidator<User>>();

        var jwtSettings = builder.Configuration.GetSection("JWTSettings");

        builder.Services.AddAuthentication(opt =>
        {
            opt.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            opt.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(opt =>
        {
            opt.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings["ValidIssuer"],
                ValidAudience = jwtSettings["ValidAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.GetSection("SecurityKey").Value))
            };
        });

        builder.Services.AddAuthorizationBuilder()
            .AddPolicy("OnlyAdminUsers", policy => policy.RequireRole("Admin"));
        builder.Services.AddSingleton<JwtHandler>();

        builder.Services.AddOptions<EmailServiceSettings>().Bind(builder.Configuration.GetSection(nameof(EmailServiceSettings)));

        builder.Services.AddSingleton<IEmailService, EmailService>();

        builder.Services.AddControllers();

        var app = builder.Build();

        using (var scope = app.Services.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<DatabaseContext>();
            dbContext.Database.Migrate();
        }

        app.UseHttpsRedirection();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        app.Run();
    }
}
