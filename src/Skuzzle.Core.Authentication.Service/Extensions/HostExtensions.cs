using AutoMapper.Extensions.ExpressionMapping;
using FluentValidation;
using Microsoft.EntityFrameworkCore;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Services.Interfaces;
using Skuzzle.Core.Authentication.Service.Settings;
using Skuzzle.Core.Authentication.Service.Storage;
using Skuzzle.Core.Authentication.Service.Storage.Contexts;
using Skuzzle.Core.Authentication.Service.Storage.Entities;
using Skuzzle.Core.Authentication.Service.Validators;
using Skuzzle.Core.Lib.MongoDb;

namespace Skuzzle.Core.Authentication.Service.Extensions;

internal static class HostExtensions
{
    internal static IHostBuilder ConfigureService(this IHostBuilder host)
    {
        return host.ConfigureServices((hostContext, services) =>
        {
            var mongoSettingsSection = hostContext.Configuration.GetSection(nameof(MongoDbSettings));
            if (mongoSettingsSection.Exists())
            {
                host.ConfigureMongoDb<ApplicationMongoDbContext>();
            }
            else // MySQL
            {
                services.AddDbContext<ApplicationDbContext>(options =>
                    options.UseMySQL(hostContext.Configuration.GetConnectionString("DefaultConnection")!));
            }

            services.AddMemoryCache();
            services.AddServices();
            services.AddValidators();
            services.AddRepositories(hostContext);
            services.AddValidatedSettings(hostContext);
            services.AddAutoMapper(cfg => cfg.AddExpressionMapping(), typeof(MappingProfiles));
            services.AddControllers();
        });
    }

    internal static IServiceCollection AddServices(this IServiceCollection services) =>
        services
            .AddScoped<IPasswordHashService, PasswordHashService>()
            .AddSingleton<ITokenService, TokenService>()
            .AddScoped<IUserService, UserService>()
            .AddScoped<IRoleService, RoleService>()
            .AddScoped<IEncryptionService, EncryptionService>();

    internal static IServiceCollection AddRepositories(this IServiceCollection services, HostBuilderContext hostContext)
    {
        var mongoSettingsSection = hostContext.Configuration.GetSection(nameof(MongoDbSettings));
        if (mongoSettingsSection.Exists())
        {
            services
                .AddScoped<IRepository<User>, MongoEncryptedRepository<User, UserEntity>>()
                .AddScoped<IRepository<Role>, MongoRepository<Role, RoleEntity>>();
        }
        else
        {
            services
                .AddScoped<IRepository<User>, EncryptedRepository<User, UserEntity>>()
                .AddScoped<IRepository<Role>, Repository<Role, RoleEntity>>();
        }

        return services;
    }

    internal static IServiceCollection AddValidators(this IServiceCollection services) =>
        services
            .AddScoped<IValidator<UserDto>, UserDtoValidator>();

    internal static IServiceCollection AddValidatedSettings(this IServiceCollection services, HostBuilderContext hostContext)
    {
        var mongoSettingsSection = hostContext.Configuration.GetSection(nameof(MongoDbSettings));
        if (mongoSettingsSection.Exists())
        {
            services.AddOptions<MongoDbSettings>()
                .Bind(hostContext.Configuration.GetSection(nameof(MongoDbSettings)))
                .ValidateDataAnnotations()
                .ValidateOnStart();
        }

        services.AddOptions<JwtSettings>()
            .Bind(hostContext.Configuration.GetSection(nameof(JwtSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<EncryptionSettings>()
            .Bind(hostContext.Configuration.GetSection(nameof(EncryptionSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return services;
    }
}
