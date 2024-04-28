using AutoMapper.Extensions.ExpressionMapping;
using FluentValidation;
using Skuzzle.Core.Authentication.Lib.Dtos;
using Skuzzle.Core.Authentication.Lib.Models;
using Skuzzle.Core.Authentication.Service.Services;
using Skuzzle.Core.Authentication.Service.Settings;
using Skuzzle.Core.Authentication.Service.Storage;
using Skuzzle.Core.Authentication.Service.Storage.Entities;
using Skuzzle.Core.Authentication.Service.Validators;

namespace Skuzzle.Core.Authentication.Service.Extensions;

internal static class HostExtensions
{
    internal static IHostBuilder ConfigureService(this IHostBuilder host) =>
        host.ConfigureServices((hostContext, services) =>
        {
            services.AddMemoryCache();
            services.AddServices();
            services.AddValidators();
            services.AddRepositories();
            services.AddValidatedSettings(hostContext);
            services.AddAutoMapper(cfg => cfg.AddExpressionMapping(), typeof(MappingProfiles));
            services.AddControllers();
        });

    internal static IServiceCollection AddServices(this IServiceCollection services) =>
        services
            .AddSingleton<IPasswordHashService, PasswordHashService>()
            .AddSingleton<ITokenService, TokenService>()
            .AddSingleton<IEncryptionService, EncryptionService>();

    internal static IServiceCollection AddRepositories(this IServiceCollection services) =>
        services
            .AddSingleton<IRepository<User>, MongoDbRepository<User, UserEntity>>();

    internal static IServiceCollection AddValidators(this IServiceCollection services) =>
        services
            .AddScoped<IValidator<UserDto>, UserDtoValidator>();

    internal static IServiceCollection AddValidatedSettings(this IServiceCollection services, HostBuilderContext hostContext)
    {
        services.AddOptions<JwtSettings>()
            .Bind(hostContext.Configuration.GetSection(nameof(JwtSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<MongoDbSettings>()
            .Bind(hostContext.Configuration.GetSection(nameof(MongoDbSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        services.AddOptions<EncryptionSettings>()
            .Bind(hostContext.Configuration.GetSection(nameof(EncryptionSettings)))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        return services;
    }
}
