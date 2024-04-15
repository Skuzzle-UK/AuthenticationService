using AutoMapper.Extensions.ExpressionMapping;
using FluentValidation;
using Skuzzle.Core.Service.AuthenticationService.Dtos;
using Skuzzle.Core.Service.AuthenticationService.Models;
using Skuzzle.Core.Service.AuthenticationService.Services;
using Skuzzle.Core.Service.AuthenticationService.Settings;
using Skuzzle.Core.Service.AuthenticationService.Storage;
using Skuzzle.Core.Service.AuthenticationService.Storage.Entities;
using Skuzzle.Core.Service.AuthenticationService.Validators;

namespace Skuzzle.Core.Service.AuthenticationService.Extensions;

internal static class HostExtensions
{
    internal static IHostBuilder ConfigureService(this IHostBuilder host) =>
        host.ConfigureServices((hostContext, services) =>
        {
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
