using AutoMapper.Extensions.ExpressionMapping;
using Skuzzle.Core.Service.AuthenticationService.Extensions;
using Skuzzle.Core.Service.AuthenticationService.Models;
using Skuzzle.Core.Service.AuthenticationService.Services;
using Skuzzle.Core.Service.AuthenticationService.Settings;
using Skuzzle.Core.Service.AuthenticationService.Storage;
using Skuzzle.Core.Service.AuthenticationService.Storage.Entities;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton<IPasswordHashService, PasswordHashService>();
builder.Services.AddSingleton<ITokenService, TokenService>();

builder.Services.AddSingleton<IRepository<User>, Repository<User, UserEntity>>();

builder.Services.AddOptions<JwtSettings>()
    .Bind(builder.Configuration.GetSection(nameof(JwtSettings)))
    .ValidateDataAnnotations();
builder.Services.AddOptions<MongoDbSettings>()
    .Bind(builder.Configuration.GetSection(nameof(MongoDbSettings)))
    .ValidateDataAnnotations();

builder.Services.AddAutoMapper(cfg => cfg.AddExpressionMapping(), typeof(MappingProfiles));

builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapControllers();

app.Run();
