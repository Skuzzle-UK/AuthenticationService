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

builder.Services.AddOptions<ServiceSettings>()
    .Bind(builder.Configuration.GetSection(nameof(ServiceSettings)))
    .ValidateDataAnnotations();
builder.Services.AddOptions<MongoDbSettings>()
    .Bind(builder.Configuration.GetSection(nameof(MongoDbSettings)))
    .ValidateDataAnnotations();

builder.Services.AddAutoMapper(cfg => cfg.AddExpressionMapping(), typeof(MappingProfiles));

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.MapControllers();

app.Run();
