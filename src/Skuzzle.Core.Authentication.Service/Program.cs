using Skuzzle.Core.Authentication.Service.Extensions;
using Skuzzle.Core.Authentication.Service.Storage.Contexts;

var builder = WebApplication.CreateBuilder(args);

var environment = builder.Environment;

builder.Configuration
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{environment.EnvironmentName}.json", optional: true, reloadOnChange: true);

builder.Host.ConfigureService();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// TODO: Introduce mongo migrations maybe ? /nb
//// https://bitbucket.org/i_am_a_kernel/mongodbmigrations/src/master/
//new MigrationEngine()
//    .UseDatabase(_settings.ConnectionString, _settings.DatabaseName)
//    .UseAssembly(Assembly)
//    .Run();

var app = builder.Build();

ApplicationDbContext.ApplyMigrations(app);

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapControllers();

app.Run();
