using Skuzzle.Core.Authentication.Service.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Host.ConfigureService();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// https://bitbucket.org/i_am_a_kernel/mongodbmigrations/src/master/
//new MigrationEngine()
//    .UseDatabase(_settings.ConnectionString, _settings.DatabaseName)
//    .UseAssembly(Assembly)
//    .Run();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapControllers();

app.Run();
