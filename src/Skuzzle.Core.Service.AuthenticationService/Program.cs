using Skuzzle.Core.Service.AuthenticationService.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Host.ConfigureService();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapControllers();

app.Run();
