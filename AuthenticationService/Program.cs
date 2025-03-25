using AuthenticationService.Extensions;

namespace AuthenticationService;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Host.ConfigureHost(builder.Configuration);

        var app = builder.Build();
        app.ConfigureApplication();
        app.Run();
    }
}
