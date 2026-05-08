var builder = DistributedApplication.CreateBuilder(args);

var smtp = builder.AddContainer("smtp4dev", "rnwood/smtp4dev")
    .WithEndpoint(name: "smtp", targetPort: 25)
    .WithHttpEndpoint(name: "http", targetPort: 80);

var mysql = builder.AddMySql("mysql");
var authDb = mysql.AddDatabase("AuthenticationService");

var redis = builder.AddRedis("redis")
    .WithRedisInsight();

var auth = builder.AddProject<Projects.AuthenticationService>("auth")
    .WithEnvironment("EmailServerSettings__SmtpServer", smtp.GetEndpoint("smtp").Property(EndpointProperty.Host))
    .WithEnvironment("EmailServerSettings__Port", smtp.GetEndpoint("smtp").Property(EndpointProperty.Port))
    .WithEnvironment("EmailServerSettings__UserName", "")
    .WithEnvironment("EmailServerSettings__Password", "")
    .WithEnvironment("ConnectionStrings__MySQL", authDb)
    .WithEnvironment("ConnectionStrings__Redis", redis)
    .WaitFor(authDb)
    .WaitFor(redis)
    .WaitFor(smtp);

auth.WithEnvironment("PublicUrlSettings__BaseUrl", auth.GetEndpoint("https"));


builder.Build().Run();
