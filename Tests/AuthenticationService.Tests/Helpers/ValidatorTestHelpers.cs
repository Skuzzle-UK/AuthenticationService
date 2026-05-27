using AuthenticationService.Entities;
using AuthenticationService.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace AuthenticationService.Tests.Helpers;

/// <summary>
/// Stubs shared across the per-validator test files. Each one is small, but several
/// validators need the same shape (Identity user-manager stub, IdentitySettings options,
/// IHostEnvironment stub) so centralising avoids drift between files.
/// </summary>
internal static class ValidatorTestHelpers
{
    public static UserManager<User> StubUserManager(string? userName = null, string? email = null)
    {
        var store = Substitute.For<IUserStore<User>>();
        var manager = Substitute.For<UserManager<User>>(store, null!, null!, null!, null!, null!, null!, null!, null!);
        manager.GetUserNameAsync(Arg.Any<User>()).Returns(userName);
        manager.GetEmailAsync(Arg.Any<User>()).Returns(email);
        return manager;
    }

    public static IOptions<IdentitySettings> MakeIdentitySettings(IEnumerable<string> reserved) =>
        Options.Create(new IdentitySettings
        {
            User = new UserSettings { ReservedUserNames = reserved.ToList() },
        });

    public static IHostEnvironment StubEnvironment(string envName)
    {
        var env = Substitute.For<IHostEnvironment>();
        env.EnvironmentName.Returns(envName);
        return env;
    }
}
