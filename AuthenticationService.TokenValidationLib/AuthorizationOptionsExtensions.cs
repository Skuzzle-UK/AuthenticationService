using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Authorization;

namespace AuthenticationService.TokenValidationLib;

/// <summary>
/// Extensions for scope-based authorization on service-identity tokens (OAuth
/// client-credentials). Register one policy per scope, then guard endpoints with
/// <c>[Authorize(Policy = "inventory.read")]</c>. User JWTs lack a <c>scope</c> claim
/// and fail these policies by design — scope policies are for S2S calls only.
/// <example>
/// <code>
/// services.AddAuthorization(opt =>
/// {
///     opt.AddScopePolicy("inventory.read");
///     opt.AddScopePolicy("inventory.write");
/// });
/// </code>
/// </example>
/// </summary>
public static class AuthorizationOptionsExtensions
{
    /// <summary>
    /// Registers a policy named <paramref name="requiredScope"/> that requires the
    /// JWT's <c>scope</c> claim to contain that scope. <c>requiredScope</c> is used as
    /// both policy name and required scope value; comparison is case-sensitive
    /// (scope names are a published contract).
    /// </summary>
    public static AuthorizationOptions AddScopePolicy(
        this AuthorizationOptions options,
        string requiredScope)
    {
        ConfigureScopePolicy(requiredScope, (name, configure) => options.AddPolicy(name, configure));
        return options;
    }

    /// <summary>
    /// <see cref="AuthorizationBuilder"/>-flavoured counterpart for the fluent
    /// <c>AddAuthorizationBuilder()</c> style.
    /// </summary>
    public static AuthorizationBuilder AddScopePolicy(
        this AuthorizationBuilder builder,
        string requiredScope)
    {
        ConfigureScopePolicy(requiredScope, (name, configure) =>
        {
            var policyBuilder = new AuthorizationPolicyBuilder();
            configure(policyBuilder);
            builder.AddPolicy(name, policyBuilder.Build());
        });
        return builder;
    }

    private static void ConfigureScopePolicy(
        string requiredScope,
        Action<string, Action<AuthorizationPolicyBuilder>> register)
    {
        if (string.IsNullOrWhiteSpace(requiredScope))
        {
            throw new ArgumentException("requiredScope must be a non-empty string.", nameof(requiredScope));
        }

        register(requiredScope, policy =>
            policy.RequireAssertion(ctx =>
            {
                // OAuth scope claim is space-separated. Case-sensitive match.
                var claim = ctx.User.FindFirst(ClaimConstants.Scope);
                if (claim is null || string.IsNullOrWhiteSpace(claim.Value))
                {
                    return false;
                }

                return claim.Value
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Contains(requiredScope, StringComparer.Ordinal);
            }));
    }
}
