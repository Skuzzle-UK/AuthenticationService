using AuthenticationService.Shared.Constants;
using Microsoft.AspNetCore.Authorization;

namespace AuthenticationService.TokenValidationLib;

/// <summary>
/// Extensions for scope-based authorization on top of the auth service's service-identity
/// tokens (OAuth client-credentials grant). Use in <c>builder.Services.AddAuthorization(...)</c>
/// to register one policy per scope your service cares about:
///
/// <code>
/// services.AddAuthorization(opt =>
/// {
///     opt.AddScopePolicy("inventory.read");
///     opt.AddScopePolicy("inventory.write");
/// });
/// </code>
///
/// then guard endpoints with <c>[Authorize(Policy = "inventory.read")]</c>.
///
/// <para>Each policy checks the JWT's <c>scope</c> claim — a space-separated list of
/// granted scopes per OAuth convention — and returns success iff the requested scope is
/// present. User JWTs (from the <c>/authenticate</c> flow) don't carry a <c>scope</c>
/// claim and so will fail any scope policy by default; this is intentional — scope
/// policies are for service-to-service calls, not user-on-behalf-of calls.</para>
/// </summary>
public static class AuthorizationOptionsExtensions
{
    /// <summary>
    /// Registers a policy named <paramref name="requiredScope"/> that requires the
    /// caller's JWT to carry that scope in its <c>scope</c> claim.
    /// </summary>
    /// <param name="options">The <see cref="AuthorizationOptions"/> being built.</param>
    /// <param name="requiredScope">
    /// The scope to require (e.g. <c>inventory.read</c>). Used both as the policy name
    /// and as the value matched against the <c>scope</c> claim — pick stable strings;
    /// renaming a scope across services is a coordinated change.
    /// </param>
    public static AuthorizationOptions AddScopePolicy(
        this AuthorizationOptions options,
        string requiredScope)
    {
        ConfigureScopePolicy(requiredScope, (name, configure) => options.AddPolicy(name, configure));
        return options;
    }

    /// <summary>
    /// <see cref="AuthorizationBuilder"/>-flavoured counterpart of
    /// <see cref="AddScopePolicy(AuthorizationOptions, string)"/>. Use when wiring up via
    /// <c>services.AddAuthorizationBuilder()</c> (the fluent style).
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
                // Standard OAuth: the scope claim is a single string with space-separated
                // entries. Split + exact-match on the required scope; the comparison is
                // case-sensitive because scope names are part of a published contract.
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
