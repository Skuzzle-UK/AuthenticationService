namespace AuthenticationService.Services;

/// <summary>
/// Response shape for <c>/.well-known/jwks.json</c>. Pre-built once by <see cref="IEcdsaKeyProvider"/>.
/// Field names rely on the global camelCase JSON naming policy.
/// </summary>
public sealed record JwksDocument(IReadOnlyList<JwksKey> Keys);

/// <summary>
/// One public key in a <see cref="JwksDocument"/>. Field names follow the JSON Web Key spec.
/// </summary>
public sealed record JwksKey(
    string Kty,
    string Crv,
    string X,
    string Y,
    string Use,
    string Alg,
    string Kid);
