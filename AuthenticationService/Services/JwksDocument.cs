namespace AuthenticationService.Services;

/// <summary>
/// JSON-shape of the response served at <c>/.well-known/jwks.json</c>. Pre-built once by
/// <see cref="IEcdsaKeyProvider"/> when keys are loaded — consumers can fetch a fleet of
/// times without the controller re-allocating the same payload on every request.
///
/// <para>Field names rely on the global camelCase JSON naming policy (<c>Keys</c> → <c>"keys"</c>).
/// The key entries use spec-defined lowercase identifiers (<c>kty</c>, <c>crv</c>, <c>x</c>,
/// <c>y</c>, <c>use</c>, <c>alg</c>, <c>kid</c>) which the same policy emits correctly from
/// PascalCase property names.</para>
/// </summary>
public sealed record JwksDocument(IReadOnlyList<JwksKey> Keys);

/// <summary>
/// One public key in a <see cref="JwksDocument"/>. Field names follow the JSON Web Key
/// spec — see <see cref="JwksDocument"/> for the naming-policy contract.
/// </summary>
public sealed record JwksKey(
    string Kty,
    string Crv,
    string X,
    string Y,
    string Use,
    string Alg,
    string Kid);
