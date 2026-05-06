using AuthenticationService.Settings;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace AuthenticationService.Services;

/// <summary>
/// Loads every <c>*.pem</c> ES256 key from the configured directory and exposes them as a
/// signing credential (active key only) plus a list of public keys / JWKs for validation
/// and discovery. Supports rotation by holding multiple keys simultaneously — one signs new
/// tokens; all are advertised in the JWKS so consumers can validate tokens issued by any of
/// them during overlap windows.
///
/// <para>Dev convenience: if the directory is empty in Development, generates a single key
/// to disk so <c>dotnet run</c> works first time. Production refuses to start without at
/// least one key — keys are operator-provisioned, not auto-generated.</para>
/// </summary>
public sealed class EcdsaKeyProvider : IEcdsaKeyProvider, IDisposable
{
    private readonly IReadOnlyList<LoadedKey> _allKeys;
    private readonly LoadedKey _activeKey;

    public string KeyId => _activeKey.KeyId;
    public SigningCredentials SigningCredentials { get; }
    public IReadOnlyList<SecurityKey> PublicSecurityKeys { get; }
    public IReadOnlyList<JsonWebKey> PublicJsonWebKeys { get; }

    public EcdsaKeyProvider(
        IOptions<JWTSettings> jwtSettings,
        IHostEnvironment environment,
        ILogger<EcdsaKeyProvider> logger)
    {
        var settings = jwtSettings.Value;
        var resolvedDir = Path.IsPathRooted(settings.PrivateKeyDirectory)
            ? settings.PrivateKeyDirectory
            : Path.Combine(environment.ContentRootPath, settings.PrivateKeyDirectory);

        _allKeys = LoadOrCreateKeys(resolvedDir, environment, logger);

        foreach (var key in _allKeys)
        {
            logger.LogInformation(
                "Loaded ES256 signing key {KeyId} from '{Path}'.",
                key.KeyId, key.SourcePath);
        }

        _activeKey = SelectActiveKey(_allKeys, settings.ActiveKeyId, logger);

        SigningCredentials = new SigningCredentials(
            new ECDsaSecurityKey(_activeKey.Ecdsa) { KeyId = _activeKey.KeyId },
            SecurityAlgorithms.EcdsaSha256);

        PublicSecurityKeys = _allKeys.Select(k => (SecurityKey)k.PublicKey).ToList();
        PublicJsonWebKeys = _allKeys.Select(k => k.JsonWebKey).ToList();
    }

    public void Dispose()
    {
        foreach (var key in _allKeys)
        {
            key.Dispose();
        }
    }

    private static List<LoadedKey> LoadOrCreateKeys(string directory, IHostEnvironment environment, ILogger logger)
    {
        if (!Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var pemFiles = Directory.GetFiles(directory, "*.pem");

        if (pemFiles.Length == 0)
        {
            if (!environment.IsDevelopment())
            {
                throw new InvalidOperationException(
                    $"No JWT signing keys found in '{directory}'. Auto-generation is disabled " +
                    "outside Development. Provide one or more PEM keys via the deployment's secret store.");
            }

            logger.LogWarning(
                "No signing keys found in '{Directory}'. Generating a new ES256 key for Development. " +
                "DO NOT use this key in production.",
                directory);

            using var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var newPath = Path.Combine(directory, "jwt-signing.pem");
            File.WriteAllText(newPath, generated.ExportECPrivateKeyPem());

            pemFiles = Directory.GetFiles(directory, "*.pem");
        }

        return pemFiles.Select(LoadedKey.FromPemFile).ToList();
    }

    private static LoadedKey SelectActiveKey(
        IReadOnlyList<LoadedKey> keys,
        string activeKeyId,
        ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(activeKeyId) || activeKeyId == "auto")
        {
            var first = keys[0];
            logger.LogInformation(
                "Active signing key is {KeyId} (auto-selected; set JWTSettings:ActiveKeyId for explicit control during rotation).",
                first.KeyId);
            return first;
        }

        var match = keys.FirstOrDefault(k => k.KeyId == activeKeyId);
        if (match is null)
        {
            throw new InvalidOperationException(
                $"JWTSettings:ActiveKeyId is '{activeKeyId}' but no loaded key has that thumbprint. " +
                $"Available keys: {string.Join(", ", keys.Select(k => k.KeyId))}.");
        }

        logger.LogInformation(
            "Active signing key is {KeyId} (explicit via JWTSettings:ActiveKeyId).",
            match.KeyId);
        return match;
    }

    private static string ComputeThumbprint(ECParameters parameters)
    {
        var raw = new byte[parameters.Q.X!.Length + parameters.Q.Y!.Length];
        Buffer.BlockCopy(parameters.Q.X, 0, raw, 0, parameters.Q.X.Length);
        Buffer.BlockCopy(parameters.Q.Y, 0, raw, parameters.Q.X.Length, parameters.Q.Y.Length);
        var hash = SHA256.HashData(raw);
        return Base64UrlEncoder.Encode(hash);
    }

    private sealed class LoadedKey : IDisposable
    {
        public required ECDsa Ecdsa { get; init; }
        public required string KeyId { get; init; }
        public required ECDsaSecurityKey PublicKey { get; init; }
        public required JsonWebKey JsonWebKey { get; init; }
        public required string SourcePath { get; init; }

        public static LoadedKey FromPemFile(string path)
        {
            var pem = File.ReadAllText(path);
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);

            var parameters = ecdsa.ExportParameters(includePrivateParameters: false);
            var keyId = ComputeThumbprint(parameters);

            var publicEcdsa = ECDsa.Create();
            publicEcdsa.ImportParameters(parameters);
            var publicKey = new ECDsaSecurityKey(publicEcdsa) { KeyId = keyId };

            var jwk = new JsonWebKey
            {
                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                Crv = JsonWebKeyECTypes.P256,
                X = Base64UrlEncoder.Encode(parameters.Q.X),
                Y = Base64UrlEncoder.Encode(parameters.Q.Y),
                Use = "sig",
                Alg = SecurityAlgorithms.EcdsaSha256,
                Kid = keyId,
            };

            return new LoadedKey
            {
                Ecdsa = ecdsa,
                KeyId = keyId,
                PublicKey = publicKey,
                JsonWebKey = jwk,
                SourcePath = path,
            };
        }

        public void Dispose() => Ecdsa.Dispose();
    }
}
