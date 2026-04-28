using AuthenticationService.Settings;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace AuthenticationService.Services;

public sealed class EcdsaKeyProvider : IEcdsaKeyProvider, IDisposable
{
    private readonly ECDsa _ecdsa;

    public string KeyId { get; }
    public SigningCredentials SigningCredentials { get; }
    public SecurityKey PublicSecurityKey { get; }
    public JsonWebKey PublicJsonWebKey { get; }

    public EcdsaKeyProvider(
        IOptions<JWTSettings> jwtSettings,
        IHostEnvironment environment,
        ILogger<EcdsaKeyProvider> logger)
    {
        var settings = jwtSettings.Value;
        var resolvedPath = Path.IsPathRooted(settings.PrivateKeyPath)
            ? settings.PrivateKeyPath
            : Path.Combine(environment.ContentRootPath, settings.PrivateKeyPath);

        _ecdsa = LoadOrCreateKey(resolvedPath, environment, logger);

        var parameters = _ecdsa.ExportParameters(includePrivateParameters: false);

        KeyId = string.IsNullOrWhiteSpace(settings.KeyId) || settings.KeyId == "auto"
            ? ComputeThumbprint(parameters)
            : settings.KeyId;

        var privateKey = new ECDsaSecurityKey(_ecdsa) { KeyId = KeyId };
        SigningCredentials = new SigningCredentials(privateKey, SecurityAlgorithms.EcdsaSha256);

        var publicEcdsa = ECDsa.Create();
        publicEcdsa.ImportParameters(parameters);
        PublicSecurityKey = new ECDsaSecurityKey(publicEcdsa) { KeyId = KeyId };

        PublicJsonWebKey = new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
            Crv = JsonWebKeyECTypes.P256,
            X = Base64UrlEncoder.Encode(parameters.Q.X),
            Y = Base64UrlEncoder.Encode(parameters.Q.Y),
            Use = "sig",
            Alg = SecurityAlgorithms.EcdsaSha256,
            Kid = KeyId,
        };
    }

    private static ECDsa LoadOrCreateKey(string path, IHostEnvironment environment, ILogger logger)
    {
        if (File.Exists(path))
        {
            var pem = File.ReadAllText(path);
            var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(pem);
            logger.LogInformation("Loaded ES256 signing key from '{Path}'.", path);
            return ecdsa;
        }

        if (!environment.IsDevelopment())
        {
            throw new InvalidOperationException(
                $"JWT signing key not found at '{path}'. " +
                "Auto-generation is disabled outside Development. " +
                "Provide the key via your deployment's secret store.");
        }

        logger.LogWarning(
            "No signing key found at '{Path}'. Generating a new ES256 key for Development. " +
            "DO NOT use this key in production.", path);

        var generated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(path, generated.ExportECPrivateKeyPem());
        return generated;
    }

    private static string ComputeThumbprint(ECParameters parameters)
    {
        var raw = new byte[parameters.Q.X!.Length + parameters.Q.Y!.Length];
        Buffer.BlockCopy(parameters.Q.X, 0, raw, 0, parameters.Q.X.Length);
        Buffer.BlockCopy(parameters.Q.Y, 0, raw, parameters.Q.X.Length, parameters.Q.Y.Length);
        var hash = SHA256.HashData(raw);
        return Base64UrlEncoder.Encode(hash);
    }

    public void Dispose() => _ecdsa.Dispose();
}
