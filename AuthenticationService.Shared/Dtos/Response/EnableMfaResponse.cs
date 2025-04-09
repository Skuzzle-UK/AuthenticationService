using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Shared.Dtos.Response;

public class EnableMfaResponse : ApiResponse
{
    public byte[]? QrCode { get; set; }
    public string? Key { get; set; }

    public MfaProviders? EnabledMfaProvider { get; set; }

    public EnableMfaResponse()
    {
    }

    public EnableMfaResponse(MfaProviders mfaProvider, byte[]? qrCode = null, string? key = null)
    {
        EnabledMfaProvider = mfaProvider;
        QrCode = qrCode;
        Key = key;
    }
}
