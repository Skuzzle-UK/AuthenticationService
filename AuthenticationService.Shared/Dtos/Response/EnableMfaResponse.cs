using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Shared.Dtos.Response;

public class EnableMfaResponse : ApiResponse
{
    public byte[]? QrCode { get; set; }

    public string? EnabledMfaProvider { get; set; }

    public EnableMfaResponse()
    {
    }

    public EnableMfaResponse(MfaProviders mfaProvider, byte[]? qrCode = null)
    {
        EnabledMfaProvider = mfaProvider.ToString();
        QrCode = qrCode;
    }
}
