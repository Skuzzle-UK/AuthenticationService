using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Shared.Dtos.Response;

public class EnableMfaResponse
{
    public bool IsSuccessful { get; set; }

    public string? ErrorMessage { get; set; }

    public byte[]? QrCode { get; set; }

    public MfaProviders Provider { get; set; }
}
