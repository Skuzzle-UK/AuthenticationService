using AuthenticationService.Shared.Enums;

namespace AuthenticationService.Shared.Dtos;

public class EnableMfaRequest
{
    public MfaProviders? PreferredMfaProvider { get; set; }
}
