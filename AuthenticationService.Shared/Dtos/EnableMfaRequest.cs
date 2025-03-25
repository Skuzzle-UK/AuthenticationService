using AuthenticationService.Shared.Enums;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Shared.Dtos;

public class EnableMfaRequest
{
    public MfaProviders? Preferred2FAProvider { get; set; }
}
