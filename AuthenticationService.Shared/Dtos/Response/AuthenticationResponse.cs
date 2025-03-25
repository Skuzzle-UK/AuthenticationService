using AuthenticationService.Shared.Models;

namespace AuthenticationService.Shared.Dtos.Response;

public class AuthenticationResponse
{
    public bool IsSuccessful { get; set; }
    public string? ErrorMessage { get; set; }
    public Token? Token { get; set; }
    public bool? MfaRequired { get; set; }
    public string? MfaProvider { get; set; }
}
