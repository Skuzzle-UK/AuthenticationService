namespace AuthenticationService.Dtos.Response;

public class UserAuthenticationResponse
{
    public bool IsSuccess { get; set; }
    public string? ErrorMessage { get; set; }
    public string? Token { get; set; }
    public bool? MfaRequired { get; set; }
    public string? Provider { get; set; }
}
