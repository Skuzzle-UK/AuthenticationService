namespace AuthenticationService.Shared.Dtos.Response;

public class RegistrationResponse
{
    public bool IsSuccessful { get; set; }
    public IEnumerable<string>? Errors { get; set; }
}
