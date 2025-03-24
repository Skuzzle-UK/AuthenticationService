namespace AuthenticationService.Dtos.Response;

public class UserRegistrationResponse
{
    public bool IsSuccessful { get; set; }
    public IEnumerable<string>? Errors { get; set; }
}
