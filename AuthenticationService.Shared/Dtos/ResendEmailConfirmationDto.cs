namespace AuthenticationService.Shared.Dtos;

public class ResendEmailConfirmationDto
{
    public string? Email { get; set; }
    public string? callbackUri { get; set; }
}
