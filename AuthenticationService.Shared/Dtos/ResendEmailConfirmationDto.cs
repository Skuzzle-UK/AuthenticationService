namespace AuthenticationService.Shared.Dtos;

public class ResendEmailConfirmationDto
{
    public string? Email { get; set; }
    public string? CallbackUri { get; set; }
}
