#pragma warning disable

using AuthenticationService.Enums;

namespace AuthenticationService.Entities;

public class AccessRecord
{
    public int Id { get; set; }
    public string TokenJti { get; set; }
    public string UserId { get; set; }
    public string IpAddress { get; set; }
    public DateTime CreatedAt { get; set; }
    public bool Revoked { get; set; }
    public Severity Severity { get; set; }
}
