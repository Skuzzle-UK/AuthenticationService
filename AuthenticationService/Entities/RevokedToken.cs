#pragma warning disable

using System.ComponentModel.DataAnnotations;

namespace AuthenticationService.Entities;

public class RevokedToken
{
    [Required]
    public string TokenJti { get; set; }

    public string UserId { get; set; }

    public DateTime? ExpiresAt { get; set; }
}

public class AccessRecord
{
    public int Id { get; set; }
    public string TokenJti { get; set; }
    public string UserId { get; set; }
    public string IpAddress { get; set; }
    public DateTime AccessAt { get; set; }
    public bool Revoked { get; set; }
}
