using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Service.AuthenticationService.Settings;

public class EncryptionSettings
{
    [Required]
    public required byte[] Key { get; set; }

    [Required]
    public required byte[] InitialisationVector { get; set; }

    [Required]
    public int Iterations { get; set; }
}
