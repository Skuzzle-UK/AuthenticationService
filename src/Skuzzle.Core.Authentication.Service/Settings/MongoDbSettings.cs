using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Authentication.Service.Settings;

public class MongoDbSettings
{
    [Required]
    public required string ConnectionString { get; set; } = null!;

    [Required]
    public required string DatabaseName { get; set; } = null!;
}
