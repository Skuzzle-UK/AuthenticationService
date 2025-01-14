#pragma warning disable
using System.ComponentModel.DataAnnotations;

namespace Skuzzle.Core.Authentication.Client.Settings;

public class AuthenticationClientSettings
{
    public string LoginUrl { get; set; }

    public string RefreshUrl { get; set; }

    public string RegisterUrl { get; set; }

    public int? RetryCount { get; set; }

    public int? RetryDelay { get; set; }

    public int? DefaultRefreshExpiry { get; set; }
}
