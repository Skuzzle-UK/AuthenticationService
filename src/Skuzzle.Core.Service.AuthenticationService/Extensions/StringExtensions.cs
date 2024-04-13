using System.Text.RegularExpressions;

namespace Skuzzle.Core.Service.AuthenticationService.Extensions;

public static class StringExtensions
{
    public static string ReformatPlaceholders(this string value)
    {
        string pattern = @"\{(\w+)\}";
        int i = 0;
        return Regex.Replace(value, pattern, match => "{" + i++ + "}");
    }
}
