using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace Skuzzle.Core.Authentication.Service.Extensions;

public static class StringValuesExtensions
{
    public static bool IsNullOrEmptyOrWhiteSpace(this StringValues value)
    {
        return string.IsNullOrWhiteSpace(value);
    }
}
