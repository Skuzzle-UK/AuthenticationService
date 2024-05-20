using Skuzzle.Core.Authentication.Lib.Enums;
using Skuzzle.Core.Authentication.Lib.Models;

namespace Skuzzle.Core.Authentication.Service.Extensions;

public static class IFormCollectionExtensions
{
    private const string CLIENT_ID = "client_id";
    private const string CLIENT_SECRET = "client_secret";
    private const string GRANT_TYPE = "grant_type";
    private const string USERNAME = "username";
    private const string PASSWORD = "password";
    private const string REFRESH_TOKEN = "refresh_token";

    public static AuthenticationRequest? ToAuthenticationRequest(this IFormCollection formCollection)
    {
        var canParse = Enum.TryParse(formCollection[GRANT_TYPE].ToString(), true, out GrantType grantType);
        if (!canParse)
        {
            return null;
        }

        try
        {
            return new AuthenticationRequest()
            {
                ClientId = formCollection[CLIENT_ID].ToString(),
                ClientSecret = formCollection[CLIENT_SECRET].ToString(),
                GrantType = grantType,
                Username = formCollection[USERNAME].ToString(),
                Password = formCollection[PASSWORD].ToString(),
                RefreshToken = formCollection[REFRESH_TOKEN].ToString()
            };
        }
        catch (Exception)
        {
            return null;
        }
    }
}
