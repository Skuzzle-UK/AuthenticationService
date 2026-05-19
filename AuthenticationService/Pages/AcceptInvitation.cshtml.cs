using AuthenticationService.Constants;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthenticationService.Pages
{
    /// <summary>
    /// Backs the invitation-acceptance Razor page. Extracts the email + token + optional
    /// callback URI from the query string (where the invitation email link puts them) and
    /// exposes them to the cshtml view so JavaScript can post the form to
    /// <c>/api/registration/accept-invitation</c>.
    /// </summary>
    public class AcceptInvitationModel : PageModel
    {
        public string? Token { get; private set; }
        public string? Email { get; private set; }
        public string? CallbackUri { get; private set; }

        public void OnGet()
        {
            Token = Request.Query[UriConstants.Token];
            Email = Request.Query[UriConstants.Email];
            CallbackUri = Request.Query["callbackUri"];
        }
    }
}
