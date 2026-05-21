using AuthenticationService.Constants;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthenticationService.Pages
{
    /// <summary>
    /// Backs the invitation-acceptance page. Pulls email/token/callback from the query
    /// string so the view's JS can POST to <c>/api/registration/accept-invitation</c>.
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
