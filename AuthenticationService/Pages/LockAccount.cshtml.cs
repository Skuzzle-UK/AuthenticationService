using AuthenticationService.Constants;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthenticationService.Pages
{
    public class LockAccountModel : PageModel
    {
        public string? Token { get; private set; }
        public string? Email { get; private set; }

        public void OnGet()
        {
            Token = Request.Query[UriConstants.Token];
            Email = Request.Query[UriConstants.Email];
        }
    }
}
