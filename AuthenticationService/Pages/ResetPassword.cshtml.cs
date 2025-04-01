using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthenticationService.Pages
{
    public class ResetPasswordModel : PageModel
    {
        public string Token { get; private set; }

        public void OnGet()
        {
            Token = Request.Query["token"];
        }
    }
}
