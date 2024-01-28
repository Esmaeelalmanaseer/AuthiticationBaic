using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace AuthiticationBaic.Authentictation
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public BasicAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
                return Task.FromResult(AuthenticateResult.NoResult());
            var authHeader = Request.Headers["Authorization"].ToString();
            if (!authHeader.StartsWith("Basic", StringComparison.OrdinalIgnoreCase))
                return Task.FromResult(AuthenticateResult.Fail("Unkown"));
            var encodingCredential = authHeader["Basic".Length..];
            var decodingCredential = Encoding.UTF8.GetString(Convert.FromBase64String(encodingCredential));
            var usernamepassworld = decodingCredential.Split(':');
            if (usernamepassworld[0] != "Admin" || usernamepassworld[1] != "password")
                return Task.FromResult(AuthenticateResult.Fail("Unkown"));

            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.NameIdentifier,"1"),
                new Claim(ClaimTypes.Name,usernamepassworld[0])
            }, "Basic");
            var prinviple = new ClaimsPrincipal(identity);
            var tikat=new AuthenticationTicket(prinviple,"Basic"); 
            return Task.FromResult(AuthenticateResult.Success(tikat));
        }
    }
}
