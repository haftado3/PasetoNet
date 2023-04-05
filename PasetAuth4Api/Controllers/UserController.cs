using Microsoft.AspNetCore.Mvc;
using PasetoAuth4.Common;
using PasetoAuth4.Interfaces;
using System.Security.Claims;

namespace PasetAuth4Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IPasetoTokenHandler _pasetoTokenHandler;
        public UserController(IPasetoTokenHandler pasetoTokenHandler)
        {
            _pasetoTokenHandler = pasetoTokenHandler;
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(string username, string password)
        {
            ClaimsIdentity identity = new ClaimsIdentity(
                //new GenericIdentity("ali","admin"),
                new[]
                {
                    new Claim(PasetoRegisteredClaimsNames.TokenIdentifier, Guid.NewGuid().ToString("N"))
                });

            PasetoTokenDescriptor pasetoTokenDescriptor = new PasetoTokenDescriptor()
            {
                Subject = identity,
            };
            var token = await _pasetoTokenHandler.WriteTokenAsync(pasetoTokenDescriptor);
            return Ok(token.Token);
        }

        [HttpPost("ValidateUser")]
        public async Task<IActionResult> ValidateUser(string token)
        {
            ClaimsPrincipal claimsPrincipal = await _pasetoTokenHandler.DecodeTokenAsync(token);
            return Ok(claimsPrincipal);
        }
    }
}
