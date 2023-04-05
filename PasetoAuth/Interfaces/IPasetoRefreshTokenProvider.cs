using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace PasetoAuth4.Interfaces
{
    public interface IPasetoRefreshTokenProvider
    {
        Task<ClaimsPrincipal> ReceiveAsync(HttpContext httpContext);
        Task<string> CreateAsync(ClaimsIdentity claimsPrincipal);
    }
}