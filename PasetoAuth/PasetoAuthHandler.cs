﻿using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PasetoAuth4.Exceptions;
using PasetoAuth4.Interfaces;
using PasetoAuth4.Options;

namespace PasetoAuth4
{
    public class PasetoAuthHandler : AuthenticationHandler<PasetoValidationParameters>
    {
        private const string AuthorizationHeaderName = "Authorization";
        private readonly IPasetoTokenHandler _pasetoTokenHandler;
        
        public PasetoAuthHandler(
            IOptionsMonitor<PasetoValidationParameters> options, 
            ILoggerFactory logger, UrlEncoder encoder,
            ISystemClock clock,
            IPasetoTokenHandler pasetoTokenHandler) 
            : base(options, logger, encoder, clock)
        {
            _pasetoTokenHandler = pasetoTokenHandler;
        }

       
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {

            if (!Request.Headers.ContainsKey(AuthorizationHeaderName))
                return AuthenticateResult.NoResult();
            
            if (!AuthenticationHeaderValue.TryParse(Request.Headers[AuthorizationHeaderName], out AuthenticationHeaderValue headerValue))
                return AuthenticateResult.NoResult();
            
            if (!Scheme.Name.Equals(headerValue.Scheme, StringComparison.OrdinalIgnoreCase))
                return AuthenticateResult.NoResult();
            
            
            try
            {
                ClaimsPrincipal claimsPrincipal;
                if (Options.UseRefreshToken.HasValue && Options.UseRefreshToken.Value)
                {
                    if (Options.PasetoRefreshTokenProvider == null)
                        throw new InvalidOperationException("Paseto Refresh Tokens handler not defined");
                    claimsPrincipal = await Options.PasetoRefreshTokenProvider.ReceiveAsync(Request.HttpContext);
                }
                else
                {
                    claimsPrincipal = await _pasetoTokenHandler.DecodeTokenAsync(headerValue.Parameter);
                }

                if (!claimsPrincipal.Claims.Any())
                    throw new InvalidGrantType();
                    
                return AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, Scheme.Name));
            }
            catch (Exception ex)
            {
                Response.Headers["Error-Message"] = ex.Message;
                return AuthenticateResult.Fail(ex);
            }
        }
        
        
    }
}