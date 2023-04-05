using System;
using Microsoft.AspNetCore.Authentication;
using PasetoAuth4.Interfaces;

namespace PasetoAuth4.Options
{
    /// <summary>
    /// this class should be defined inside appsetting.json and registered in configuration settings
    /// </summary>
    public class PasetoValidationParameters : AuthenticationSchemeOptions
    {
        public string SecretKey { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public int DefaultExpirationTime { get; set; }
        public TimeSpan ClockSkew { get; set; }
        public bool? ValidateIssuer { get; set; } = true;
        public bool? ValidateAudience { get; set; } = true;
        public bool? UseRefreshToken { get; set; }
        public IPasetoRefreshTokenProvider PasetoRefreshTokenProvider { get; set; }
    }
}