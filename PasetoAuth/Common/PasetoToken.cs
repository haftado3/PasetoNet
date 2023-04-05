using System;

namespace PasetoAuth4.Common
{
    public class PasetoToken
    {
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
    }
}