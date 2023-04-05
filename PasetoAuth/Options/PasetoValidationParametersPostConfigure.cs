using System;
using Microsoft.Extensions.Options;

namespace PasetoAuth4.Options
{
    public class PasetoValidationParametersPostConfigure : IPostConfigureOptions<PasetoValidationParameters>
    {
        public void PostConfigure(string name, PasetoValidationParameters options)
        {
            if (string.IsNullOrEmpty(options.SecretKey))
                throw new InvalidOperationException("Secret key is required.");
            if (options.SecretKey.Length is < 32 or > 32)
                throw new InvalidOperationException("Secret key must have 32 chars.");
            if (options.UseRefreshToken.HasValue && options.UseRefreshToken.Value)
            {
                if (options.PasetoRefreshTokenProvider == null)
                    throw new InvalidOperationException("You must provide a Paseto Refresh Token provider");
            }
        }
    }
}