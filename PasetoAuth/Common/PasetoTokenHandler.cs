using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using Paseto.Protocol;
using PasetoAuth4.Exceptions;
using PasetoAuth4.Interfaces;
using PasetoAuth4.Options;

namespace PasetoAuth4.Common
{
    public class PasetoTokenHandler : IPasetoTokenHandler
    {
        private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
        private readonly PasetoValidationParameters _validationParameters;

        public PasetoTokenHandler(IAuthenticationSchemeProvider authenticationSchemeProvider,
            IOptions<PasetoValidationParameters> validationParameters)
        {
            _authenticationSchemeProvider = authenticationSchemeProvider;
            _validationParameters = validationParameters.Value;
        }

        public Task<PasetoToken> WriteTokenAsync(PasetoTokenDescriptor descriptor)
        {
            PasetoToken pasetoToken = new PasetoToken();
            DateTime now = DateTime.Now;
            DateTime expirationDate = descriptor.Expires ?? now.AddSeconds(_validationParameters.DefaultExpirationTime);
            string audience = descriptor.Audience ?? _validationParameters.Audience;
            string issuer = descriptor.Issuer ?? _validationParameters.Issuer;
            var key = GenerateKeyPairAsync(_validationParameters.SecretKey).Result;
            var privateKey = new PasetoAsymmetricSecretKey(key.SecretKey.Key,new Version4());
            PasetoBuilder pasetoBuilder = new PasetoBuilder()
                .UseV4(Purpose.Public)
                .WithKey(privateKey)
                .Audience(audience)
                .Issuer(issuer)
                .IssuedAt(now)
                .Expiration(expirationDate);
            if (!descriptor.NotBefore.Equals(null))
                pasetoBuilder.AddClaim(RegisteredClaims.NotBefore, descriptor.NotBefore);
            foreach (Claim claim in descriptor.Subject.Claims)
                pasetoBuilder.AddClaim(claim.Type, claim.Value);

            pasetoToken.Token = pasetoBuilder.Encode();
            pasetoToken.CreatedAt = now;
            pasetoToken.ExpiresAt = expirationDate;
            if (_validationParameters is { PasetoRefreshTokenProvider: { }, UseRefreshToken: { } } && _validationParameters.UseRefreshToken.Value)
            {
                pasetoToken.RefreshToken = _validationParameters.PasetoRefreshTokenProvider
                    .CreateAsync(descriptor.Subject).Result;
            }
            return Task.FromResult(pasetoToken);
        }

        //public Task<(byte[] publicKey, byte[] privateKey)> GenerateKeyPairAsync(string secretKey)
        //{
        //    Ed25519.KeyPairFromSeed(out var publicKey, out var privateKey,
        //        Encoding.ASCII.GetBytes(secretKey));
        //    return Task.FromResult((publicKey, privateKey));
        //}        
        public Task<PasetoAsymmetricKeyPair> GenerateKeyPairAsync(string secretKey)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(secretKey);
            var keyPair = new PasetoBuilder().UseV4(Purpose.Public)
                .GenerateAsymmetricKeyPair(bytes);
            return Task.FromResult(keyPair);
        }

        public async Task<ClaimsPrincipal> DecodeTokenAsync(string token)
        {
            var key = GenerateKeyPairAsync(_validationParameters.SecretKey).Result;
            var publicKey = new PasetoAsymmetricPublicKey(key.PublicKey.Key, new Version4());
            var decodedToken = new PasetoBuilder().UseV4(Purpose.Public)
                .WithKey(publicKey)
                .Decode(token);
            var json = decodedToken.Paseto.Payload.ToJson();
            JObject deserializedObject = JObject.Parse(json);
            if (Convert.ToDateTime(deserializedObject[PasetoRegisteredClaimsNames.ExpirationTime]).CompareTo(DateTime.Now) < 0 ||
                Convert.ToDateTime(deserializedObject[PasetoRegisteredClaimsNames.NotBefore]).CompareTo(DateTime.Now) > 0)
                throw new ExpiredToken();

            List<Claim> claimsList = new List<Claim>();

            await Task.Run(() =>
            {
                foreach (var obj in deserializedObject.Properties())
                {
                    switch (obj.Name)
                    {
                        case PasetoRegisteredClaimsNames.ExpirationTime:
                            claimsList.Add(new Claim(PasetoRegisteredClaimsNames.ExpirationTime,
                                obj.Value.ToString()));
                            break;
                        case PasetoRegisteredClaimsNames.Audience:
                            claimsList.Add(new Claim(PasetoRegisteredClaimsNames.Audience, obj.Value.ToString()));
                            break;
                        case PasetoRegisteredClaimsNames.Issuer:
                            claimsList.Add(new Claim(PasetoRegisteredClaimsNames.Issuer, obj.Value.ToString()));
                            break;
                        case PasetoRegisteredClaimsNames.IssuedAt:
                            claimsList.Add(new Claim(PasetoRegisteredClaimsNames.IssuedAt, obj.Value.ToString()));
                            break;
                        case PasetoRegisteredClaimsNames.NotBefore:
                            claimsList.Add(new Claim(PasetoRegisteredClaimsNames.NotBefore, obj.Value.ToString()));
                            break;
                        case PasetoRegisteredClaimsNames.TokenIdentifier:
                            claimsList.Add(new Claim(PasetoRegisteredClaimsNames.TokenIdentifier,
                                obj.Value.ToString()));
                            break;
                        default:
                            claimsList.Add(new Claim(obj.Name, obj.Value.ToString()));
                            break;
                    }
                }
            });

            AuthenticationScheme authenticationScheme =
                await _authenticationSchemeProvider.GetSchemeAsync(PasetoDefaults.Bearer);

            ClaimsIdentity identity = new ClaimsIdentity(claimsList, authenticationScheme.Name);
            return new ClaimsPrincipal(identity);
        }
    }
}