using System.Security.Claims;
using System.Threading.Tasks;
using Paseto.Cryptography.Key;
using PasetoAuth4.Common;

namespace PasetoAuth4.Interfaces
{
    public interface IPasetoTokenHandler
    {
        Task<PasetoToken> WriteTokenAsync(PasetoTokenDescriptor tokenDescriptor);
        Task<ClaimsPrincipal> DecodeTokenAsync(string token);
        //Task<(byte[] publicKey, byte[] privateKey)> GenerateKeyPairAsync(string secretKey);
        Task<PasetoAsymmetricKeyPair> GenerateKeyPairAsync(string secretKey);
    }
}