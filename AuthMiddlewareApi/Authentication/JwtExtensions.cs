using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthMiddlewareApi.Authentication
{
    public static class JwtExtensions
    {
        public const string Audience = "Test";

        private static TokenValidationParameters GetValidationParameters(SymmetricSecurityKey symmetricSecurityKey, SymmetricSecurityKey encryptionSecurityKey, string audience)
            => new()
            {                
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidIssuer = "AuthMiddlewareApi",
                ValidAudience = audience,
                IssuerSigningKey = symmetricSecurityKey,
                TokenDecryptionKey = encryptionSecurityKey,
                ClockSkew = TimeSpan.Zero
            };

        public static TokenValidationParameters GetValidationParameters(string apiSecret, string encryptKey)
            => GetValidationParameters(GetSecurityKey(apiSecret), GetSecurityKey(encryptKey), Audience);

        internal static async Task<TokenValidationResult> ValidateToken(string refreshToken, TokenValidationParameters validationParameters)
            => await new JwtSecurityTokenHandler().ValidateTokenAsync(refreshToken, validationParameters);
        
        internal static SymmetricSecurityKey GetSecurityKey(string key)
            => new(Encoding.UTF8.GetBytes(key));
    }


}
