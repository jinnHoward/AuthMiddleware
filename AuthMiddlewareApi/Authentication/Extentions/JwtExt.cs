using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace AuthMiddlewareApi.Authentication.Extentions
{
    public static class JwtExt
    {
        public const string Issuer = "https://microsoftsecurity";
        public const string Audience = "Test";

        internal static TokenValidationParameters GetValidationParameters(SymmetricSecurityKey symmetricSecurityKey, SymmetricSecurityKey encryptionSecurityKey, string audience)
        {
            //TODO: Setup JWT token Validation parameters
            return new TokenValidationParameters()
            {
                ValidateLifetime = true,
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidAudience = audience,
                IssuerSigningKey = symmetricSecurityKey,
                TokenDecryptionKey = encryptionSecurityKey,
                ClockSkew = TimeSpan.Zero
            };
        }

        internal static async Task<TokenValidationResult> ValidateToken(string refreshToken, TokenValidationParameters validationParameters)
        {
            //TODO: Setup JWT token Validation
            if (validationParameters == null)
                return new TokenValidationResult() { IsValid = string.IsNullOrWhiteSpace(refreshToken) == false };

            return await new JwtSecurityTokenHandler().ValidateTokenAsync(refreshToken, validationParameters);
        }

        public static string GenerateDefaultToken(string apiSecret)
        {
            var token = new JwtSecurityToken(
             issuer: Issuer,
             audience: Audience,
             expires: DateTime.Now.AddHours(3),
             signingCredentials: GetSigningCredentials(apiSecret)
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        internal static TokenValidationParameters GetValidationParameters(string apiSecret, string encryptionKey)
            => GetValidationParameters(GetSecurityKey(apiSecret), GetSecurityKey(encryptionKey), Audience);

        internal static SigningCredentials GetSigningCredentials(string key)
            => new(GetSecurityKey(key), SecurityAlgorithms.HmacSha256);

        internal static SymmetricSecurityKey GetSecurityKey(string key)
            => new(Encoding.UTF8.GetBytes(key));
    }
}
