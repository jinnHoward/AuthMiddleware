using JinnStudios.Howard.AuthMiddlewareApi.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JinnStudios.Howard.AuthMiddlewareApi.Authentication.Extentions
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
                //TokenDecryptionKey = encryptionSecurityKey,
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

        internal static UserInfo GetUserInfo(TokenValidationResult validatedToken)
        => new()
        {
            UserId = Guid.Parse(validatedToken.Claims[CustomUserClaims.UserId].ToString() ?? string.Empty),
            Email = validatedToken.Claims[CustomUserClaims.Email].ToString() ?? string.Empty,
            FirstName = validatedToken.Claims[CustomUserClaims.FirstName].ToString() ?? string.Empty,
            LastName = validatedToken.Claims[CustomUserClaims.LastName].ToString() ?? string.Empty,
        };

        public static string GenerateDefaultToken(string apiSecret)
        {
            var token = new JwtSecurityToken(
             issuer: Issuer,
             audience: Audience,
             expires: DateTime.Now.AddHours(3),
             signingCredentials: GetSigningCredentials(apiSecret),
             claims: GetDefaultClaims()
            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private static IEnumerable<Claim> GetDefaultClaims()
        {
            var userInfo = new UserInfo()
            {
                UserId = new Guid(),
                CompanyId = new Guid(),
                DepartmentId = new Guid(),
                FirstName = "Mario",
                LastName = "Mario",
                Email = "test@chomp.chomp",

            };
            var claims = new List<Claim>
            {
                new Claim(CustomUserClaims.UserId, userInfo.UserId.ToString()),
                new Claim(CustomUserClaims.Email, userInfo.Email),
                new Claim(CustomUserClaims.FirstName, userInfo.FirstName),
                new Claim(CustomUserClaims.LastName, userInfo.LastName),
                new Claim(CustomUserClaims.CompanyId, userInfo.CompanyId.ToString()),
                new Claim(CustomUserClaims.DepartmentId, userInfo.DepartmentId.ToString())
            };
            return claims;
        }

        internal static TokenValidationParameters GetValidationParameters(string apiSecret, string encryptionKey)
            => GetValidationParameters(GetSecurityKey(apiSecret), GetSecurityKey(encryptionKey), Audience);

        internal static SigningCredentials GetSigningCredentials(string key)
            => new(GetSecurityKey(key), SecurityAlgorithms.HmacSha256);

        internal static SymmetricSecurityKey GetSecurityKey(string key)
            => new(Encoding.UTF8.GetBytes(key));
    }
}
