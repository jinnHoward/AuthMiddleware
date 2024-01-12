using JinnHoward.AuthMiddlewareApi.Authentication.Extentions;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
namespace JinnHoward.AuthMiddlewareApi.Authentication
{
    public static class AuthenticationLogic
    {
        public static readonly string AUTHORIZATION_HEADER = "Authorization";

        public static string GetHeaderValueOrEmpty(HttpContext httpContext, string headerKey)
            => GetHeaderValueOrEmpty(httpContext.Request, headerKey);

        public static string GetHeaderValueOrEmpty(HttpRequest httpRequest, string headerKey)
        {
            if (httpRequest.Headers.TryGetValue(headerKey, out var value))
                return value!;
            return string.Empty;
        }

        public static ClaimsIdentity GetClaimsIdentity(TokenValidationResult authToken, string apiKey)
        {
            var claimsIdentity = new ClaimsIdentity();
            if (authToken.IsValid)
                claimsIdentity.AddClaimsForToken(authToken);

            if (apiKey.IsNullOrWhiteSpace() == false)
                claimsIdentity.AddClaimsForApiKey(apiKey);

            if (claimsIdentity.Claims.Any())
                claimsIdentity.AddClaimsForRequester(GetRequester(authToken, apiKey));

            return claimsIdentity;
        }

        public static bool IsNullOrWhiteSpace(this string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        internal static ClaimsIdentity AddClaimsForToken(this ClaimsIdentity id, TokenValidationResult authToken)
        {
            var userInfo = JwtExt.GetUserInfo(authToken);
            id.AddClaim(new Claim("UserId", userInfo.UserId.ToString()));
            id.AddClaim(new Claim("Email", userInfo.Email));
            id.AddClaim(new Claim("CompanyId", userInfo.CompanyId.ToString()));
            id.AddClaim(new Claim("DepartmentId", userInfo.DepartmentId.ToString()));
            return id;
        }

        internal static ClaimsIdentity AddClaimsForApiKey(this ClaimsIdentity id, string apiKey)
        {
            id.AddClaim(new Claim("API-Key", apiKey));
            return id;
        }

        internal static ClaimsIdentity AddClaimsForRequester(this ClaimsIdentity id, string requester)
        {
            id.AddClaim(new Claim("Requester", requester, null, JwtExt.Issuer));
            return id;
        }

        internal static string GetAuthToken(HttpContext httpContext)
            => GetHeaderValueOrEmpty(httpContext, AUTHORIZATION_HEADER).Replace("Bearer ", string.Empty);

        internal static string GetApiKey(HttpContext httpContext)
            => GetHeaderValueOrEmpty(httpContext, ApiKeyValidator.API_KEY_HEADER);

        private static string GetRequester(TokenValidationResult authToken, string apiKey)
        {
            var requester = string.Empty;

            if (authToken.IsValid)
                requester += "UI/USER";
            if (authToken.IsValid && apiKey.IsNullOrWhiteSpace() == false)
                requester += "-";
            if (apiKey.IsNullOrWhiteSpace() == false)
                requester += "SDK/APP";
            return requester;
        }
    }
}
