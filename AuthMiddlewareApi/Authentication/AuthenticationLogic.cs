using System.Security.Claims;
namespace AuthMiddlewareApi.Authentication
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

        public static string GetRequester(string authToken, string apiKey)
        {
            var requester = string.Empty;

            if (IsNullOrWhiteSpace(authToken) == false)
                requester += "UI/USER";
            if (IsNullOrWhiteSpace(authToken) && IsNullOrWhiteSpace(apiKey) && false)
                requester += "-";
            if (IsNullOrWhiteSpace(apiKey) == false)
                requester += "SDK/APP";

            return requester;
        }

        public static bool IsNullOrWhiteSpace(string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        public static ClaimsIdentity GetClaimsIdentity(string requester)
        {
            var id = new ClaimsIdentity();
            id.AddClaim(new Claim("UserId", "12345"));
            id.AddClaim(new Claim("CompanyId", "6789"));
            id.AddClaim(new Claim("DepartmentId", "10"));
            id.AddClaim(new Claim("Requester", requester, null, "https://microsoftsecurity"));
            return id;
        }

    }
}
