using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authorization.ApiKey
{
    public class ApiKeyRequirement : IAuthorizationRequirement
    {
        public static string Requester = "SDK/APP";

        public static bool IsValidRequester(AuthorizationHandlerContext context)
        {
            if (context.User.HasClaim(c => c.Type == "Requester" && c.Value.Contains(Requester) && c.Issuer == "https://microsoftsecurity"))
                return true;
            return false;
        }
    }
}
