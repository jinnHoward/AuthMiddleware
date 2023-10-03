using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authorization.ApiKeyOrJwt
{
    public class ApiKeyOrJwtAccessRequirement : IAuthorizationRequirement
    {
        public static bool IsValidRequester(AuthorizationHandlerContext context, string requester)
        {
            if (context.User.HasClaim(c => c.Type == "Requester" && c.Value == requester && c.Issuer == "https://microsoftsecurity"))
                return true;
            return false;
        }
    }
}
