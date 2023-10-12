using Microsoft.AspNetCore.Authorization;

namespace JinnStudios.Howard.AuthMiddlewareApi.Authorization.Jwt
{
    public class JwtRequirement : IAuthorizationRequirement
    {
        public static string Requester = "UI/USER";
        public static bool IsValidRequester(AuthorizationHandlerContext context)
        {
            if (context.User.HasClaim(c => c.Type == "Requester" && c.Value.Contains(Requester) && c.Issuer == "https://microsoftsecurity"))
                return true;
            return false;
        }
    }
}
