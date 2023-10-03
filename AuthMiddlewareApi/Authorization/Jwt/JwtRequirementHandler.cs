using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authorization.Jwt
{
    public class JwtRequirementHandler : AuthorizationHandler<JwtRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, JwtRequirement requirement)
        {
            if (JwtRequirement.IsValidRequester(context))
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
