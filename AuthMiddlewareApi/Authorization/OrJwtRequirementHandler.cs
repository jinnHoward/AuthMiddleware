using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authorization
{
    public class OrJwtRequirementHandler : AuthorizationHandler<ApiKeyOrJwtAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyOrJwtAccessRequirement requirement)
        {
            if (ApiKeyOrJwtAccessRequirement.IsValidRequester(context, JwtRequirement.Requester))
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
