using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authorization
{
    public class OrApiKeyRequirementHandler : AuthorizationHandler<ApiKeyOrJwtAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyOrJwtAccessRequirement requirement)
        {
            if (ApiKeyOrJwtAccessRequirement.IsValidRequester(context, ApiKeyRequirement.Requester))
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
