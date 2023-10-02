using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authorization
{
    public class ApiKeyRequirementHandler : AuthorizationHandler<ApiKeyRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyRequirement requirement)
        {
            if (ApiKeyRequirement.IsValidRequester(context))
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
