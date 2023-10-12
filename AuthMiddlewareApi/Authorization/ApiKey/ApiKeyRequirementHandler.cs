using Microsoft.AspNetCore.Authorization;

namespace JinnStudios.Howard.AuthMiddlewareApi.Authorization.ApiKey
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
