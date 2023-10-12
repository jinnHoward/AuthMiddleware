using JinnStudios.Howard.AuthMiddlewareApi.Authorization.ApiKey;
using Microsoft.AspNetCore.Authorization;

namespace JinnStudios.Howard.AuthMiddlewareApi.Authorization.ApiKeyOrJwt
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
