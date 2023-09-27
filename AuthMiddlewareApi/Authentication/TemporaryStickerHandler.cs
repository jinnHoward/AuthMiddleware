using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authentication
{
    public class ApiKeyOrJwtAccessRequirement : IAuthorizationRequirement 
    {
        public static bool IsValidRequester(AuthorizationHandlerContext context, string requester)
        {
          if(context.User.HasClaim(c => c.Type == "Requester" && c.Value == requester && c.Issuer == "https://microsoftsecurity"))
                return true;
          return false;
        }
    }

    public class JwtAccessRequirement : IAuthorizationRequirement 
    {
        public static string Requester = "UI/USER";
    }

    public class ApiKeyAccessRequirement : IAuthorizationRequirement
    {
        public static string Requester = "SDK/APP";
    }

    public class JwtRequirementHandler : AuthorizationHandler<JwtAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, JwtAccessRequirement requirement)
        {
            if (ApiKeyOrJwtAccessRequirement.IsValidRequester(context, JwtAccessRequirement.Requester))
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }

    public class ApiKeyRequirementHandler : AuthorizationHandler<ApiKeyAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyAccessRequirement requirement)
        {
            if (ApiKeyOrJwtAccessRequirement.IsValidRequester(context, ApiKeyAccessRequirement.Requester))
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }

    public class OrJwtRequirementHandler : AuthorizationHandler<ApiKeyOrJwtAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyOrJwtAccessRequirement requirement)
        {
            if (ApiKeyOrJwtAccessRequirement.IsValidRequester(context, JwtAccessRequirement.Requester))
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }

    public class OrApiKeyRequirementHandler : AuthorizationHandler<ApiKeyOrJwtAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ApiKeyOrJwtAccessRequirement requirement)
        {
            if (ApiKeyOrJwtAccessRequirement.IsValidRequester(context, ApiKeyAccessRequirement.Requester))            
                context.Succeed(requirement);

            return Task.CompletedTask;
        }
    }
}
