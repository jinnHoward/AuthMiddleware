using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authentication
{
    public class BuildingEntryRequirement : IAuthorizationRequirement { }

    public class BadgeEntryHandler : AuthorizationHandler<BuildingEntryRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, BuildingEntryRequirement requirement)
        {
            if (context.User.HasClaim(
                c => c.Type == "BadgeId" && c.Issuer == "https://microsoftsecurity"))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }

    public class TemporaryStickerHandler : AuthorizationHandler<BuildingEntryRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, BuildingEntryRequirement requirement)
        {
            if (context.User.HasClaim(
                c => c.Type == "TemporaryBadgeId" && c.Issuer == "https://microsoftsecurity"))
            {
                // Code to check expiration date omitted for brevity.
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
