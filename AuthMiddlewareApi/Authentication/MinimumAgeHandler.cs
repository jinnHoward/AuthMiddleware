using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authentication
{
    public class MinimumAgeHandler : AuthorizationHandler<MinimumAgeRequirement>
    {
        protected override Task HandleRequirementAsync(
            AuthorizationHandlerContext context, MinimumAgeRequirement requirement)
        {
            //var dateOfBirthClaim = context.User.FindFirst(
            //    c => c.Type == ClaimTypes.DateOfBirth && c.Issuer == "http://contoso.com");

            //if (dateOfBirthClaim is null)
            //{
            //    return Task.CompletedTask;
            //}

            var dateOfBirth = Convert.ToDateTime(DateTime.Today.AddYears(-21));
            int calculatedAge = DateTime.Today.Year - dateOfBirth.Year;
            if (dateOfBirth > DateTime.Today.AddYears(-calculatedAge))
            {
                calculatedAge--;
            }

            if (calculatedAge >= requirement.MinimumAge)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
