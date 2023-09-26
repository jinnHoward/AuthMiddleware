using Microsoft.AspNetCore.Authorization;

namespace AuthMiddlewareApi.Authentication
{
    public class MinimumAgeRequirement : IAuthorizationRequirement
    {
        public MinimumAgeRequirement(int minimumAge) 
            => MinimumAge = minimumAge;

        public int MinimumAge { get; }
    }
}