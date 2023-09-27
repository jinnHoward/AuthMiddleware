using AuthMiddlewareApi.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Cryptography.Xml;
using System.Text;

namespace AuthMiddlewareApi.ControllerExtentions
{
    internal static class AuthControllerExt
    {
        internal static void MapAuthApiController(this WebApplication app)
        {
            var healthController = app.MapGroup("/api/auth");

            healthController.MapCreateToken();
        }

        internal static void MapCreateToken(this RouteGroupBuilder grp)
        {
            grp.MapGet("/create-token", GenerateToken())
                .AllowAnonymous()
                .WithName("MapCreateToken")
                .WithOpenApi();
        }

        private static Func<HttpContext, string> GenerateToken()
        {
            return (HttpContext httpContext) =>
            {
                return JwtExtensions.GenerateDefaultToken();
            };
        }
    }
}
