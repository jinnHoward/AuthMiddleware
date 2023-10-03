using AuthMiddlewareApi.Authentication;
using AuthMiddlewareApi.Authentication.Extentions;
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
        internal static void MapAuthApiController(this WebApplication app, string apiSecret)
        {
            var healthController = app.MapGroup("/api/auth");

            healthController.MapCreateToken(apiSecret);
        }

        internal static void MapCreateToken(this RouteGroupBuilder grp, string apiSecret)
        {
            grp.MapGet("/create-token", GenerateToken(apiSecret))
                .AllowAnonymous()
                .WithName("MapCreateToken")
                .WithOpenApi();
        }

        private static Func<HttpContext, object> GenerateToken(string apiSecret)
        {
            return (HttpContext httpContext) =>
            {
                return new { Token = JwtExt.GenerateDefaultToken(apiSecret) };
            };
        }
    }
}
