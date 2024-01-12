using JinnHoward.AuthMiddlewareApi.Authentication.Extentions;

namespace JinnHoward.AuthMiddlewareApi.ControllerExtentions
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
            return (httpContext) =>
            {
                return new { Token = JwtExt.GenerateDefaultToken(apiSecret) };
            };
        }
    }
}
