using JinnStudios.Howard.AuthMiddlewareApi.Authentication;
using JinnStudios.Howard.AuthMiddlewareApi.Models;

namespace JinnStudios.Howard.AuthMiddlewareApi.ControllerExtentions
{
    internal static class WeatherControllerExt
    {
        private static string[] summaries = new[]
            {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
            };

        internal static void MapWeatherApiController(this WebApplication app)
        {
            var weatherController = app.MapGroup("/api/weatherforecast");

            weatherController.MapEndpointNoAuth("none");
            weatherController.MapEndpointApiAuth("api-key");
            weatherController.MapEndpointJwtAuth("jwt");
            weatherController.MapEnpointApiOrJwtAuth("api-key-or-jwt");
            weatherController.MapEnpointApiAndJwtAuth("api-key-and-jwt");
        }

        private static void MapEndpointNoAuth(this RouteGroupBuilder grp, string endpointName)
            => grp.MapGet($"/{endpointName.ToLower()}", GetForecast())
                .AllowAnonymous()
                .WithName($"GetWeatherForecast-{endpointName}")
                .WithOpenApi();

        private static void MapEndpointApiAuth(this RouteGroupBuilder grp, string endpointName)
            => MapDefaultGetEndpoint(grp, endpointName, AuthConstants.API_ONLY);

        private static void MapEndpointJwtAuth(this RouteGroupBuilder grp, string endpointName)
            => MapDefaultGetEndpoint(grp, endpointName, AuthConstants.JWT_ONLY);

        private static void MapEnpointApiOrJwtAuth(this RouteGroupBuilder grp, string endpointName)
            => MapDefaultGetEndpoint(grp, endpointName, AuthConstants.API_OR_JWT);

        private static void MapEnpointApiAndJwtAuth(this RouteGroupBuilder grp, string endpointName)
            => MapDefaultGetEndpoint(grp, endpointName, AuthConstants.API_AND_JWT);

        private static void MapDefaultGetEndpoint(RouteGroupBuilder grp, string endpointName, string authAttributeName, string openApiEndpointPrefix = "GetWeatherForecast")
            => grp.MapGet($"/{endpointName.ToLower()}", GetForecast())
                .RequireAuthorization(authAttributeName)
                .WithName($"{openApiEndpointPrefix}-{endpointName}")
                .WithOpenApi();

        private static Func<HttpContext, WeatherForecast[]> GetForecast()
        {
            return (httpContext) =>
            {
                var forecast = Enumerable.Range(1, 5).Select(index =>
                    new WeatherForecast
                    {
                        Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                        TemperatureC = Random.Shared.Next(-40, 60),
                        Summary = summaries[Random.Shared.Next(summaries.Length)]
                    })
                    .ToArray();
                return forecast;
            };
        }
    }
}
