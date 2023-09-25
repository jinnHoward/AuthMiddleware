using AuthMiddleware.Core;

namespace AuthMiddlewareApi.Extentions
{
    internal static class WeatherControllerExt
    {
        private static string[] summaries = new[]
            {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
            };

        internal static void MapWeatherApiController(this WebApplication app)
        {
            var weatherController = app.MapGroup("/weatherforecast");

            weatherController.MapEnpointNoAuth("none");
            weatherController.MapEnpointApiAuth("api-key_only");
            weatherController.MapEnpointJwtAuth("jwt_only");
            weatherController.MapEnpointApiOrJwtAuth("api-key_or_jwt");
        }

        private static void MapEnpointNoAuth(this RouteGroupBuilder grp, string endpointName)
        {
            grp.MapGet($"/{endpointName.ToLower()}", (HttpContext httpContext) =>
                {
                    var forecast = Enumerable.Range(1, 5).Select(index =>
                        new WeatherForecast
                        {
                            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                            TemperatureC = Random.Shared.Next(-20, 55),
                            Summary = summaries[Random.Shared.Next(summaries.Length)]
                        })
                        .ToArray();
                    return forecast;
                })
                .WithName($"GetWeatherForecast-{endpointName}")
                .WithOpenApi();
        }

        private static void MapEnpointApiAuth(this RouteGroupBuilder grp, string endpointName) 
        {
            grp.MapGet($"/{endpointName.ToLower()}", (HttpContext httpContext) =>
                {
                    var forecast = Enumerable.Range(1, 5).Select(index =>
                        new WeatherForecast
                        {
                            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                            TemperatureC = Random.Shared.Next(-20, 55),
                            Summary = summaries[Random.Shared.Next(summaries.Length)]
                        })
                        .ToArray();
                    return forecast;
                })
                //.RequireAuthorization(ApiKeyAuthenticationOptions.DefaultScheme)
                .WithName($"GetWeatherForecast-{endpointName}")
                .WithOpenApi();
        }

        private static void MapEnpointJwtAuth(this RouteGroupBuilder grp, string endpointName) { }

        private static void MapEnpointApiOrJwtAuth(this RouteGroupBuilder grp, string endpointName) { }
    }
}
