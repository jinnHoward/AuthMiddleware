using Microsoft.AspNetCore.DataProtection;
using System.Net.Mime;
using System.Security.Cryptography.Xml;

namespace AuthMiddlewareApi.Authentication
{
    public class SimpleApiKeyMiddleware
    {
        private static readonly string API_KEY_HEADER = "X-Api-Key";

        private readonly RequestDelegate _next;
        private readonly ILogger<SimpleApiKeyMiddleware> _logger;

        public SimpleApiKeyMiddleware(RequestDelegate next, ILogger<SimpleApiKeyMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (httpContext.Request.Headers.TryGetValue("Authorization", out var authToken))
            {
                var validationToken = JwtExtensions.GetValidationParameters("ProEMLh5e_qnzdNU", "ProEMLh5e_qnzdNU");
                if((await JwtExtensions.ValidateToken(authToken, validationToken)).IsValid)
                    await _next(httpContext);
                else
                    await GenerateForbiddenResponse(httpContext, "JWT not valid.");

            }
            //Get apikey header
            else if (!httpContext.Request.Headers.TryGetValue(API_KEY_HEADER, out var apiKey))
            {
                //_logger.LogInformation("ApiKey not found inside request headers.");

                //Error and exit from asp.net core pipeline
                await GenerateForbiddenResponse(httpContext, "ApiKey not found inside request headers");    
                //await _next(httpContext);
            }
            else if (!await ApiKeyCheckAsync(apiKey))
            {
                _logger.LogError("ApiKey is not valid: {ApiKey}", apiKey);

                //Error and exit from asp.net core pipeline
                await GenerateForbiddenResponse(httpContext, "ApiKey not valid");
            }
            else
            {
                _logger.LogInformation("ApiKey validated: {ApiKey}", apiKey);

                //Proceed with pipeline
                await _next(httpContext);
            }
        }

        private Task<bool> ApiKeyCheckAsync(string apiKey)
        {
            //TODO: setup your validation code...

            return Task.FromResult<bool>(apiKey == "EECBA5A9-5541-4D58-A2A2-C6A46AC3D03C");
        }

        private async Task GenerateForbiddenResponse(HttpContext context, string message)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = MediaTypeNames.Application.Json;

            using var responseStream = new MemoryStream();
            await System.Text.Json.JsonSerializer.SerializeAsync(responseStream, new
            {
                Status = StatusCodes.Status403Forbidden,
                Message = message
            });

            await context.Response.BodyWriter.WriteAsync(responseStream.ToArray());
        }
    }
}
