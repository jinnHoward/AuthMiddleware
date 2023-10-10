using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using System.Net.Mime;
using System.Security.Claims;
using System.Security.Cryptography.Xml;
using AuthMiddlewareApi.Authentication.Extentions;

namespace AuthMiddlewareApi.Authentication
{
    public class ApiKeyOrJwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ApiKeyOrJwtMiddleware> _logger;

        public ApiKeyOrJwtMiddleware(RequestDelegate next, ILogger<ApiKeyOrJwtMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (IsHttpContextValid(httpContext) == false || IsAllowAnonymousEndpoint(httpContext))
            {
                await _next(httpContext);
                return;
            }
            var authToken = AuthenticationLogic.GetHeaderValueOrEmpty(httpContext, AuthenticationLogic.AUTHORIZATION_HEADER);
            var apiKey = AuthenticationLogic.GetHeaderValueOrEmpty(httpContext, ApiKeyExt.API_KEY_HEADER);
            var requester = AuthenticationLogic.GetRequester(authToken, apiKey);

            if (AuthenticationLogic.IsNullOrWhiteSpace(authToken) == false)
            {
                if ((await JwtExt.ValidateToken(authToken!, null)).IsValid)
                {
                    var identity = AuthenticationLogic.GetClaimsIdentity(requester);
                    httpContext.User.AddIdentity(identity);

                    await _next(httpContext);
                }
                else
                    await GenerateForbiddenResponse(httpContext, "JWT not valid.");
            }
            //Get apikey header
            else if (AuthenticationLogic.IsNullOrWhiteSpace(apiKey))
            {
                await GenerateForbiddenResponse(httpContext, "ApiKey not found inside request headers");
            }
            else if (!await ApiKeyExt.ApiKeyCheckAsync(apiKey))
            {
                _logger.LogError("ApiKey is not valid: {ApiKey}", apiKey);

                //Error and exit from asp.net core pipeline
                await GenerateForbiddenResponse(httpContext, "ApiKey not valid");
            }
            else
            {
                _logger.LogInformation("ApiKey validated: {ApiKey}", apiKey);

                var id = AuthenticationLogic.GetClaimsIdentity(requester);
                httpContext.User.AddIdentity(id);
                //Proceed with pipeline
                await _next(httpContext);
            }
        }

        public static bool IsHttpContextValid(HttpContext httpContext)
        {
            if (httpContext.GetEndpoint()?.DisplayName == "405 HTTP Method Not Supported")
                return false;

            return true;
        }

        private bool IsAllowAnonymousEndpoint(HttpContext httpContext)
        {
            var endpoint = httpContext.GetEndpoint();
            if (endpoint == null)
                _logger.LogInformation("endpoint is null");

            return endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null;
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

        private async Task SetResponseBody(HttpContext context, int httpStatusCode, string message)
        {
            context.Response.StatusCode = httpStatusCode;
            context.Response.ContentType = MediaTypeNames.Application.Json;

            using var responseStream = new MemoryStream();
            await System.Text.Json.JsonSerializer.SerializeAsync(responseStream, new
            {
                Status = httpStatusCode,
                Message = message
            });

            await context.Response.BodyWriter.WriteAsync(responseStream.ToArray());
        }
    }
}
