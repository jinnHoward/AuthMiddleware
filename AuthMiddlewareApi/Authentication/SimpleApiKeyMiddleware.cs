﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using System.Net.Mime;
using System.Security.Claims;
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
            if (IsHttpContextValid(httpContext) == false || IsAllowAnonymousEndpoint(httpContext))
            {
                await _next(httpContext);
                return;
            }

            if (httpContext.Request.Headers.TryGetValue("Authorization", out var authToken))
            {
                if ((await JwtExtensions.ValidateToken(authToken!, null)).IsValid)
                {
                    var identity = GetClaimsIdentity("UI/USER");
                    httpContext.User.AddIdentity(identity);

                    await _next(httpContext);
                }
                else
                    await GenerateForbiddenResponse(httpContext, "JWT not valid.");

            }
            //Get apikey header
            else if (!httpContext.Request.Headers.TryGetValue(API_KEY_HEADER, out var apiKey))
            {
                await GenerateForbiddenResponse(httpContext, "ApiKey not found inside request headers");
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


                var id = GetClaimsIdentity("SDK/APP");
                httpContext.User.AddIdentity(id);
                //Proceed with pipeline
                await _next(httpContext);
            }
        }

        private static bool IsHttpContextValid(HttpContext httpContext)
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

        private static ClaimsIdentity GetClaimsIdentity(string requester)
        {
            var id = new ClaimsIdentity();
            id.AddClaim(new Claim("UserId", "12345"));
            id.AddClaim(new Claim("CompanyId", "6789"));
            id.AddClaim(new Claim("DepartmentId", "10"));
            id.AddClaim(new Claim("Requester", requester, null, "https://microsoftsecurity"));
            return id;
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

        private async Task SetResponseBody(HttpContext context, int httpStatusCode,  string message)
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
