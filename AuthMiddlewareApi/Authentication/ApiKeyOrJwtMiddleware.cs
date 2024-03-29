﻿using JinnHoward.AuthMiddlewareApi.Authentication.Extentions;
using JinnHoward.AuthMiddlewareApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Net.Mime;

namespace JinnHoward.AuthMiddlewareApi.Authentication
{
    public class ApiKeyOrJwtMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ApiKeyOrJwtMiddleware> _logger;
        private readonly string _apiSecret;
        private readonly string _encryptionKey;
        private readonly IApiKeyValidator _apiKeyValidator;

        public ApiKeyOrJwtMiddleware(RequestDelegate next, ILogger<ApiKeyOrJwtMiddleware> logger, string apiSecret, string encryptionKey, IApiKeyValidator apiKeyValidator)
        {
            _next = next;
            _logger = logger;
            _apiSecret = apiSecret;
            _encryptionKey = encryptionKey;
            _apiKeyValidator = apiKeyValidator;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            try
            {
                if (IsHttpContextValid(httpContext) == false || IsAllowAnonymousEndpoint(httpContext) || HasAuthorizeAttribute(httpContext) == false)
                {
                    await _next(httpContext);
                    return;
                }

                var authAttr = GetAuthAttributePolicy(httpContext);
                var isValidToProceed = false;
                var apiKey = string.Empty;
                var authTokenValidator = new TokenValidationResult();
                var isApiKeyValid = false;
                var isJwtValid = false;

                switch (authAttr)
                {
                    case AuthConstants.API_ONLY:
                        apiKey = AuthenticationLogic.GetApiKey(httpContext);
                        isValidToProceed = await ValidateApiKey(apiKey);
                        break;
                    case AuthConstants.JWT_ONLY:
                        authTokenValidator = await ValidateAuthToken(AuthenticationLogic.GetAuthToken(httpContext));
                        isValidToProceed = authTokenValidator.IsValid;
                        break;

                    case AuthConstants.API_OR_JWT:
                        apiKey = AuthenticationLogic.GetApiKey(httpContext);
                        isApiKeyValid = await ValidateApiKey(apiKey);

                        authTokenValidator = await ValidateAuthToken(AuthenticationLogic.GetAuthToken(httpContext));
                        isJwtValid = authTokenValidator.IsValid;

                        isValidToProceed = isApiKeyValid || isJwtValid;
                        break;
                    case AuthConstants.API_AND_JWT:
                        apiKey = AuthenticationLogic.GetApiKey(httpContext);
                        isApiKeyValid = await ValidateApiKey(apiKey);

                        authTokenValidator = await ValidateAuthToken(AuthenticationLogic.GetAuthToken(httpContext));
                        isJwtValid = authTokenValidator.IsValid;

                        isValidToProceed = isApiKeyValid && isJwtValid;
                        break;
                    default:
                        _logger.LogWarning("Authentication Policy not found: {authAttr}", authAttr);
                        await _next(httpContext);
                        break;
                }


                if (isValidToProceed)
                {
                    var id = AuthenticationLogic.GetClaimsIdentity(authTokenValidator, apiKey);
                    httpContext.User.AddIdentity(id);
                    //Proceed with pipeline
                    await _next(httpContext);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("Exception trying to proceed: {Exception}", ex);
            }
            await SetResponseCodeForbidden(httpContext, "Authentication Missing or Invalid");
            return;
        }

        private async Task<bool> ValidateApiKey(string apiKey, bool isRequired = true)
        {
            if (isRequired && apiKey.IsNullOrWhiteSpace())
            {
                _logger.LogError("ApiKey not present");
                return false;
            }
            if (isRequired)
            {
                var isValid = await _apiKeyValidator.ValidateApiKey(apiKey);
                if (isValid == false)
                    _logger.LogError("ApiKey is not valid: {ApiKey}", apiKey);
                return isValid;
            }

            return true;
        }

        private async Task<TokenValidationResult> ValidateAuthToken(string authToken, bool isRequired = true)
        {
            var tokenValidator = new TokenValidationResult() { IsValid = false };
            if (isRequired && authToken.IsNullOrWhiteSpace())
            {
                _logger.LogError("Jwt not present");
                return tokenValidator;
            }
            if (isRequired)
            {
                var validationParameters = JwtExt.GetValidationParameters(_apiSecret, _encryptionKey);
                tokenValidator = await JwtExt.ValidateToken(authToken!, validationParameters);

                if (tokenValidator.IsValid == false)
                    _logger.LogError("JWT not valid. {Exception}", tokenValidator.Exception);
            }

            return tokenValidator;
        }

        public static bool IsHttpContextValid(HttpContext httpContext)
        {
            if (httpContext.GetEndpoint()?.DisplayName == "405 HTTP Method Not Supported")
                return false;

            return true;
        }

        private bool HasAuthorizeAttribute(HttpContext httpContext)
            => GetAuthAttributePolicy(httpContext).IsNullOrWhiteSpace() == false;

        private static string GetAuthAttributePolicy(HttpContext httpContext)
                => httpContext.GetEndpoint()?.Metadata?.GetMetadata<AuthorizeAttribute>()?.Policy ?? string.Empty;

        private bool IsAllowAnonymousEndpoint(HttpContext httpContext)
        {
            var endpoint = httpContext.GetEndpoint();
            if (endpoint == null)
                _logger.LogInformation("endpoint is null");

            return endpoint?.Metadata?.GetMetadata<IAllowAnonymous>() != null;
        }

        private static async Task SetResponseCodeForbidden(HttpContext context, string message)
            => await SetResponseBody(context, StatusCodes.Status403Forbidden, message);

        private static async Task SetResponseBody(HttpContext context, int httpStatusCode, string message)
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
