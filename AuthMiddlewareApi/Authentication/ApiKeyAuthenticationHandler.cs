﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using AuthMiddlewareApi.Authentication.Extentions;

namespace AuthMiddlewareApi.Authentication
{
    public class ApiKeyAuthenticationHandler : AuthenticationHandler<ApiKeyAuthenticationOptions>
    {
        private enum AuthenticationFailureReason
        {
            NONE = 0,
            API_KEY_HEADER_NOT_PROVIDED,
            API_KEY_HEADER_VALUE_NULL,
            API_KEY_INVALID
        }

        private readonly Microsoft.Extensions.Logging.ILogger _logger;

        private AuthenticationFailureReason _failureReason = AuthenticationFailureReason.NONE;

        public ApiKeyAuthenticationHandler(IOptionsMonitor<ApiKeyAuthenticationOptions> options,
                                           ILoggerFactory loggerFactory,
                                           ILogger<ApiKeyAuthenticationHandler> logger,
                                           UrlEncoder encoder,
                                           ISystemClock clock) : base(options, loggerFactory, encoder, clock)
        {
            _logger = logger;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            //ApiKey header get
            if (!TryGetApiKeyHeader(out string providedApiKey, out AuthenticateResult authenticateResult))
            {
                return authenticateResult;
            }

            //TODO: you apikey validity check
            if (await ApiKeyExt.ApiKeyCheckAsync(providedApiKey))
            {
                var principal = new ClaimsPrincipal();  //TODO: Create your Identity retreiving claims
                var ticket = new AuthenticationTicket(principal, ApiKeyAuthenticationOptions.Scheme);

                return AuthenticateResult.Success(ticket);
            }

            _failureReason = AuthenticationFailureReason.API_KEY_INVALID;
            return AuthenticateResult.NoResult();
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            //Create response
            Response.Headers.Append(HeaderNames.WWWAuthenticate, $@"Authorization realm=""{ApiKeyAuthenticationOptions.DefaultScheme}""");
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            Response.ContentType = MediaTypeNames.Application.Json;

            //TODO: setup a response to provide additional information if you want
            var result = new
            {
                StatusCode = Response.StatusCode,
                Message = _failureReason switch
                {
                    AuthenticationFailureReason.API_KEY_HEADER_NOT_PROVIDED => "ApiKey not provided",
                    AuthenticationFailureReason.API_KEY_HEADER_VALUE_NULL => "ApiKey value is null",
                    AuthenticationFailureReason.NONE or AuthenticationFailureReason.API_KEY_INVALID or _ => "ApiKey is not valid"
                }
            };

            using var responseStream = new MemoryStream();
            await JsonSerializer.SerializeAsync(responseStream, result);
            await Response.BodyWriter.WriteAsync(responseStream.ToArray());
        }

        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            //Create response
            Response.Headers.Append(HeaderNames.WWWAuthenticate, $@"Authorization realm=""{ApiKeyAuthenticationOptions.DefaultScheme}""");
            Response.StatusCode = StatusCodes.Status403Forbidden;
            Response.ContentType = MediaTypeNames.Application.Json;

            var result = new
            {
                StatusCode = Response.StatusCode,
                Message = "Forbidden"
            };

            using var responseStream = new MemoryStream();
            await JsonSerializer.SerializeAsync(responseStream, result);
            await Response.BodyWriter.WriteAsync(responseStream.ToArray());
        }

        private bool TryGetApiKeyHeader(out string apiKeyHeaderValue, out AuthenticateResult result)
        {
            apiKeyHeaderValue = null;
            if (!Request.Headers.TryGetValue(ApiKeyExt.API_KEY_HEADER, out var apiKeyHeaderValues))
            {
                _logger.LogError("ApiKey header not provided");

                _failureReason = AuthenticationFailureReason.API_KEY_HEADER_NOT_PROVIDED;
                result = AuthenticateResult.Fail("ApiKey header not provided");

                return false;
            }

            apiKeyHeaderValue = apiKeyHeaderValues.FirstOrDefault();
            if (apiKeyHeaderValues.Count == 0 || string.IsNullOrWhiteSpace(apiKeyHeaderValue))
            {
                _logger.LogError("ApiKey header value null");

                _failureReason = AuthenticationFailureReason.API_KEY_HEADER_VALUE_NULL;
                result = AuthenticateResult.Fail("ApiKey header value null");

                return false;
            }

            result = null;
            return true;
        }       
    }

    public class ApiKeyAuthenticationOptions : AuthenticationSchemeOptions
    {
        public const string DefaultScheme = "ApiKey";

        public static string Scheme => DefaultScheme;
        public static string AuthenticationType => DefaultScheme;
    }

}