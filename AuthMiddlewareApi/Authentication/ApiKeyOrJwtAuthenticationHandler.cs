using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using System.Net.Mime;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AuthMiddlewareApi.Authentication
{
    public class ApiKeyOrJwtAuthenticationHandler : AuthenticationHandler<ApiKeyOrJwtAuthenticationOptions>
    {
        private static readonly string API_KEY_HEADER = "X-Api-Key";
        private enum AuthenticationFailureReason
        {
            NONE = 0,
            API_KEY_HEADER_NOT_PROVIDED,
            API_KEY_HEADER_VALUE_NULL,
            API_KEY_INVALID
        }
        private readonly Microsoft.Extensions.Logging.ILogger _logger;

        private AuthenticationFailureReason _failureReason = AuthenticationFailureReason.NONE;

        public ApiKeyOrJwtAuthenticationHandler(IOptionsMonitor<ApiKeyOrJwtAuthenticationOptions> options,
                                           ILoggerFactory loggerFactory,
                                           ILogger<ApiKeyAuthenticationHandler> logger,
                                           UrlEncoder encoder,
                                           ISystemClock clock) : base(options, loggerFactory, encoder, clock)
        {
            _logger = logger;
        }

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {

            if (Request.Headers.TryGetValue("Authorization", out var authToken))
            {
                if ((await JwtExtensions.ValidateToken(authToken!, null)).IsValid)
                {
                    var identity = GetClaimsIdentity("UI/USER");

                    var principal = new ClaimsPrincipal();  //TODO: Create your Identity retreiving claims
                    principal.AddIdentity(identity);
                    var ticket = new AuthenticationTicket(principal, ApiKeyAuthenticationOptions.Scheme);

                    return AuthenticateResult.Success(ticket);
                }
            }
            //Get apikey header
            if (Request.Headers.TryGetValue(API_KEY_HEADER, out var apiKey))
            {
                if (!await ApiKeyCheckAsync(apiKey))
                {
                    _logger.LogError("ApiKey is not valid: {ApiKey}", apiKey);
                }
                else
                {
                    _logger.LogInformation("ApiKey validated: {ApiKey}", apiKey);


                    var identity = GetClaimsIdentity("SDK/APP");

                    var principal = new ClaimsPrincipal();  //TODO: Create your Identity retreiving claims
                    principal.AddIdentity(identity);
                    var ticket = new AuthenticationTicket(principal, ApiKeyAuthenticationOptions.Scheme);
                    return AuthenticateResult.Success(ticket);
                }
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

        private Task<bool> ApiKeyCheckAsync(string apiKey)
        {
            //TODO: setup your validation code...
            return Task.FromResult<bool>(apiKey == "EECBA5A9-5541-4D58-A2A2-C6A46AC3D03C");
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
    }

    public class ApiKeyOrJwtAuthenticationOptions : AuthenticationSchemeOptions
    {
        public const string DefaultScheme = "ApiKey";

        public static string Scheme => DefaultScheme;
        public static string AuthenticationType => DefaultScheme;
    }
}
