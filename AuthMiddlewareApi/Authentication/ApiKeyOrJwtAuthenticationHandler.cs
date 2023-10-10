using AuthMiddlewareApi.Authentication.Extentions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
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
        private enum AuthenticationFailureReason
        {
            NONE = 0,
            API_KEY_HEADER_NOT_PROVIDED,
            API_KEY_HEADER_VALUE_NULL,
            API_KEY_INVALID
        }

        private readonly IOptionsMonitor<ApiKeyOrJwtAuthenticationOptions> _options;
        private readonly Microsoft.Extensions.Logging.ILogger _logger;

        private AuthenticationFailureReason _failureReason = AuthenticationFailureReason.NONE;

        public ApiKeyOrJwtAuthenticationHandler(IOptionsMonitor<ApiKeyOrJwtAuthenticationOptions> options,
                                           ILoggerFactory loggerFactory,
                                           ILogger<ApiKeyOrJwtAuthenticationHandler> logger,
                                           UrlEncoder encoder,
                                           ISystemClock clock) : base(options, loggerFactory, encoder, clock)
        {
            _options = options;
            _logger = logger;
        }

        protected async override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (AuthOptions.None == _options.CurrentValue.AuthOption)
                return SetDefaultFailureAndReturn();

            var authToken = AuthenticationLogic.GetHeaderValueOrEmpty(Request, AuthenticationLogic.AUTHORIZATION_HEADER);
            var apiKey = AuthenticationLogic.GetHeaderValueOrEmpty(Request, ApiKeyExt.API_KEY_HEADER);
            var requester = AuthenticationLogic.GetRequester(authToken, apiKey);
            var isApiKeyValid = false;
            var isJwtValid = false;


            if (IsJwtValidationRequired())
                isJwtValid = (await JwtExt.ValidateToken(authToken!, null)).IsValid;

            if (IsApiKeyValidationRequired())
                isApiKeyValid = await ApiKeyCheckAsync(apiKey);                

            if (IsJwtValidationRequired() == isJwtValid && IsApiKeyValidationRequired() == isApiKeyValid)
                return GetSuccessfullAuthResult(requester);


            return SetDefaultFailureAndReturn();
        }

        private bool IsApiKeyValidationRequired()
        {
            return _options.CurrentValue.AuthOption == AuthOptions.ApiOnly || _options.CurrentValue.AuthOption == AuthOptions.ApiOrJwt || _options.CurrentValue.AuthOption == AuthOptions.ApiAndJwt;
        }

        private static AuthenticateResult GetSuccessfullAuthResult(string requester)
        {
            var identity = GetClaimsIdentity(requester);

            var principal = new ClaimsPrincipal();  //TODO: Create your Identity retreiving claims
            principal.AddIdentity(identity);
            var ticket = new AuthenticationTicket(principal, ApiKeyOrJwtAuthenticationOptions.Scheme);

            return AuthenticateResult.Success(ticket);
        }

        private bool IsJwtValidationRequired()
        {
            return _options.CurrentValue.AuthOption == AuthOptions.JwtOnly || _options.CurrentValue.AuthOption == AuthOptions.ApiOrJwt || _options.CurrentValue.AuthOption == AuthOptions.ApiAndJwt;
        }

        private AuthenticateResult SetDefaultFailureAndReturn()
        {
            _failureReason = AuthenticationFailureReason.NONE;
            return AuthenticateResult.NoResult();
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            //Create response
            Response.Headers.Append(HeaderNames.WWWAuthenticate, $@"Authorization realm=""{ApiKeyOrJwtAuthenticationOptions.DefaultScheme}""");
            Response.StatusCode = StatusCodes.Status401Unauthorized;
            Response.ContentType = MediaTypeNames.Application.Json;

            //TODO: setup a response to provide additional information if you want
            var result = new
            {
                StatusCode = Response.StatusCode,
                Message = _failureReason switch
                {
                    AuthenticationFailureReason.NONE => "Authentication failed",
                    AuthenticationFailureReason.API_KEY_HEADER_NOT_PROVIDED => "ApiKey not provided",
                    AuthenticationFailureReason.API_KEY_HEADER_VALUE_NULL => "ApiKey value is null",                     
                    AuthenticationFailureReason.API_KEY_INVALID or _ => "ApiKey is not valid"
                }
            };

            using var responseStream = new MemoryStream();
            await JsonSerializer.SerializeAsync(responseStream, result);
            await Response.BodyWriter.WriteAsync(responseStream.ToArray());
        }

        protected override async Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            //Create response
            Response.Headers.Append(HeaderNames.WWWAuthenticate, $@"Authorization realm=""{ApiKeyOrJwtAuthenticationOptions.DefaultScheme}""");
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
            var isValid = apiKey == "EECBA5A9-5541-4D58-A2A2-C6A46AC3D03C";
            if (isValid)
                _logger.LogInformation("ApiKey validated: {ApiKey}", apiKey);
            else 
                _logger.LogError("ApiKey is not valid: {ApiKey}", apiKey);

            return Task.FromResult<bool>(isValid);
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
        public AuthOptions AuthOption { get; set; }

    }

    public enum AuthOptions
    {
        None = 0,
        ApiOnly = 1,
        JwtOnly = 2,
        ApiOrJwt = 3,
        ApiAndJwt = 4,
    }
}
