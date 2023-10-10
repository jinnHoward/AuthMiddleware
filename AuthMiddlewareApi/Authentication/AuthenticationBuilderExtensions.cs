using Microsoft.AspNetCore.Authentication;

namespace AuthMiddlewareApi.Authentication
{
    public static class AuthenticationBuilderExtensions
    {
        public static AuthenticationBuilder AddApiKeyOrJwtSupport(this AuthenticationBuilder authenticationBuilder,string schemeName, Action<ApiKeyOrJwtAuthenticationOptions> options)
            => authenticationBuilder.AddScheme<ApiKeyOrJwtAuthenticationOptions, ApiKeyOrJwtAuthenticationHandler>(schemeName, options);

        public static AuthenticationBuilder AddApiKeyOrJwtSupport(this AuthenticationBuilder authenticationBuilder, Action<ApiKeyOrJwtAuthenticationOptions> options)
            => authenticationBuilder.AddApiKeyOrJwtSupport(ApiKeyOrJwtAuthenticationOptions.DefaultScheme, options);

        public static AuthenticationBuilder AddApiKeySupport(this AuthenticationBuilder authenticationBuilder, Action<ApiKeyAuthenticationOptions> options)
            => authenticationBuilder.AddApiKeySupport(ApiKeyAuthenticationOptions.DefaultScheme, options);

        public static AuthenticationBuilder AddApiKeySupport(this AuthenticationBuilder authenticationBuilder, string schemeName, Action<ApiKeyAuthenticationOptions> options)
               => authenticationBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(schemeName, options);
    }
}
