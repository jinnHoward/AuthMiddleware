using JinnStudios.Howard.AuthMiddlewareApi.Authentication;
using JinnStudios.Howard.AuthMiddlewareApi.Authentication.Extentions;
using JinnStudios.Howard.AuthMiddlewareApi.Authorization.ApiKey;
using JinnStudios.Howard.AuthMiddlewareApi.Authorization.ApiKeyOrJwt;
using JinnStudios.Howard.AuthMiddlewareApi.Authorization.Jwt;
using JinnStudios.Howard.AuthMiddlewareApi.ControllerExtentions;
using JinnStudios.Howard.AuthMiddlewareApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Logging;
using System.Reflection;

namespace JinnStudios.Howard.AuthMiddlewareApi
{
    public static class Program
    {
        private const string ApiSecret = "ProEMLh5e_qnzdNU";
        private const string EncryptionKey = "ProEMLh5e_qnzdNU";
        private static ConfigurationManager _config = new();
        private static string _environment = string.Empty;

        public static void Main(string[] args)
        {
            WebApplication.CreateBuilder(args)
                .SetupConfiguration()
                .ComposeDependencies()
                .BuildApp()
                .ConfigureApp()
                .Run();
        }

        public static WebApplicationBuilder SetupConfiguration(this WebApplicationBuilder builder)
        {
            builder.Configuration
                .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                .AddJsonFile("appsettings.json", false)
                .AddEnvironmentVariables()
                .AddUserSecrets(Assembly.GetExecutingAssembly());
            _config = builder.Configuration;
            _environment = _config.GetValue<string>("Environment") ?? "development";

            return builder;
        }

        public static WebApplicationBuilder ComposeDependencies(this WebApplicationBuilder builder)
        {
            builder.Services.AddSingleton<IAuthorizationHandler, OrApiKeyRequirementHandler>();
            builder.Services.AddSingleton<IAuthorizationHandler, OrJwtRequirementHandler>();
            builder.Services.AddSingleton<IAuthorizationHandler, JwtRequirementHandler>();
            builder.Services.AddSingleton<IAuthorizationHandler, ApiKeyRequirementHandler>();
            return builder;
        }

        public static WebApplication BuildApp(this WebApplicationBuilder builder)
        {
            builder.Services.AddServices();
            return builder.Build();
        }

        public static void AddServices(this IServiceCollection services)
        {
            services.AddAuthentication();
            services.AddAuthorization(options =>
            {
                options.AddPolicy(AuthConstants.API_OR_JWT, (policy) => policy.AddRequirements(new ApiKeyOrJwtAccessRequirement()));
                options.AddPolicy(AuthConstants.API_AND_JWT, policy => policy.AddRequirements(new ApiKeyRequirement(), new JwtRequirement()));
                options.AddPolicy(AuthConstants.JWT_ONLY, policy => policy.AddRequirements(new JwtRequirement()));
                options.AddPolicy(AuthConstants.API_ONLY, policy => policy.AddRequirements(new ApiKeyRequirement()));
            });

            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();
        }

        private static Action<JwtBearerOptions> GetDefaultJwtOptions()
        {
            return jwtOptions =>
            {
                jwtOptions.TokenValidationParameters = JwtExt.GetValidationParameters(ApiSecret, EncryptionKey);
            };
        }

        private static WebApplication ConfigureApp(this WebApplication app)
        {
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseMiddleware<ApiKeyOrJwtMiddleware>(ApiSecret, EncryptionKey);  //Register as first middleware to avoid other middleware execution before api key check
            app.UseAuthorization();

            app.MapAuthApiController(ApiSecret);
            app.MapWeatherApiController();

            if (EnvIsDevelopment())
                IdentityModelEventSource.ShowPII = true;

            return app;
        }

        private static bool EnvIsDevelopment() => _environment.Trim().ToLower().StartsWith("dev");
        private static bool EnvIsStaging() => _environment.Trim().ToLower().StartsWith("stag");
        private static bool EnvIsProduction() => _environment.Trim().ToLower().StartsWith("prod");
    }
}