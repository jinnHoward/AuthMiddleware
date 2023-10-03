
using AuthMiddlewareApi.Authentication;
using AuthMiddlewareApi.Authentication.Extentions;
using AuthMiddlewareApi.Authorization.ApiKey;
using AuthMiddlewareApi.Authorization.ApiKeyOrJwt;
using AuthMiddlewareApi.Authorization.Jwt;
using AuthMiddlewareApi.ControllerExtentions;
using AuthMiddlewareApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Text;

namespace AuthMiddlewareApi
{
    public static class Program
    {
        private const string ApiSecret = "ProEMLh5e_qnzdNU";
        private const string EncryptionKey = "ProEMLh5e_qnzdNU";
        private static ConfigurationManager _config;
        private static string _environment;

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
            AddServices(builder.Services);
            return builder.Build();
        }

        public static void AddServices(this IServiceCollection services)
        {
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = AuthConstants.API_OR_JWT;
                    options.DefaultChallengeScheme = AuthConstants.API_OR_JWT;
                })
                .AddApiKeyOrJwtSupport(AuthConstants.OR_API, options => { })
                .AddJwtBearer(AuthConstants.OR_JWT, GetDefaultJwtOptions())
                .AddPolicyScheme(AuthConstants.API_OR_JWT, AuthConstants.API_OR_JWT, options =>
                {
                    options.ForwardDefaultSelector = context =>
                    {
                        string? authorization = context.Request.Headers[HeaderNames.Authorization];
                        if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                        {
                            return AuthConstants.OR_JWT;
                        }
                        return AuthConstants.OR_API;
                    };
                });

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = AuthConstants.JWT_ONLY;
                    options.DefaultChallengeScheme = AuthConstants.JWT_ONLY;
                    options.DefaultScheme = AuthConstants.JWT_ONLY;
                })
                .AddJwtBearer(AuthConstants.JWT_ONLY, GetDefaultJwtOptions());

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = AuthConstants.API_ONLY;
                    options.DefaultChallengeScheme = AuthConstants.API_ONLY;
                    options.DefaultScheme = AuthConstants.API_ONLY;
                })
                .AddApiKeySupport(AuthConstants.API_ONLY, options => { });

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = AuthConstants.API_AND_JWT;
                    options.DefaultChallengeScheme = AuthConstants.API_AND_JWT;
                })
                .AddApiKeySupport(options => { })
                .AddJwtBearer(GetDefaultJwtOptions());


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
            app.UseMiddleware<ApiKeyOrJwtMiddleware>();  //Register as first middleware to avoid other middleware execution before api key check
            app.UseAuthorization();

            app.MapAuthApiController(ApiSecret);
            app.MapWeatherApiController();

            return app;
        }
    }
}