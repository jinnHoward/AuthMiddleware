
using AuthMiddlewareApi.Authentication;
using AuthMiddlewareApi.Authorization;
using AuthMiddlewareApi.ControllerExtentions;
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
        public const string AccessAudience = "TestAud";
        private const string API_OR_JWT = "API_OR_JWT";
        private const string OR_API = "OR_API";
        private const string OR_JWT = "OR_JWT";

        private const string API_AND_JWT = "API_AND_JWT";
        private const string AND_API = "AND_API";
        private const string AND_JWT = "AND_JWT";
        
        private const string JWT_ONLY = "JWT_ONLY";
        private const string API_ONLY = "API_ONLY";

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
                    options.DefaultAuthenticateScheme = API_OR_JWT;
                    options.DefaultChallengeScheme = API_OR_JWT;
                })
                .AddApiKeyOrJwtSupport(OR_API, options => { })
                .AddJwtBearer(OR_JWT, GetDefaultJwtOptions())
                .AddPolicyScheme(API_OR_JWT, API_OR_JWT, options =>
                {
                    options.ForwardDefaultSelector = context =>
                    {
                        string? authorization = context.Request.Headers[HeaderNames.Authorization];
                        if (!string.IsNullOrEmpty(authorization) && authorization.StartsWith("Bearer "))
                        {
                            return OR_JWT;
                        }
                        return OR_API;
                    };
                });

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = JWT_ONLY;
                    options.DefaultChallengeScheme = JWT_ONLY;
                    options.DefaultScheme = JWT_ONLY;
                })
                .AddJwtBearer(JWT_ONLY, GetDefaultJwtOptions());

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = API_ONLY;
                    options.DefaultChallengeScheme = API_ONLY;
                    options.DefaultScheme = API_ONLY;
                })
                .AddApiKeySupport(API_ONLY, options => { });

            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = API_AND_JWT;
                    options.DefaultChallengeScheme = API_AND_JWT;
                })
                .AddApiKeySupport(options => { })
                .AddJwtBearer(GetDefaultJwtOptions());


            services.AddAuthorization(options =>
            {
                options.AddPolicy("API_OR_JWT", (policy) => policy.AddRequirements(new ApiKeyOrJwtAccessRequirement()));
                options.AddPolicy("API_AND_JWT", policy => policy.AddRequirements(new ApiKeyRequirement(), new JwtRequirement()));
                options.AddPolicy("JWT_ONLY", policy => policy.AddRequirements(new JwtRequirement()));
                options.AddPolicy("API_ONLY", policy => policy.AddRequirements(new ApiKeyRequirement()));
            });

            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();
        }

        private static Action<ApiKeyOrJwtAuthenticationOptions> GetDefaultApiKeyOrJwtOptions()
        {
            return options => { };
        }

        private static Action<JwtBearerOptions> GetDefaultJwtOptions()
        {
            return jwtOptions =>
            {
                jwtOptions.TokenValidationParameters = JwtExtensions.GetValidationParameters("ProEMLh5e_qnzdNU", "ProEMLh5e_qnzdNU");
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

            app.MapAuthApiController();
            app.MapWeatherApiController();

            return app;
        }
    }
}