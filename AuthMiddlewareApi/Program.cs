
using AuthMiddlewareApi.Authentication;
using AuthMiddlewareApi.Extentions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Text;

namespace AuthMiddlewareApi
{
    public static class Program
    {
        public const string AccessAudience = "TestAud";
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
            //builder.Services.AddSingleton<IAuthorizationPolicyProvider, MinimumAgePolicyProvider>();
            builder.Services.AddSingleton<IAuthorizationHandler, TemporaryStickerHandler>();
            builder.Services.AddSingleton<IAuthorizationHandler, BadgeEntryHandler>();
            return builder;
        }

        public static WebApplication BuildApp(this WebApplicationBuilder builder)
        {
            AddServices(builder.Services);
            return builder.Build();
        }

        public static void AddServices(this IServiceCollection services)
        {
            //services.AddAuthentication();
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = ApiKeyAuthenticationOptions.DefaultScheme;
                    options.DefaultChallengeScheme = ApiKeyAuthenticationOptions.DefaultScheme;
                })
                .AddApiKeySupport(options => { });

            //services.AddAuthentication(options =>
            //    {
            //        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            //    })
            //    .AddJwtBearer(jwtOptions =>
            //    {
            //        jwtOptions.TokenValidationParameters = JwtExtensions.GetValidationParameters("ProEMLh5e_qnzdNU", "ProEMLh5e_qnzdNU");
            //    });

            //services.AddAuthorization();
            services.AddAuthorization(options =>
            {
                options.AddPolicy("Api_Or_Jwt", policy => policy.AddRequirements(new BuildingEntryRequirement()));
            });

            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen();
        }               

        private static WebApplication ConfigureApp(this WebApplication app)
        {
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            //app.UseMiddleware<SimpleApiKeyMiddleware>();  //Register as first middleware to avoid other middleware execution before api key check
            app.UseAuthorization();

            app.MapWeatherApiController();

            return app;
        }
    }
}