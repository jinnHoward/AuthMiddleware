
using AuthMiddlewareApi.Extentions;
using Microsoft.AspNetCore.Authorization;
using System.Reflection;

namespace AuthMiddlewareApi
{
    public static class Program
    {
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
            // services.AddTransient<IAuthorizationService>(x => { });
            return builder;
        }

        public static WebApplication BuildApp(this WebApplicationBuilder builder)
        {
            AddServices(builder.Services);
            return builder.Build();
        }

        public static void AddServices(this IServiceCollection services)
        {
            services.AddAuthorization();
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

            app.UseAuthorization();

            app.MapWeatherApiController();

            return app;
        }
    }
}