namespace JinnStudios.Howard.AuthMiddlewareApi.Authentication.Extentions
{
    public interface IApiKeyValidator
    {
        Task<bool> ValidateApiKey(string apiKey);
    }
}