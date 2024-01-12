namespace JinnHoward.AuthMiddlewareApi.Authentication.Extentions
{
    public interface IApiKeyValidator
    {
        Task<bool> ValidateApiKey(string apiKey);
    }
}