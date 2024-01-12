namespace JinnStudios.Howard.AuthMiddlewareApi.Authentication.Extentions
{
    public class ApiKeyValidator : IApiKeyValidator
    {
        public static readonly string API_KEY_HEADER = "X-Api-Key";

        public Task<bool> ValidateApiKey(string apiKey)
        {
            //TODO: setup your validation code...
            return Task.FromResult(apiKey == "EECBA5A9-5541-4D58-A2A2-C6A46AC3D03C");
        }
    }
}