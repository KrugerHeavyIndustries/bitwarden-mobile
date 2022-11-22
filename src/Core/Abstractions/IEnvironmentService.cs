using System.Threading.Tasks;
using Bit.Core.Models.Data;

namespace Bit.Core.Abstractions
{
    public interface IEnvironmentService
    {
        string ApiUrl { get; set; }
        string BaseUrl { get; set; }
        string IconsUrl { get; set; }
        string IdentityUrl { get; set; }
        string NotificationsUrl { get; set; }
        string WebVaultUrl { get; set; }
        string EventsUrl { get; set; }

        string ClientCertificatePem { get; set; }
        string ClientPrivateKeyPem { get; set; }

        string GetWebVaultUrl(bool returnNullIfDefault = false);
        string GetWebSendUrl();
        Task<EnvironmentUrlData> SetUrlsAsync(EnvironmentUrlData urls);
        Task<bool?> SetUseTLSAuthenticationDataAsync(bool? useIt);
        Task<HttpClientData> SetClientCertificateDataAsync(HttpClientData clientData);
        Task SetUrlsFromStorageAsync();
        Task SetUseTLSAuthenticationFromStorageAsync();
        Task SetClientCertificateDataFromStorageAsync();
    }
}
