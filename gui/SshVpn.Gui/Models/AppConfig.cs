using System.Text.Json.Serialization;

namespace SshVpn.Gui.Models;

internal sealed class AppConfig
{
    [JsonPropertyName("server_address")]
    public string ServerAddress { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("proxy_port")]
    public int ProxyPort { get; set; } = 1080;
}
