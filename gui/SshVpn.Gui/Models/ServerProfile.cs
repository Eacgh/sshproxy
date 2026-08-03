using System.Text.Json.Serialization;

namespace SshVpn.Gui.Models;

// 一条服务器配置，对应核心 config.json 的一个可用服务器。
internal sealed class ServerProfile
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("server_address")]
    public string ServerAddress { get; set; } = string.Empty;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    [JsonPropertyName("proxy_port")]
    public int ProxyPort { get; set; } = 1080;

    [JsonPropertyName("dns_server")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? DnsServer { get; set; }
}
