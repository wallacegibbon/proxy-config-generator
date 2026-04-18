# Proxy Config Updater

A command line tool in Go that generates mihomo (Clash Meta) configuration files from subscription proxy lists.

## How It Works

1. Reads one or more input files, each containing a list of proxy URIs (one per line)
2. Parses all supported proxy protocols (vless, vmess, trojan, ss, tuic, hysteria2)
3. Generates a complete mihomo config with hardcoded defaults (ports, DNS, proxy-groups, rules, rule-providers)
4. Outputs valid YAML ready for mihomo

## Installation

```bash
go build -o proxy-config-updater .
```

## Usage

```bash
proxy-config-updater [-output <path>] <url-file> [url-file2 ...]
```

### Input Files

Each input file contains one entry per line. Lines can be:
- **Proxy URIs**: `vless://...`, `tuic://...`, `hysteria2://...`, `vmess://...`, `trojan://...`, `ss://...`
- **Subscription URLs**: `https://...` — these are fetched and decoded (base64 or raw)

### Examples

```bash
# Generate config from a single proxy list file
proxy-config-updater ~/a.txt

# Merge multiple subscription files into one config
proxy-config-updater ~/a.txt ~/b.txt

# Save to a file
proxy-config-updater ~/a.txt -output config.yaml
```

### Sample Input File

```
vless://uuid@server:443?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=example.com&pbk=key&sid=id#ProxyName
tuic://uuid:pass@server:443?sni=cdn.example.com&alpn=h3&congestion_control=bbr#TUICProxy
hysteria2://pass@server:443/?insecure=1&sni=cdn.example.com#HY2Proxy
```

## Supported Protocols

| Protocol | URI Scheme |
|----------|-----------|
| VLESS | `vless://` |
| VMess | `vmess://` |
| Trojan | `trojan://` |
| Shadowsocks | `ss://` |
| TUIC | `tuic://` |
| Hysteria2 | `hysteria2://` |

## Hardcoded Configuration

The generated config includes:

- **Ports**: 7890 (HTTP), 7891 (SOCKS), 7892 (redirect)
- **DNS**: fake-ip mode with Chinese nameservers
- **Proxy Groups**: 选择节点, 自动选择, Google谷歌应用, ChatGPT, PayPal, 海外游戏平台, Bilibili哔哩哔哩, 广告屏蔽, 主站加速
- **Rules**: ~150 rules for routing (Google, Telegram, OpenAI, gaming, etc.)
- **Rule Providers**: direct, reject, gfw, cncidr

## Dependencies

- Go 1.25.6
- gopkg.in/yaml.v3

## License

MIT
