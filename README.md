# Proxy Config Updater

A command line tool that generates mihomo (Clash Meta) configuration from proxy URI lists.

Reads proxy URIs from files or stdin, outputs a complete mihomo YAML config to stdout.

> [!WARNING]
> **This project is mostly useless.** Many subscription providers inspect the
> User Agent and directly return the corresponding mihomo/Clash config, so
> there's usually no need to parse proxy URIs and generate a config yourself.
> Just fetch the subscription with curl using a Clash Meta User Agent:
>
> ```bash
> curl -sL -A "ClashMetaForAndroid/2.11.1" https://blah.com/a/b/c/subscription > ~/mihomo-config/config.yaml
> ```
>
> This tool is only useful when a provider does not support returning a mihomo
> config based on the User Agent (e.g. it only returns a base64-encoded list of
> proxy URIs).

## Installation

```bash
go build -o proxy-config-updater .
```

## Usage

```bash
# From file
./proxy-config-updater proxies.txt > config.yaml

# From stdin
./proxy-config-updater < proxies.txt > config.yaml

# Merge multiple files
cat a.txt b.txt | ./proxy-config-updater > config.yaml

# Fetch and decode a subscription
curl -s URL | base64 -d | ./proxy-config-updater > config.yaml
```

## Input Format

One proxy URI per line:

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
| AnyTLS | `anytls://` |

## Generated Config

The output is a complete mihomo config with hardcoded defaults:

- **Ports**: 7890 (HTTP), 7891 (SOCKS), 7892 (redirect)
- **DNS**: fake-ip mode (`198.18.0.1/16`) with Chinese nameservers (223.5.5.5, 119.29.29.29)
- **Groups**: `Proxy` (select) → `Auto` (url-test, auto-selects fastest node)
- **Rules**: route to `Proxy`, `DIRECT`, or `REJECT`
- **Rule Providers**: direct, reject, gfw, cncidr

Unsupported proxy schemes, unparseable lines, and subscription metadata lines
masquerading as proxies (e.g. names containing 到期/剩余/流量/时间/套餐) are
skipped with a warning on stderr.

## Dependencies

- Go 1.25.6
- gopkg.in/yaml.v3

## License

MIT
