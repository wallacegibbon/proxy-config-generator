# Proxy Config Updater

A command line tool that generates mihomo (Clash Meta) configuration from proxy URI lists.

Reads proxy URIs from files or stdin, outputs a complete mihomo YAML config to stdout.

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

## Generated Config

The output is a complete mihomo config with hardcoded defaults:

- **Ports**: 7890 (HTTP), 7891 (SOCKS), 7892 (redirect)
- **DNS**: fake-ip mode with Chinese nameservers
- **Group**: single `AUTO` group (url-test, auto-selects fastest node)
- **Rules**: ~150 rules routing to AUTO, DIRECT, or REJECT
- **Rule Providers**: direct, reject, gfw, cncidr

## Dependencies

- Go 1.25.6
- gopkg.in/yaml.v3

## License

MIT
