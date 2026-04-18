# AGENTS.md

This file contains essential information for working effectively in this codebase.

## Project Overview

A Go CLI that generates mihomo (Clash Meta) configuration files from subscription URLs.
Input is one or more text files, each containing a list of proxy URIs (one per line).
All other configuration (ports, DNS, proxy-groups, rules, rule-providers) is hardcoded
based on the pattern in `~/mihomo-config/config.yaml`.

## Essential Commands

```bash
go build -o proxy-config-updater .          # Build executable
go test ./...                                # Run all tests
go test -v ./internal/clash                  # Verbose test output
go vet ./...                                 # Static analysis
```

### Run

```bash
# Single subscription file (URIs are in the file directly)
./proxy-config-updater ~/a.txt

# Multiple subscription files (all proxies merged into one config)
./proxy-config-updater ~/a.txt ~/b.txt

# Output to file
./proxy-config-updater ~/a.txt -output config.yaml

# File can also contain subscription URLs (http/https)
# If a line is not a proxy URI, it's fetched as a subscription URL
./proxy-config-updater url-list.txt
```

## Project Structure

```
├── main.go                     # CLI entry point: reads input files, collects proxies, generates config
├── internal/clash/
│   ├── models.go               # Types: ClashConfig, Proxy, ProxyGroup, RuleProvider, DNSConfig
│   ├── generate.go             # Hardcoded defaults, GenerateConfig(), WriteConfig()
│   ├── config.go               # ParseContent(), IsURIList(), ParseURIList()
│   ├── uri.go                  # URI parsing: all protocol parsers (vless, vmess, trojan, ss, tuic, hysteria2)
│   ├── helpers.go              # Shared helpers: decodeFragment, setExtra, stringFromMap, intFromMap
│   ├── fetch.go                # HTTP fetch: FetchContent()
│   ├── decode.go               # Base64: DecodeBase64(), base64DecodeCompat()
│   └── config_test.go          # Tests
├── go.mod / go.sum
└── README.md
```

## Design

1. **Input = proxy URI list**: Each input file has one proxy URI per line (`vless://`, `tuic://`, `hysteria2://`, etc.).
   Lines that aren't proxy URIs are treated as subscription URLs and fetched.

2. **All config is hardcoded**: Ports, DNS, proxy-groups, rules, and rule-providers come from `LoadDefaultConfig()`, `BuildDefaultProxyGroups()`, and `BuildDefaultRules()` in `generate.go`.

3. **Proxy-groups auto-populated**: `BuildDefaultProxyGroups()` takes the list of proxy names and creates all groups (选择节点, 自动选择, ChatGPT, etc.) with all proxies included.

4. **No merge logic**: The old reflection-based `MergeConfigs()` and dual-fetch strategy are removed. `GenerateConfig()` simply combines proxies with hardcoded defaults.

## Dependencies

- Go 1.25.6
- `gopkg.in/yaml.v3`
- Standard library only
