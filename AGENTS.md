# AGENTS.md

This file contains essential information for working effectively in this codebase.

## Project Overview

A Go CLI that generates mihomo (Clash Meta) configuration from proxy URI lists.
Reads proxy URIs from files or stdin, outputs complete YAML config to stdout.
No HTTP fetching or base64 decoding — user handles that with `curl` and `base64`.

## Essential Commands

```bash
go build -o proxy-config-updater .   # Build
go test ./...                         # Test
go vet ./...                          # Lint
```

### Usage

```bash
./proxy-config-updater file.txt > config.yaml
cat a.txt b.txt | ./proxy-config-updater > config.yaml
curl -s URL | base64 -d | ./proxy-config-updater > config.yaml
```

## Project Structure

```
├── main.go                     # CLI: reads files/stdin, parses URIs, writes config to stdout
├── internal/clash/
│   ├── models.go               # Types: ClashConfig, Proxy, ProxyGroup, RuleProvider, DNSConfig
│   ├── generate.go             # Hardcoded defaults, GenerateConfig(), WriteConfig()
│   ├── config.go               # IsProxyURI(), parseClashConfig()
│   ├── uri.go                  # URI parsing: all protocol parsers
│   ├── helpers.go              # Shared helpers: base64DecodeCompat, decodeFragment, etc.
│   └── config_test.go          # Tests
├── go.mod / go.sum
└── README.md
```

## Design

- **Input = proxy URIs only**. No fetching, no base64 content decoding.
- **All config hardcoded** in `generate.go`: ports, DNS, rules, rule-providers.
- **One group**: `AUTO` (url-test, auto-picks fastest node).
- **Rules** use only `AUTO`, `DIRECT`, `REJECT` as targets.
