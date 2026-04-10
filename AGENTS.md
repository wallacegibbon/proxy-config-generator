# AGENTS.md

This file contains essential information for working effectively in this codebase.

## Project Overview

A Go CLI that parses Clash/mihomo subscription configurations. It reads a subscription URL from a file, fetches content from that URL (base64 encoded or raw), decodes it, parses the configuration (YAML or proxy URI list), and outputs a merged configuration with default settings.

## Essential Commands

```bash
go build -o proxy-config-updater .          # Build executable
go test ./...                                # Run all tests
go test -v ./internal/clash                  # Verbose test output
go vet ./...                                 # Static analysis
go mod tidy                                  # Clean up dependencies
```

### Run

```bash
./proxy-config-updater <url-file> [options]

# Options:
#   -output <path>      Output file path (default: stdout)
#   -pretty             Pretty print output (default: true)
#   -pretty=false       Raw output

# Examples:
./proxy-config-updater url.txt
./proxy-config-updater url.txt -output config.yaml
./proxy-config-updater -output config.yaml url.txt   # flags can go anywhere
```

## Project Structure

```
├── main.go                     # CLI entry point: flag parsing, orchestration, output
├── internal/clash/             # Business logic (package clash)
│   ├── models.go               #   Types: ClashConfig, Proxy, ProxyGroup, RuleProvider
│   ├── fetch.go                #   HTTP: FetchContent, FetchClashConfig
│   ├── decode.go               #   Base64: DecodeBase64
│   ├── uri.go                  #   URI parsing: IsURIList, all protocol parsers, helpers
│   ├── config.go               #   ParseContent, LoadDefaultConfig, MergeConfigs, MergeClash
│   └── config_test.go          #   Tests
├── go.mod / go.sum
└── README.md
```

## File Guide

| File | What to edit for... |
|------|-------------------|
| `main.go` | CLI flags, output flow, status messages |
| `internal/clash/models.go` | Struct fields |
| `internal/clash/fetch.go` | HTTP behavior, User-Agents, timeouts |
| `internal/clash/decode.go` | Base64/content decoding |
| `internal/clash/uri.go` | New proxy protocol parsers, URI parsing |
| `internal/clash/config.go` | Defaults, merge logic, format detection |
| `internal/clash/config_test.go` | Tests |

## Key Design Decisions

1. **Dual-fetch strategy**: Two HTTP requests per run — generic UA gets the full proxy list, Clash UA gets proxy-groups/rules. `MergeClash()` combines both responses.

2. **Extra map pattern**: `ClashConfig.Extra` and `Proxy.Extra` use `yaml:",inline,omitempty"` to capture unknown YAML keys. Use the `setExtra()` helper in `uri.go` to populate protocol-specific fields.

3. **URI scheme dispatch**: The `proxySchemes` slice in `uri.go` defines known schemes used by both `IsURIList()` and `parseProxyURI()`. Add new schemes there.

4. **Reflection-based merge**: `MergeConfigs()` copies non-zero fields from subscription over defaults. Maps are replaced entirely, not deep-merged.

## Dependencies

- Go 1.25.6
- `gopkg.in/yaml.v3`
- Standard library only

## Gotchas

1. **File-based URL input**: The tool accepts a filename (not a URL).
2. **User-Agent sensitivity**: Do NOT use "Mozilla" in the UA (triggers reduced proxy set).
3. **`-pretty` default is true**: Set `-pretty=false` for raw output.
4. **Binary may exist**: Rebuild after code changes.
