package clash

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Known proxy URI schemes used for format detection and dispatch.
var proxySchemes = []string{
	"vless://",
	"vmess://",
	"trojan://",
	"ss://",
	"ssr://",
	"tuic://",
	"hysteria2://",
	"hysteria://",
}

// IsURIList returns true if more than half of non-empty lines are proxy URIs.
func IsURIList(content string) bool {
	lines := strings.Split(content, "\n")
	total, uriCount := 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		total++
		for _, scheme := range proxySchemes {
			if strings.HasPrefix(line, scheme) {
				uriCount++
				break
			}
		}
	}
	return uriCount > 0 && uriCount >= total/2
}

// parseURIList parses a list of proxy URI lines into a ClashConfig.
// Invalid lines are skipped with warnings to stderr.
func parseURIList(content string) (*ClashConfig, error) {
	cfg := &ClashConfig{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		proxy, err := parseProxyURI(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse URI: %v\n", err)
			continue
		}
		if proxy != nil {
			cfg.Proxies = append(cfg.Proxies, *proxy)
		}
	}
	return cfg, nil
}

// parseProxyURI dispatches to the appropriate URI parser based on scheme.
func parseProxyURI(line string) (*Proxy, error) {
	switch {
	case strings.HasPrefix(line, "vless://"):
		return parseVlessURI(line)
	case strings.HasPrefix(line, "vmess://"):
		return parseVmessURI(line)
	case strings.HasPrefix(line, "trojan://"):
		return parseTrojanURI(line)
	case strings.HasPrefix(line, "ss://"):
		return parseSSURI(line)
	case strings.HasPrefix(line, "tuic://"):
		return parseTuicURI(line)
	case strings.HasPrefix(line, "hysteria2://") || strings.HasPrefix(line, "hysteria://"):
		return parseHysteria2URI(line)
	default:
		fmt.Fprintf(os.Stderr, "Warning: skipping unrecognized line: %s\n", line)
		return nil, nil
	}
}

// parseVlessURI parses a vless:// URI into a Proxy.
func parseVlessURI(uri string) (*Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing vless URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	query := u.Query()

	proxy := &Proxy{
		Name:   decodeFragment(u.Fragment),
		Type:   "vless",
		Server: u.Hostname(),
		Port:   port,
		UUID:   u.User.Username(),
		UDP:    true,
	}

	network := query.Get("type")
	if network != "" {
		proxy.Network = network
	}

	security := query.Get("security")
	if security == "reality" || security == "tls" {
		proxy.TLS = true
	}

	if flow := query.Get("flow"); flow != "" {
		proxy.Extra = setExtra(proxy.Extra, "flow", flow)
	}
	if fp := query.Get("fp"); fp != "" {
		proxy.Extra = setExtra(proxy.Extra, "client-fingerprint", fp)
	}
	if sni := query.Get("sni"); sni != "" {
		proxy.Extra = setExtra(proxy.Extra, "servername", sni)
	}
	if pbk := query.Get("pbk"); pbk != "" || query.Get("sid") != "" {
		realityOpts := map[string]any{}
		if pbk != "" {
			realityOpts["public-key"] = pbk
		}
		if sid := query.Get("sid"); sid != "" {
			realityOpts["short-id"] = sid
		}
		proxy.Extra = setExtra(proxy.Extra, "reality-opts", realityOpts)
	}
	if query.Get("insecure") == "1" {
		proxy.SkipCertVerify = true
	}

	// Transport options
	if network == "ws" {
		wsOpts := map[string]any{}
		if wsPath := query.Get("path"); wsPath != "" {
			wsOpts["path"] = wsPath
		}
		if host := query.Get("host"); host != "" {
			wsOpts["headers"] = map[string]string{"Host": host}
		}
		if len(wsOpts) > 0 {
			proxy.Extra = setExtra(proxy.Extra, "ws-opts", wsOpts)
		}
	}
	if network == "grpc" {
		if serviceName := query.Get("serviceName"); serviceName != "" {
			proxy.Extra = setExtra(proxy.Extra, "grpc-opts", map[string]any{
				"grpc-service-name": serviceName,
			})
		}
	}

	return proxy, nil
}

// parseVmessURI parses a vmess:// URI (base64-encoded JSON) into a Proxy.
func parseVmessURI(uri string) (*Proxy, error) {
	encoded := strings.TrimPrefix(uri, "vmess://")
	decoded, err := base64DecodeCompat(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding vmess payload: %w", err)
	}

	var v map[string]any
	if err := json.Unmarshal([]byte(decoded), &v); err != nil {
		return nil, fmt.Errorf("parsing vmess JSON: %w", err)
	}

	port := intFromMap(v, "port")
	proxy := &Proxy{
		Name:   stringFromMap(v, "ps"),
		Type:   "vmess",
		Server: stringFromMap(v, "add"),
		Port:   port,
		UUID:   stringFromMap(v, "id"),
		Cipher: stringFromMap(v, "scy"),
		UDP:    true,
	}

	if alterId := intFromMap(v, "aid"); alterId > 0 {
		proxy.Extra = setExtra(proxy.Extra, "alterId", alterId)
	}

	network := stringFromMap(v, "net")
	if network != "" {
		proxy.Network = network
	}
	if stringFromMap(v, "tls") == "tls" {
		proxy.TLS = true
	}
	if sni := stringFromMap(v, "sni"); sni != "" {
		proxy.Extra = setExtra(proxy.Extra, "servername", sni)
	}

	if network == "ws" {
		wsOpts := map[string]any{}
		if wsPath := stringFromMap(v, "path"); wsPath != "" {
			wsOpts["path"] = wsPath
		}
		if host := stringFromMap(v, "host"); host != "" {
			wsOpts["headers"] = map[string]string{"Host": host}
		}
		if len(wsOpts) > 0 {
			proxy.Extra = setExtra(proxy.Extra, "ws-opts", wsOpts)
		}
	}
	if network == "grpc" {
		if serviceName := stringFromMap(v, "path"); serviceName != "" {
			proxy.Extra = setExtra(proxy.Extra, "grpc-opts", map[string]any{
				"grpc-service-name": serviceName,
			})
		}
	}

	return proxy, nil
}

// parseTrojanURI parses a trojan:// URI into a Proxy.
func parseTrojanURI(uri string) (*Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing trojan URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	query := u.Query()

	proxy := &Proxy{
		Name:     decodeFragment(u.Fragment),
		Type:     "trojan",
		Server:   u.Hostname(),
		Port:     port,
		Password: u.User.Username(),
		UDP:      true,
		TLS:      true,
	}

	if sni := query.Get("sni"); sni != "" {
		proxy.Extra = setExtra(proxy.Extra, "sni", sni)
	}
	if query.Get("allowInsecure") == "1" || query.Get("allow_insecure") == "1" {
		proxy.SkipCertVerify = true
	}
	if network := query.Get("type"); network != "" && network != "tcp" {
		proxy.Network = network
	}

	return proxy, nil
}

// parseSSURI parses a ss:// URI into a Proxy.
// Supports both SIP002 (base64(method:password)@host:port) and
// legacy (base64(method:password@host:port)) formats.
func parseSSURI(uri string) (*Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing ss URI: %w", err)
	}

	name := decodeFragment(u.Fragment)
	var host, method, password string
	var port int

	if u.User != nil && u.User.Username() != "" {
		// SIP002: ss://base64(method:password)@host:port#name
		userInfo := u.User.Username()
		if decoded, err := base64DecodeCompat(userInfo); err == nil {
			parts := strings.SplitN(decoded, ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		} else {
			parts := strings.SplitN(userInfo, ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		}
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
	} else {
		// Legacy: ss://base64(method:password@host:port)#name
		decoded, err := base64DecodeCompat(u.Host)
		if err != nil {
			return nil, fmt.Errorf("decoding ss URI: %w", err)
		}
		atIdx := strings.LastIndex(decoded, "@")
		if atIdx < 0 {
			return nil, fmt.Errorf("invalid ss URI format")
		}
		colonIdx := strings.Index(decoded[:atIdx], ":")
		if colonIdx < 0 {
			return nil, fmt.Errorf("invalid ss method:password")
		}
		method = decoded[:colonIdx]
		password = decoded[colonIdx+1 : atIdx]
		h, p, err := net.SplitHostPort(decoded[atIdx+1:])
		if err != nil {
			return nil, fmt.Errorf("invalid ss host:port: %w", err)
		}
		host = h
		port, _ = strconv.Atoi(p)
	}

	return &Proxy{
		Name:     name,
		Type:     "ss",
		Server:   host,
		Port:     port,
		Password: password,
		Cipher:   method,
		UDP:      true,
	}, nil
}

// parseTuicURI parses a tuic:// URI into a Proxy.
func parseTuicURI(uri string) (*Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing tuic URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	query := u.Query()

	proxy := &Proxy{
		Name:     decodeFragment(u.Fragment),
		Type:     "tuic",
		Server:   u.Hostname(),
		Port:     port,
		UUID:     u.User.Username(),
		Password: u.User.Username(),
		UDP:      true,
	}
	if pass, ok := u.User.Password(); ok {
		proxy.Password = pass
	}

	if sni := query.Get("sni"); sni != "" {
		proxy.Extra = setExtra(proxy.Extra, "sni", sni)
	}
	if alpn := query.Get("alpn"); alpn != "" {
		proxy.Extra = setExtra(proxy.Extra, "alpn", []string{alpn})
	}
	if cc := query.Get("congestion_control"); cc != "" {
		proxy.Extra = setExtra(proxy.Extra, "congestion-control", cc)
	}
	if query.Get("allow_insecure") == "1" {
		proxy.SkipCertVerify = true
	}
	if query.Get("disable_sni") == "1" {
		proxy.Extra = setExtra(proxy.Extra, "disable-sni", true)
	}
	if mode := query.Get("udp_relay_mode"); mode != "" {
		proxy.Extra = setExtra(proxy.Extra, "udp-relay-mode", mode)
	}

	return proxy, nil
}

// parseHysteria2URI parses a hysteria2:// URI into a Proxy.
func parseHysteria2URI(uri string) (*Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing hysteria2 URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	query := u.Query()

	proxy := &Proxy{
		Name:     decodeFragment(u.Fragment),
		Type:     "hysteria2",
		Server:   u.Hostname(),
		Port:     port,
		Password: u.User.Username(),
		UDP:      true,
		TLS:      true,
	}

	if sni := query.Get("sni"); sni != "" {
		proxy.Extra = setExtra(proxy.Extra, "sni", sni)
	}
	if query.Get("insecure") == "1" {
		proxy.SkipCertVerify = true
	}
	if obfs := query.Get("obfs"); obfs != "" {
		proxy.Extra = setExtra(proxy.Extra, "obfs", obfs)
		if obfsPass := query.Get("obfs-password"); obfsPass != "" {
			proxy.Extra = setExtra(proxy.Extra, "obfs-password", obfsPass)
		}
	}
	if mport := query.Get("mport"); mport != "" {
		proxy.Extra = setExtra(proxy.Extra, "mport", mport)
	}

	return proxy, nil
}

// --- Helpers ---

// decodeFragment URL-decodes the fragment (after #) of a URI, which may be percent-encoded.
func decodeFragment(fragment string) string {
	decoded, err := url.PathUnescape(fragment)
	if err != nil {
		return fragment
	}
	return decoded
}

// setExtra sets a key-value pair in a proxy's Extra map, creating it if nil.
func setExtra(extra map[string]any, key string, value any) map[string]any {
	if extra == nil {
		extra = make(map[string]any)
	}
	extra[key] = value
	return extra
}

// stringFromMap safely extracts a string value from a map[string]any.
func stringFromMap(m map[string]any, key string) string {
	if val, ok := m[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// intFromMap extracts an int value from a map[string]any (handles float64 and string).
func intFromMap(m map[string]any, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return int(v)
		case string:
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return 0
}
