package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------- types ----------

// ClashConfig represents a top-level Clash/mihomo configuration.
type ClashConfig struct {
	Port               int                     `yaml:"port"`
	SocksPort          int                     `yaml:"socks-port"`
	RedirPort          int                     `yaml:"redir-port"`
	AllowLan           bool                    `yaml:"allow-lan"`
	BindAddress        string                  `yaml:"bind-address"`
	Mode               string                  `yaml:"mode"`
	LogLevel           string                  `yaml:"log-level"`
	ExternalController string                  `yaml:"external-controller"`
	Proxies            []Proxy                 `yaml:"proxies"`
	ProxyGroups        []ProxyGroup            `yaml:"proxy-groups"`
	Rules              []string                `yaml:"rules"`
	RuleProviders      map[string]RuleProvider `yaml:"rule-providers,omitempty"`
}

// Proxy represents an individual proxy server configuration.
type Proxy struct {
	Name           string         `yaml:"name"`
	Type           string         `yaml:"type"`
	Server         string         `yaml:"server"`
	Port           int            `yaml:"port"`
	Password       string         `yaml:"password,omitempty"`
	UUID           string         `yaml:"uuid,omitempty"`
	Cipher         string         `yaml:"cipher,omitempty"`
	Network        string         `yaml:"network,omitempty"`
	UDP            bool           `yaml:"udp,omitempty"`
	TLS            bool           `yaml:"tls,omitempty"`
	SkipCertVerify bool           `yaml:"skip-cert-verify,omitempty"`
	Extra          map[string]any `yaml:",inline,omitempty"`
}

// ProxyGroup represents a group of proxies with a selection strategy.
type ProxyGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url,omitempty"`
	Interval int      `yaml:"interval,omitempty"`
}

// RuleProvider represents a rule-provider entry in the configuration.
type RuleProvider struct {
	Type     string `yaml:"type"`
	Behavior string `yaml:"behavior"`
	Format   string `yaml:"format,omitempty"`
	URL      string `yaml:"url"`
	Path     string `yaml:"path"`
	Interval int    `yaml:"interval"`
}

// ---------- constants ----------

// autoGroupName is the name of the url-test group that holds all proxies.
const autoGroupName = "Auto"
const proxyGroupName = "Proxy"

// ---------- main ----------

func main() {
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(fmt.Sprintf("Error reading stdin: %v", err))
	}

	cfg, err := ParseContent(string(content))
	if err != nil {
		fatal(fmt.Sprintf("Error parsing config: %v", err))
	}

	defaultCfg := LoadDefaultConfig()
	if defaultCfg == nil {
		defaultCfg = &ClashConfig{}
	}
	merged := MergeConfigs(defaultCfg, cfg)

	// Populate Auto group with real proxy names
	for i := range merged.ProxyGroups {
		if merged.ProxyGroups[i].Name == autoGroupName {
			names := make([]string, 0, len(merged.Proxies))
			for _, p := range merged.Proxies {
				if isRealProxyName(p.Name) {
					names = append(names, p.Name)
				}
			}
			merged.ProxyGroups[i].Proxies = names
			break
		}
	}

	yamlData, err := yaml.Marshal(merged)
	if err != nil {
		fatal(fmt.Sprintf("Error marshaling YAML: %v", err))
	}
	os.Stdout.Write(yamlData)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

// isRealProxyName returns false for subscription metadata lines masquerading as proxy names.
func isRealProxyName(name string) bool {
	if name == "" {
		return false
	}
	// Common subscription metadata patterns (Chinese)
	metadata := []string{"到期", "剩余", "流量", "时间", "套餐"}
	for _, m := range metadata {
		if strings.Contains(name, m) {
			return false
		}
	}
	// Name must contain at least one ASCII letter (real proxies have service names)
	hasLetter := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			hasLetter = true
			break
		}
	}
	return hasLetter
}

// ---------- base64 ----------

// base64DecodeCompat tries multiple base64 encodings to decode a string.
func base64DecodeCompat(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil {
			return string(decoded), nil
		}
	}
	return "", fmt.Errorf("failed to decode base64: %s", s)
}

// ---------- config ----------

// ParseContent parses subscription content as a URI list and returns a ClashConfig.
func ParseContent(content string) (*ClashConfig, error) {
	trimmed := strings.TrimSpace(content)
	if !IsURIList(trimmed) {
		return nil, fmt.Errorf("content does not contain valid proxy URIs")
	}
	return parseURIList(trimmed)
}

// LoadDefaultConfig returns the embedded default Clash configuration values.
func LoadDefaultConfig() *ClashConfig {
	return &ClashConfig{
		Port:               7890,
		SocksPort:          7891,
		RedirPort:          7892,
		AllowLan:           true,
		BindAddress:        "*",
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		ProxyGroups: []ProxyGroup{
			{Name: proxyGroupName, Type: "select", Proxies: []string{autoGroupName}},
			{Name: autoGroupName, Type: "url-test", Proxies: nil, URL: "https://www.gstatic.com/generate_204", Interval: 3600},
		},
		Rules: []string{
			"DOMAIN-SUFFIX,google.com," + proxyGroupName,
			"DOMAIN-SUFFIX,duckduckgo.com," + proxyGroupName,
			"DOMAIN-SUFFIX,youtube.com," + proxyGroupName,
			"DOMAIN-SUFFIX,twitter.com," + proxyGroupName,
			"DOMAIN-SUFFIX,x.com," + proxyGroupName,
			"DOMAIN-SUFFIX,facebook.com," + proxyGroupName,
			"DOMAIN-SUFFIX,instagram.com," + proxyGroupName,
			"DOMAIN-SUFFIX,telegram.org," + proxyGroupName,
			"RULE-SET,reject,REJECT",
			"RULE-SET,direct,DIRECT",
			"RULE-SET,gfw," + proxyGroupName,
			"RULE-SET,cncidr,DIRECT",
			"GEOIP,CN,DIRECT",
			"MATCH," + proxyGroupName,
		},
		RuleProviders: getDefaultRuleProviders(),
	}
}

// getDefaultRuleProviders returns the embedded rule-provider definitions.
func getDefaultRuleProviders() map[string]RuleProvider {
	return map[string]RuleProvider{
		"direct": {
			Type:     "http",
			Behavior: "domain",
			Format:   "mrs",
			URL:      "https://edgeone.gh-proxy.org/https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/cn-lite.mrs",
			Path:     "./ruleset/direct.list",
			Interval: int(time.Hour * 24 * 7 / time.Second),
		},
		"reject": {
			Type:     "http",
			Behavior: "domain",
			Format:   "mrs",
			URL:      "https://edgeone.gh-proxy.org/raw.githubusercontent.com/privacy-protection-tools/anti-ad.github.io/master/docs/mihomo.mrs",
			Path:     "./ruleset/aiti-ad.list",
			Interval: int(time.Hour * 24 * 7 / time.Second),
		},
		"gfw": {
			Type:     "http",
			Behavior: "domain",
			URL:      "https://edgeone.gh-proxy.org/raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
			Path:     "./ruleset/gfw.list",
			Interval: int(time.Hour * 24 * 7 / time.Second),
		},
		"cncidr": {
			Type:     "http",
			Behavior: "ipcidr",
			Format:   "mrs",
			URL:      "https://edgeone.gh-proxy.org/https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/cnip.mrs",
			Path:     "./ruleset/cncidr.list",
			Interval: int(time.Hour * 24 * 7 / time.Second),
		},
	}
}

// MergeConfigs deep-copies the default config and overlays non-zero subscription fields.
func MergeConfigs(defaultConfig, subscriptionConfig *ClashConfig) *ClashConfig {
	// Deep copy all fields to avoid shared slice/map backing arrays
	merged := &ClashConfig{
		Port:               defaultConfig.Port,
		SocksPort:          defaultConfig.SocksPort,
		RedirPort:          defaultConfig.RedirPort,
		AllowLan:           defaultConfig.AllowLan,
		BindAddress:        defaultConfig.BindAddress,
		Mode:               defaultConfig.Mode,
		LogLevel:           defaultConfig.LogLevel,
		ExternalController: defaultConfig.ExternalController,
	}
	if defaultConfig.Proxies != nil {
		merged.Proxies = make([]Proxy, len(defaultConfig.Proxies))
		copy(merged.Proxies, defaultConfig.Proxies)
	}
	if defaultConfig.ProxyGroups != nil {
		merged.ProxyGroups = make([]ProxyGroup, len(defaultConfig.ProxyGroups))
		copy(merged.ProxyGroups, defaultConfig.ProxyGroups)
	}
	if defaultConfig.Rules != nil {
		merged.Rules = make([]string, len(defaultConfig.Rules))
		copy(merged.Rules, defaultConfig.Rules)
	}
	if defaultConfig.RuleProviders != nil {
		merged.RuleProviders = make(map[string]RuleProvider, len(defaultConfig.RuleProviders))
		for k, v := range defaultConfig.RuleProviders {
			merged.RuleProviders[k] = v
		}
	}

	// Override with non-zero subscription fields
	if subscriptionConfig.Port != 0 {
		merged.Port = subscriptionConfig.Port
	}
	if subscriptionConfig.SocksPort != 0 {
		merged.SocksPort = subscriptionConfig.SocksPort
	}
	if subscriptionConfig.RedirPort != 0 {
		merged.RedirPort = subscriptionConfig.RedirPort
	}
	if subscriptionConfig.AllowLan {
		merged.AllowLan = true
	}
	if subscriptionConfig.BindAddress != "" {
		merged.BindAddress = subscriptionConfig.BindAddress
	}
	if subscriptionConfig.Mode != "" {
		merged.Mode = subscriptionConfig.Mode
	}
	if subscriptionConfig.LogLevel != "" {
		merged.LogLevel = subscriptionConfig.LogLevel
	}
	if subscriptionConfig.ExternalController != "" {
		merged.ExternalController = subscriptionConfig.ExternalController
	}
	if subscriptionConfig.Proxies != nil {
		merged.Proxies = make([]Proxy, len(subscriptionConfig.Proxies))
		copy(merged.Proxies, subscriptionConfig.Proxies)
	}
	if subscriptionConfig.ProxyGroups != nil {
		merged.ProxyGroups = make([]ProxyGroup, len(subscriptionConfig.ProxyGroups))
		copy(merged.ProxyGroups, subscriptionConfig.ProxyGroups)
	}
	if subscriptionConfig.Rules != nil {
		merged.Rules = make([]string, len(subscriptionConfig.Rules))
		copy(merged.Rules, subscriptionConfig.Rules)
	}
	if subscriptionConfig.RuleProviders != nil {
		merged.RuleProviders = make(map[string]RuleProvider, len(subscriptionConfig.RuleProviders))
		for k, v := range subscriptionConfig.RuleProviders {
			merged.RuleProviders[k] = v
		}
	}

	return merged
}

// ---------- URI detection & parsing ----------

var proxySchemes = []string{
	"vless://",
	"vmess://",
	"trojan://",
	"ss://",
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
func parseURIList(content string) (*ClashConfig, error) {
	cfg := &ClashConfig{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		proxy, err := parseProxyURI(line)
		if err != nil {
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
		return nil, nil
	}
}

// ---------- vless ----------

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

	if network := query.Get("type"); network != "" {
		proxy.Network = network
	}

	if security := query.Get("security"); security == "reality" || security == "tls" {
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

	proxy.Extra = applyWSOpts(proxy.Extra, query.Get("path"), query.Get("host"))
	proxy.Extra = applyGRPCOpts(proxy.Extra, query.Get("serviceName"))

	return proxy, nil
}

// ---------- vmess ----------

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

	if network := stringFromMap(v, "net"); network != "" {
		proxy.Network = network
	}
	if stringFromMap(v, "tls") == "tls" {
		proxy.TLS = true
	}
	if sni := stringFromMap(v, "sni"); sni != "" {
		proxy.Extra = setExtra(proxy.Extra, "servername", sni)
	}

	proxy.Extra = applyWSOpts(proxy.Extra, stringFromMap(v, "path"), stringFromMap(v, "host"))
	proxy.Extra = applyGRPCOpts(proxy.Extra, stringFromMap(v, "path"))

	return proxy, nil
}

// ---------- trojan ----------

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

// ---------- ss ----------

func parseSSURI(uri string) (*Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("parsing ss URI: %w", err)
	}

	name := decodeFragment(u.Fragment)
	var host, method, password string
	var port int

	if u.User != nil && u.User.Username() != "" {
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

// ---------- tuic ----------

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

// ---------- hysteria2 ----------

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

// ---------- transport helpers ----------

// applyWSOpts sets WebSocket transport options if path or host is provided.
func applyWSOpts(extra map[string]any, path, host string) map[string]any {
	if path == "" && host == "" {
		return extra
	}
	wsOpts := map[string]any{}
	if path != "" {
		wsOpts["path"] = path
	}
	if host != "" {
		wsOpts["headers"] = map[string]string{"Host": host}
	}
	return setExtra(extra, "ws-opts", wsOpts)
}

// applyGRPCOpts sets gRPC transport options if serviceName is provided.
func applyGRPCOpts(extra map[string]any, serviceName string) map[string]any {
	if serviceName == "" {
		return extra
	}
	return setExtra(extra, "grpc-opts", map[string]any{
		"grpc-service-name": serviceName,
	})
}

// ---------- helpers ----------

func decodeFragment(fragment string) string {
	decoded, err := url.PathUnescape(fragment)
	if err != nil {
		return fragment
	}
	return decoded
}

func setExtra(extra map[string]any, key string, value any) map[string]any {
	if extra == nil {
		extra = make(map[string]any)
	}
	extra[key] = value
	return extra
}

func stringFromMap(m map[string]any, key string) string {
	if val, ok := m[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

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
