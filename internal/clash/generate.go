package clash

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// LoadDefaultConfig returns the hardcoded default mihomo configuration.
func LoadDefaultConfig() (*ClashConfig, error) {
	return &ClashConfig{
		Port:               7890,
		SocksPort:          7891,
		AllowLan:           true,
		BindAddress:        "*",
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		TCPConcurrent:      true,
		UnifiedDelay:       true,
		DNS: DNSConfig{
			DefaultNameservers: []string{
				"223.5.5.5",
				"119.29.29.29",
				"[2400:3200::1]:53",
				"[240C::6666]:53",
				"system",
			},
			DirectNameservers: []string{
				"https://1.12.12.12/dns-query",
				"https://120.53.53.53/dns-query",
				"https://sm2.doh.pub/dns-query",
				"https://223.5.5.5/dns-query",
				"https://223.6.6.6/dns-query",
				"system",
			},
			Enable:       true,
			EnhancedMode: "fake-ip",
			FakeIPRange:  "198.18.0.1/16",
			IPv6:         true,
			ProxyServerNameserver: []string{
				"https://1.12.12.12/dns-query",
				"https://120.53.53.53/dns-query",
				"https://sm2.doh.pub/dns-query",
				"https://223.5.5.5/dns-query",
				"https://223.6.6.6/dns-query",
				"system",
			},
			UseHosts: true,
		},
		RuleProviders: map[string]RuleProvider{
			"direct": {
				Type:     "http",
				Behavior: "domain",
				Format:   "mrs",
				URL:      "https://edgeone.gh-proxy.org/https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/cn-lite.mrs",
				Path:     "./ruleset/direct.list",
				Interval: 604800,
			},
			"reject": {
				Type:     "http",
				Behavior: "domain",
				Format:   "mrs",
				URL:      "https://edgeone.gh-proxy.org/raw.githubusercontent.com/privacy-protection-tools/anti-ad.github.io/master/docs/mihomo.mrs",
				Path:     "./ruleset/aiti-ad.list",
				Interval: 604800,
			},
			"gfw": {
				Type:     "http",
				Behavior: "domain",
				URL:      "https://edgeone.gh-proxy.org/raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
				Path:     "./ruleset/gfw.list",
				Interval: 604800,
			},
			"cncidr": {
				Type:     "http",
				Behavior: "ipcidr",
				Format:   "mrs",
				URL:      "https://edgeone.gh-proxy.org/https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/cnip.mrs",
				Path:     "./ruleset/cncidr.list",
				Interval: 604800,
			},
		},
	}, nil
}

// BuildDefaultRules returns the hardcoded rules list.
// Most routing is handled by rule-providers (gfw, direct, reject, cncidr).
// Here we only add what they don't cover: private IPs and fallback.
func BuildDefaultRules() []string {
	return []string{
		// --- Rule-sets (handle most routing) ---
		"RULE-SET,reject,REJECT",
		"RULE-SET,gfw,AUTO",
		"RULE-SET,direct,DIRECT",

		// --- Private IPs ---
		"IP-CIDR,0.0.0.0/8,DIRECT",
		"IP-CIDR,10.0.0.0/8,DIRECT",
		"IP-CIDR,100.64.0.0/10,DIRECT",
		"IP-CIDR,127.0.0.0/8,DIRECT",
		"IP-CIDR,169.254.0.0/16,DIRECT",
		"IP-CIDR,172.16.0.0/12,DIRECT",
		"IP-CIDR,192.0.0.0/24,DIRECT",
		"IP-CIDR,192.0.2.0/24,DIRECT",
		"IP-CIDR,192.88.99.0/24,DIRECT",
		"IP-CIDR,192.168.0.0/16,DIRECT",
		"IP-CIDR,198.18.0.0/15,DIRECT",
		"IP-CIDR,198.51.100.0/24,DIRECT",
		"IP-CIDR,203.0.113.0/24,DIRECT",
		"IP-CIDR,224.0.0.0/3,DIRECT",
		"IP-CIDR,::/127,DIRECT",
		"IP-CIDR,fc00::/7,DIRECT",
		"IP-CIDR,fe80::/10,DIRECT",
		"IP-CIDR,ff00::/8,DIRECT",
		"RULE-SET,cncidr,DIRECT",

		// --- Fallback ---
		"MATCH,AUTO",
	}
}

// BuildDefaultProxyGroups builds proxy-groups from a list of proxy names.
func BuildDefaultProxyGroups(proxyNames []string) []ProxyGroup {
	return []ProxyGroup{
		{
			Name:     "AUTO",
			Type:     "url-test",
			Proxies:  proxyNames,
			URL:      "https://www.gstatic.com/generate_204",
			Interval: 30,
		},
	}
}

// GenerateConfig generates a complete mihomo config from parsed proxies.
func GenerateConfig(proxies []Proxy) (*ClashConfig, error) {
	defaultCfg, err := LoadDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("loading defaults: %w", err)
	}

	proxyNames := make([]string, 0, len(proxies))
	for _, p := range proxies {
		proxyNames = append(proxyNames, p.Name)
	}

	cfg := *defaultCfg
	cfg.Proxies = proxies
	cfg.ProxyGroups = BuildDefaultProxyGroups(proxyNames)
	cfg.Rules = BuildDefaultRules()

	return &cfg, nil
}

// WriteConfig marshals a ClashConfig to YAML and writes it.
func WriteConfig(cfg *ClashConfig, w io.Writer) error {
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	return encoder.Encode(cfg)
}
