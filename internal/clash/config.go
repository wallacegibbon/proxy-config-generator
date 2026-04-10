package clash

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseContent detects the content format (Clash YAML or URI list) and parses it.
func ParseContent(content string) (*ClashConfig, error) {
	trimmed := strings.TrimSpace(content)
	if IsURIList(trimmed) {
		fmt.Fprintln(os.Stderr, "Detected URI list format, parsing proxy URIs...")
		return parseURIList(trimmed)
	}
	return parseClashConfig(trimmed)
}

// parseClashConfig unmarshals a Clash YAML string into a ClashConfig.
func parseClashConfig(content string) (*ClashConfig, error) {
	var cfg ClashConfig
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// LoadDefaultConfig returns the embedded default Clash configuration values.
func LoadDefaultConfig() (*ClashConfig, error) {
	return &ClashConfig{
		Port:               7890,
		SocksPort:          7891,
		RedirPort:          7892,
		AllowLan:           true,
		BindAddress:        "*",
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
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

// MergeConfigs merges the subscription config into the default config.
// Non-zero fields from the subscription override default values.
// Maps (like rule-providers) are replaced entirely, not merged.
func MergeConfigs(defaultConfig, subscriptionConfig *ClashConfig) *ClashConfig {
	merged := *defaultConfig

	subVal := reflect.ValueOf(subscriptionConfig).Elem()
	defVal := reflect.ValueOf(&merged).Elem()

	for i := 0; i < subVal.NumField(); i++ {
		subField := subVal.Field(i)
		defField := defVal.Field(i)
		if !subField.IsZero() {
			defField.Set(subField)
		}
	}

	return &merged
}

// MergeClash merges proxy-groups, rules, and extra fields from the
// Clash-format response into the main config (from the generic-UA response).
func MergeClash(cfg, clash *ClashConfig) {
	// Collect all proxy names for deduplication and group population
	proxyNames := make(map[string]bool)
	for _, p := range cfg.Proxies {
		proxyNames[p.Name] = true
	}

	// Add proxies from Clash response that aren't already present
	for _, p := range clash.Proxies {
		if !proxyNames[p.Name] {
			cfg.Proxies = append(cfg.Proxies, p)
			proxyNames[p.Name] = true
		}
	}

	// Use proxy-groups from Clash response if main config has none
	if len(clash.ProxyGroups) > 0 && len(cfg.ProxyGroups) == 0 {
		for i, group := range clash.ProxyGroups {
			if group.Type == "select" || group.Type == "url-test" {
				existing := make(map[string]bool)
				for _, p := range group.Proxies {
					existing[p] = true
				}
				for name := range proxyNames {
					if !existing[name] {
						clash.ProxyGroups[i].Proxies = append(clash.ProxyGroups[i].Proxies, name)
					}
				}
			}
		}
		cfg.ProxyGroups = clash.ProxyGroups
	}

	if len(clash.Rules) > 0 && len(cfg.Rules) == 0 {
		cfg.Rules = clash.Rules
	}
	if clash.Extra != nil && cfg.Extra == nil {
		cfg.Extra = clash.Extra
	}
}
