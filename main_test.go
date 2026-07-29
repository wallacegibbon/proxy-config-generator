package main

import (
	"reflect"
	"testing"
)

func TestMergeConfigs(t *testing.T) {
	tests := []struct {
		name          string
		defaultConfig *ClashConfig
		subscription  *ClashConfig
		want          *ClashConfig
	}{
		{
			name: "subscription overrides non-zero fields",
			defaultConfig: &ClashConfig{
				Port:      7890,
				SocksPort: 7891,
				AllowLan:  true,
				Mode:      "rule",
			},
			subscription: &ClashConfig{
				Port: 9999,
				Mode: "global",
			},
			want: &ClashConfig{
				Port:      9999,
				SocksPort: 7891,
				AllowLan:  true,
				Mode:      "global",
			},
		},
		{
			name: "subscription zero fields do not override",
			defaultConfig: &ClashConfig{
				Port:      7890,
				SocksPort: 7891,
			},
			subscription: &ClashConfig{
				Port: 0,
				Mode: "rule",
			},
			want: &ClashConfig{
				Port:      7890,
				SocksPort: 7891,
				Mode:      "rule",
			},
		},
		{
			name: "empty slice overrides nil slice",
			defaultConfig: &ClashConfig{
				Port:    7890,
				Proxies: nil,
			},
			subscription: &ClashConfig{
				Port:    7890,
				Proxies: []Proxy{},
			},
			want: &ClashConfig{
				Port:    7890,
				Proxies: []Proxy{},
			},
		},
		{
			name: "rule-providers map overrides",
			defaultConfig: &ClashConfig{
				Port: 7890,
				RuleProviders: map[string]RuleProvider{
					"direct": {
						Type:     "http",
						Behavior: "domain",
						URL:      "https://example.com/direct",
						Path:     "./ruleset/direct.list",
						Interval: 604800,
					},
				},
			},
			subscription: &ClashConfig{
				Port: 9999,
				RuleProviders: map[string]RuleProvider{
					"reject": {
						Type:     "http",
						Behavior: "domain",
						URL:      "https://example.com/reject",
						Path:     "./ruleset/reject.list",
						Interval: 604800,
					},
				},
			},
			want: &ClashConfig{
				Port: 9999,
				RuleProviders: map[string]RuleProvider{
					"reject": {
						Type:     "http",
						Behavior: "domain",
						URL:      "https://example.com/reject",
						Path:     "./ruleset/reject.list",
						Interval: 604800,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeConfigs(tt.defaultConfig, tt.subscription)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MergeConfigs() = %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestLoadDefaultConfig(t *testing.T) {
	cfg := LoadDefaultConfig()
	if cfg == nil {
		t.Fatal("LoadDefaultConfig() returned nil")
	}

	want := &ClashConfig{
		Port:               7890,
		SocksPort:          7891,
		RedirPort:          7892,
		AllowLan:           true,
		BindAddress:        "*",
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		ProxyGroups: []ProxyGroup{
			{Name: "Proxy", Type: "select", Proxies: []string{"Auto"}},
			{Name: "Auto", Type: "url-test", Proxies: nil, URL: "https://www.gstatic.com/generate_204", Interval: 3600},
		},
		Rules: []string{
			"DOMAIN-SUFFIX,google.com,Proxy",
			"DOMAIN-SUFFIX,duckduckgo.com,Proxy",
			"DOMAIN-SUFFIX,youtube.com,Proxy",
			"DOMAIN-SUFFIX,twitter.com,Proxy",
			"DOMAIN-SUFFIX,x.com,Proxy",
			"DOMAIN-SUFFIX,facebook.com,Proxy",
			"DOMAIN-SUFFIX,instagram.com,Proxy",
			"DOMAIN-SUFFIX,telegram.org,Proxy",
			"RULE-SET,reject,REJECT",
			"RULE-SET,direct,DIRECT",
			"RULE-SET,gfw,Proxy",
			"RULE-SET,cncidr,DIRECT",
			"GEOIP,CN,DIRECT",
			"MATCH,Proxy",
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
	}

	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("LoadDefaultConfig() = %+v\nwant %+v", cfg, want)
	}
}
