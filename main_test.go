package main

import (
	"reflect"
	"strings"
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
				MixedPort: 7890,
				AllowLan:  true,
				Mode:      "rule",
			},
			subscription: &ClashConfig{
				MixedPort: 9999,
				Mode:      "global",
			},
			want: &ClashConfig{
				MixedPort: 9999,
				AllowLan:  true,
				Mode:      "global",
			},
		},
		{
			name: "subscription zero fields do not override",
			defaultConfig: &ClashConfig{
				MixedPort: 7890,
			},
			subscription: &ClashConfig{
				Mode: "rule",
			},
			want: &ClashConfig{
				MixedPort: 7890,
				Mode:      "rule",
			},
		},
		{
			name: "empty slice overrides nil slice",
			defaultConfig: &ClashConfig{
				MixedPort: 7890,
				Proxies:   nil,
			},
			subscription: &ClashConfig{
				MixedPort: 7890,
				Proxies:   []Proxy{},
			},
			want: &ClashConfig{
				MixedPort: 7890,
				Proxies:   []Proxy{},
			},
		},
		{
			name: "rule-providers map overrides",
			defaultConfig: &ClashConfig{
				MixedPort: 7890,
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
				MixedPort: 9999,
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
				MixedPort: 9999,
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

func TestMergeConfigsPreservesDefaultDNS(t *testing.T) {
	def := LoadDefaultConfig()
	def.DNS.NameserverPolicy = map[string][]string{
		"geosite:cn": {"223.5.5.5", "119.29.29.29"},
	}
	got := MergeConfigs(def, &ClashConfig{})
	if !reflect.DeepEqual(got.DNS, def.DNS) {
		t.Fatalf("MergeConfigs() DNS = %+v\nwant %+v", got.DNS, def.DNS)
	}
	// Mutating the merged DNS must not affect the default config (deep copy).
	got.DNS.Nameserver[0] = "1.1.1.1"
	got.DNS.NameserverPolicy["geosite:cn"][0] = "1.1.1.1"
	if def.DNS.Nameserver[0] != "223.5.5.5" {
		t.Errorf("default DNS nameserver mutated: %v", def.DNS.Nameserver)
	}
	if def.DNS.NameserverPolicy["geosite:cn"][0] != "223.5.5.5" {
		t.Errorf("default DNS policy mutated: %v", def.DNS.NameserverPolicy)
	}
}

func TestMergeConfigsDNSOverride(t *testing.T) {
	def := LoadDefaultConfig()
	sub := &ClashConfig{DNS: &DNSConfig{
		Enable:       false,
		EnhancedMode: "redir-host",
		Nameserver:   []string{"114.114.114.114"},
	}}
	got := MergeConfigs(def, sub)
	if got.DNS.Enable || got.DNS.EnhancedMode != "redir-host" || !reflect.DeepEqual(got.DNS.Nameserver, []string{"114.114.114.114"}) {
		t.Errorf("MergeConfigs() DNS override = %+v", got.DNS)
	}
	// The default config must not be mutated by the override.
	if def.DNS.EnhancedMode != "fake-ip" {
		t.Errorf("default DNS mutated by subscription override: %+v", def.DNS)
	}
}

func TestLoadDefaultConfig(t *testing.T) {
	cfg := LoadDefaultConfig()
	if cfg == nil {
		t.Fatal("LoadDefaultConfig() returned nil")
	}

	want := &ClashConfig{
		MixedPort:          7890,
		AllowLan:           true,
		BindAddress:        "*",
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		DNS: &DNSConfig{
			Enable:                true,
			IPv6:                  false,
			EnhancedMode:          "fake-ip",
			FakeIPRange:           "198.18.0.1/16",
			Nameserver:            []string{"223.5.5.5", "119.29.29.29"},
			ProxyServerNameserver: []string{"223.5.5.5", "119.29.29.29"},
		},
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

func TestParseAnyTLSURI(t *testing.T) {
	uri := "anytls://11111111-1111-1111-1111-111111111111@203.0.113.1:12345/?insecure=1&sni=example.com#!Example%20Node%20A"
	proxy, err := parseAnyTLSURI(uri)
	if err != nil {
		t.Fatalf("parseAnyTLSURI() error: %v", err)
	}
	want := &Proxy{
		Name:           "!Example Node A",
		Type:           "anytls",
		Server:         "203.0.113.1",
		Port:           12345,
		Password:       "11111111-1111-1111-1111-111111111111",
		UDP:            true,
		SkipCertVerify: true,
		Extra:          map[string]any{"sni": "example.com"},
	}
	if !reflect.DeepEqual(proxy, want) {
		t.Errorf("parseAnyTLSURI() = %+v\nwant %+v", proxy, want)
	}
}

func TestIsURIListWithAnyTLS(t *testing.T) {
	content := "anytls://11111111-1111-1111-1111-111111111111@203.0.113.1:12345/?insecure=1&sni=example.com#!Example%20Node%20A"
	if !IsURIList(content) {
		t.Errorf("IsURIList() = false, want true for anytls URI")
	}
}

func TestParseContentFiltersMetadataAndUnsupported(t *testing.T) {
	content := strings.Join([]string{
		"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:23456?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00000000#!剩余流量：53.18 GB",
		"anytls://11111111-1111-1111-1111-111111111111@203.0.113.1:12345/?insecure=1&sni=example.com#!Example%20Node%20A",
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNToxMTExMTExMS0xMTExLTExMTEtMTExMS0xMTExMTExMTExMTE=@198.51.100.1:34567#!Example%20Node%20B",
		"unknownscheme://foo@bar:1234#baz",
		"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:23456?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00000000#!Example%20Node%20C",
		"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:23456?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=00000000#香港测试节点",
	}, "\n")

	cfg, err := ParseContent(content)
	if err != nil {
		t.Fatalf("ParseContent() error: %v", err)
	}

	var names []string
	for _, p := range cfg.Proxies {
		names = append(names, p.Name)
	}
	// metadata junk line and unsupported scheme line must be skipped;
	// anytls + ss + vless nodes kept, including a Chinese-only-name node
	want := []string{"!Example Node A", "!Example Node B", "!Example Node C", "香港测试节点"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("ParseContent() proxy names = %v\nwant %v", names, want)
	}
}
