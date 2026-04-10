package clash

import (
	"reflect"
	"testing"
)

func TestDecodeBase64(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"valid base64", "SGVsbG8gV29ybGQ=", "Hello World", false},
		{"base64 with newlines", "SGVsbG8g\nV29ybGQ=", "Hello World", false},
		{"base64 with spaces", "SGVsbG8g V29ybGQ=", "Hello World", false},
		{"base64 with tabs and newlines", "SGVsbG8g\tV29ybGQ=\n", "Hello World", false},
		{"UTF-8 BOM prefix", "\xEF\xBB\xBFSGVsbG8gV29ybGQ=", "Hello World", false},
		{"data URL prefix", "data:application/octet-stream;base64,SGVsbG8gV29ybGQ=", "Hello World", false},
		{"base64, prefix", "base64,SGVsbG8gV29ybGQ=", "Hello World", false},
		{"URL-safe encoding", "SGVsbG8gV29ybGQ", "Hello World", false},
		{"invalid base64", "Not base64!", "", true},
		{"empty string", "", "", false},
		{"whitespace only", "   \n\t\r  ", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeBase64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DecodeBase64() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
	cfg, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("LoadDefaultConfig() error = %v", err)
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
