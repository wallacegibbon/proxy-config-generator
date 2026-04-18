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

func TestIsProxyURI(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"vless://uuid@host:443?type=tcp", true},
		{"tuic://uuid:pass@host:443?sni=x", true},
		{"hysteria2://pass@host:443?sni=x", true},
		{"vmess://base64data", true},
		{"trojan://pass@host:443", true},
		{"ss://method:pass@host:443", true},
		{"ssr://something", true},
		{"https://example.com/sub", false},
		{"not a proxy uri", false},
		{"", false},
	}

	for _, tt := range tests {
		got := IsProxyURI(tt.line)
		if got != tt.want {
			t.Errorf("IsProxyURI(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestLoadDefaultConfig(t *testing.T) {
	cfg, err := LoadDefaultConfig()
	if err != nil {
		t.Fatalf("LoadDefaultConfig() error = %v", err)
	}

	if cfg.Port != 7890 {
		t.Errorf("Port = %d, want 7890", cfg.Port)
	}
	if cfg.Mode != "rule" {
		t.Errorf("Mode = %s, want rule", cfg.Mode)
	}
	if !cfg.TCPConcurrent {
		t.Error("TCPConcurrent should be true")
	}
	if !cfg.UnifiedDelay {
		t.Error("UnifiedDelay should be true")
	}
	if !cfg.DNS.Enable {
		t.Error("DNS.Enable should be true")
	}
	if cfg.DNS.EnhancedMode != "fake-ip" {
		t.Errorf("DNS.EnhancedMode = %s, want fake-ip", cfg.DNS.EnhancedMode)
	}
	if len(cfg.RuleProviders) != 4 {
		t.Errorf("len(RuleProviders) = %d, want 4", len(cfg.RuleProviders))
	}
}

func TestBuildDefaultProxyGroups(t *testing.T) {
	proxyNames := []string{"proxy-a", "proxy-b", "proxy-c"}
	groups := BuildDefaultProxyGroups(proxyNames)

	if len(groups) != 4 {
		t.Fatalf("len(groups) = %d, want 4", len(groups))
	}

	// Check "Proxy" group (url-test auto-select)
	if groups[0].Name != "Proxy" {
		t.Errorf("groups[0].Name = %s, want Proxy", groups[0].Name)
	}
	if groups[0].Type != "url-test" {
		t.Errorf("groups[0].Type = %s, want url-test", groups[0].Type)
	}
	if groups[0].URL != "https://www.gstatic.com/generate_204" {
		t.Errorf("groups[0].URL = %s", groups[0].URL)
	}
	if groups[0].Interval != 30 {
		t.Errorf("groups[0].Interval = %d, want 30", groups[0].Interval)
	}
	if len(groups[0].Proxies) != 3 {
		t.Errorf("len(groups[0].Proxies) = %d, want 3", len(groups[0].Proxies))
	}

	// Check "US-Only" group
	if groups[1].Name != "US-Only" {
		t.Errorf("groups[1].Name = %s, want US-Only", groups[1].Name)
	}
	if groups[1].Type != "select" {
		t.Errorf("groups[1].Type = %s, want select", groups[1].Type)
	}
	if groups[1].Proxies[0] != "Proxy" {
		t.Errorf("groups[1].Proxies[0] = %s, want Proxy", groups[1].Proxies[0])
	}

	// Check "CN-Only" group
	if groups[2].Name != "CN-Only" {
		t.Errorf("groups[2].Name = %s, want CN-Only", groups[2].Name)
	}
	if groups[2].Type != "select" {
		t.Errorf("groups[2].Type = %s, want select", groups[2].Type)
	}
	if groups[2].Proxies[0] != "Proxy" {
		t.Errorf("groups[2].Proxies[0] = %s, want Proxy", groups[2].Proxies[0])
	}

	// Check "Reject" group
	if groups[3].Name != "Reject" {
		t.Errorf("groups[3].Name = %s, want Reject", groups[3].Name)
	}
	if !reflect.DeepEqual(groups[3].Proxies, []string{"REJECT", "DIRECT"}) {
		t.Errorf("groups[3].Proxies = %v", groups[3].Proxies)
	}
}

func TestBuildDefaultRules(t *testing.T) {
	rules := BuildDefaultRules()
	if len(rules) == 0 {
		t.Error("BuildDefaultRules() returned empty rules")
	}
	// Check first and last rules
	if rules[0] != "DOMAIN-KEYWORD,falun,REJECT" {
		t.Errorf("first rule = %s", rules[0])
	}
	if rules[len(rules)-1] != "MATCH,Proxy" {
		t.Errorf("last rule = %s", rules[len(rules)-1])
	}
}

func TestGenerateConfig(t *testing.T) {
	proxies := []Proxy{
		{Name: "test-proxy", Type: "vless", Server: "example.com", Port: 443, UUID: "test-uuid", UDP: true},
		{Name: "test-proxy2", Type: "tuic", Server: "example2.com", Port: 443, UUID: "test-uuid2", UDP: true},
	}

	cfg, err := GenerateConfig(proxies)
	if err != nil {
		t.Fatalf("GenerateConfig() error = %v", err)
	}

	if len(cfg.Proxies) != 2 {
		t.Errorf("len(Proxies) = %d, want 2", len(cfg.Proxies))
	}
	if len(cfg.ProxyGroups) != 4 {
		t.Errorf("len(ProxyGroups) = %d, want 4", len(cfg.ProxyGroups))
	}
	if len(cfg.Rules) == 0 {
		t.Error("Rules should not be empty")
	}
	if cfg.Port != 7890 {
		t.Errorf("Port = %d, want 7890", cfg.Port)
	}
}

func TestParseVlessURI(t *testing.T) {
	uri := "vless://test-uuid@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&fp=chrome&sni=www.example.com&pbk=test-pbk&sid=test-sid#TestProxy"
	proxy, err := ParseSingleURI(uri)
	if err != nil {
		t.Fatalf("ParseSingleURI() error = %v", err)
	}
	if proxy.Type != "vless" {
		t.Errorf("Type = %s, want vless", proxy.Type)
	}
	if proxy.Name != "TestProxy" {
		t.Errorf("Name = %s, want TestProxy", proxy.Name)
	}
	if proxy.UUID != "test-uuid" {
		t.Errorf("UUID = %s, want test-uuid", proxy.UUID)
	}
	if proxy.Port != 443 {
		t.Errorf("Port = %d, want 443", proxy.Port)
	}
}

func TestParseHysteria2URI(t *testing.T) {
	uri := "hysteria2://test-pass@example.com:443/?insecure=1&sni=cdn.example.com#HY2Proxy"
	proxy, err := ParseSingleURI(uri)
	if err != nil {
		t.Fatalf("ParseSingleURI() error = %v", err)
	}
	if proxy.Type != "hysteria2" {
		t.Errorf("Type = %s, want hysteria2", proxy.Type)
	}
	if proxy.Name != "HY2Proxy" {
		t.Errorf("Name = %s, want HY2Proxy", proxy.Name)
	}
	if !proxy.SkipCertVerify {
		t.Error("SkipCertVerify should be true")
	}
}

func TestParseTuicURI(t *testing.T) {
	uri := "tuic://test-uuid:test-pass@example.com:443?sni=cdn.example.com&alpn=h3&congestion_control=bbr&allow_insecure=1&udp_relay_mode=quic#TUICProxy"
	proxy, err := ParseSingleURI(uri)
	if err != nil {
		t.Fatalf("ParseSingleURI() error = %v", err)
	}
	if proxy.Type != "tuic" {
		t.Errorf("Type = %s, want tuic", proxy.Type)
	}
	if proxy.Password != "test-pass" {
		t.Errorf("Password = %s, want test-pass", proxy.Password)
	}
	if !proxy.SkipCertVerify {
		t.Error("SkipCertVerify should be true")
	}
}

func TestIsURIList(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			"mostly URIs",
			"vless://a@b:1\nvless://c@d:2\nvless://e@f:3",
			true,
		},
		{
			"mixed with some non-URIs",
			"vless://a@b:1\nvless://c@d:2\nnot a uri",
			true,
		},
		{
			"no URIs",
			"hello\nworld\nfoo",
			false,
		},
		{
			"empty",
			"",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsURIList(tt.content)
			if got != tt.want {
				t.Errorf("IsURIList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergeConfigsRemoved(t *testing.T) {
	// The old MergeConfigs function used reflection and is now removed.
	// GenerateConfig replaces it. Verify GenerateConfig produces correct output.
	proxies := []Proxy{
		{Name: "p1", Type: "vless", Server: "s1", Port: 443},
	}

	cfg, err := GenerateConfig(proxies)
	if err != nil {
		t.Fatalf("GenerateConfig() error = %v", err)
	}

	// Verify it has all expected sections
	if cfg.Port != 7890 {
		t.Errorf("Port = %d", cfg.Port)
	}
	if len(cfg.Proxies) != 1 {
		t.Errorf("Proxies = %d", len(cfg.Proxies))
	}
	if len(cfg.ProxyGroups) == 0 {
		t.Error("ProxyGroups empty")
	}
	if len(cfg.Rules) == 0 {
		t.Error("Rules empty")
	}
	if len(cfg.RuleProviders) == 0 {
		t.Error("RuleProviders empty")
	}
	if !reflect.DeepEqual(cfg.DNS.DefaultNameservers, []string{"223.5.5.5", "119.29.29.29", "[2400:3200::1]:53", "[240C::6666]:53", "system"}) {
		t.Errorf("DNS.DefaultNameservers = %v", cfg.DNS.DefaultNameservers)
	}
}
