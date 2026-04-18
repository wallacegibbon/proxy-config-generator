package clash

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// LoadDefaultConfig returns the hardcoded default mihomo configuration.
// This includes ports, DNS settings, proxy-groups template, rules, and rule-providers.
func LoadDefaultConfig() (*ClashConfig, error) {
	return &ClashConfig{
		Port:               7890,
		SocksPort:          7891,
		RedirPort:          7892,
		MixedPort:          0,
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
// Only PROXY, DIRECT, and REJECT are used as targets.
func BuildDefaultRules() []string {
	return []string{
		// --- Reject ---
		"DOMAIN-KEYWORD,falun,REJECT",
		"DOMAIN-KEYWORD,minghui,REJECT",
		"DOMAIN-SUFFIX,falunaz.net,REJECT",
		"DOMAIN-SUFFIX,wujieliulan.com,REJECT",
		"DOMAIN-SUFFIX,mhradio.org,REJECT",
		"DOMAIN-SUFFIX,dongtaiwang.com,REJECT",
		"DOMAIN-SUFFIX,epochtimes.com,REJECT",
		"DOMAIN-SUFFIX,ntdtv.com,REJECT",

		// --- Proxy ---
		"DOMAIN-SUFFIX,openai.com,PROXY",
		"DOMAIN-SUFFIX,chatgpt.com,PROXY",
		"DOMAIN-SUFFIX,oaistatic.com,PROXY",
		"DOMAIN-SUFFIX,oaiusercontent.com,PROXY",
		"DOMAIN-SUFFIX,bing.com,PROXY",
		"DOMAIN-SUFFIX,bingapis.com,PROXY",
		"DOMAIN-SUFFIX,copilot.microsoft.com,PROXY",
		"DOMAIN-SUFFIX,claude.ai,PROXY",
		"DOMAIN-SUFFIX,anthropic.com,PROXY",
		"DOMAIN-SUFFIX,perplexity.ai,PROXY",
		"DOMAIN-SUFFIX,amazon.com,PROXY",
		"DOMAIN-SUFFIX,amazonaws.com,PROXY",
		"DOMAIN-SUFFIX,netflix.com,PROXY",
		"DOMAIN-SUFFIX,nflximg.com,PROXY",
		"DOMAIN-SUFFIX,nflximg.net,PROXY",
		"DOMAIN-SUFFIX,nflxvideo.net,PROXY",
		"DOMAIN-SUFFIX,nflxso.net,PROXY",
		"DOMAIN-SUFFIX,nflxext.com,PROXY",
		"DOMAIN-SUFFIX,github.com,PROXY",
		"DOMAIN-SUFFIX,githubusercontent.com,PROXY",
		"DOMAIN-SUFFIX,git.io,PROXY",
		"DOMAIN-KEYWORD,mtalk.google.com,PROXY",
		"DOMAIN-SUFFIX,xn--ngstr-lra8j.com,PROXY",
		"DOMAIN-KEYWORD,google,PROXY",
		"DOMAIN-KEYWORD,gmail,PROXY",
		"DOMAIN-SUFFIX,youtube.com,PROXY",
		"DOMAIN-SUFFIX,youtu.be,PROXY",
		"DOMAIN-SUFFIX,gvt1.com,PROXY",
		"DOMAIN-SUFFIX,gvt2.com,PROXY",
		"DOMAIN-SUFFIX,chromium.org,PROXY",
		"DOMAIN-SUFFIX,gstatic.com,PROXY",
		"DOMAIN-KEYWORD,discord,PROXY",
		"DOMAIN-KEYWORD,whatsapp,PROXY",
		"DOMAIN-KEYWORD,linkedin,PROXY",
		"DOMAIN-KEYWORD,facebook,PROXY",
		"DOMAIN-KEYWORD,twitter,PROXY",
		"DOMAIN-KEYWORD,instagram,PROXY",
		"DOMAIN-KEYWORD,telegram,PROXY",
		"DOMAIN-KEYWORD,blogspot,PROXY",
		"DOMAIN-SUFFIX,fb.me,PROXY",
		"DOMAIN-SUFFIX,fbcdn.net,PROXY",
		"DOMAIN-SUFFIX,twimg.com,PROXY",
		"DOMAIN-SUFFIX,t.me,PROXY",
		"DOMAIN-SUFFIX,tdesktop.com,PROXY",
		"DOMAIN-SUFFIX,telegra.ph,PROXY",
		"DOMAIN-SUFFIX,telesco.pe,PROXY",
		"DOMAIN-SUFFIX,dropbox.com,PROXY",
		"DOMAIN-SUFFIX,okx.com,PROXY",
		"DOMAIN-SUFFIX,binance.com,PROXY",
		"DOMAIN-SUFFIX,nodeseek.com,PROXY",
		"DOMAIN-SUFFIX,larksuite.com,PROXY",
		"DOMAIN-KEYWORD,steam,PROXY",

		// Telegram IPs
		"IP-CIDR,91.105.192.0/23,PROXY,no-resolve",
		"IP-CIDR,91.108.4.0/22,PROXY,no-resolve",
		"IP-CIDR,91.108.8.0/21,PROXY,no-resolve",
		"IP-CIDR,91.108.16.0/21,PROXY,no-resolve",
		"IP-CIDR,91.108.56.0/22,PROXY,no-resolve",
		"IP-CIDR,95.161.64.0/20,PROXY,no-resolve",
		"IP-CIDR,149.154.160.0/20,PROXY,no-resolve",
		"IP-CIDR6,185.76.151.0/24,PROXY,no-resolve",
		"IP-CIDR6,2001:67c:4e8::/48,PROXY,no-resolve",
		"IP-CIDR6,2001:b28:f23c::/47,PROXY,no-resolve",
		"IP-CIDR6,2001:b28:f23f::/48,PROXY,no-resolve",
		"IP-CIDR6,2a0a:f280::/32,PROXY,no-resolve",

		// --- Direct ---
		"DOMAIN-SUFFIX,services.googleapis.cn,DIRECT",
		"DOMAIN-SUFFIX,cn.bing.com,DIRECT",
		"DOMAIN-SUFFIX,azure.cn,DIRECT",
		"DOMAIN-SUFFIX,microsoft.com,DIRECT",
		"DOMAIN-SUFFIX,windows.net,DIRECT",
		"DOMAIN-SUFFIX,windowsupdate.com,DIRECT",
		"DOMAIN-SUFFIX,mzstatic.com,DIRECT",
		"DOMAIN-SUFFIX,aaplimg.com,DIRECT",
		"DOMAIN-SUFFIX,me.com,DIRECT",
		"DOMAIN-KEYWORD,apple,DIRECT",
		"DOMAIN-KEYWORD,icloud,DIRECT",
		"DOMAIN-KEYWORD,mzstatic,DIRECT",
		"DOMAIN-KEYWORD,adobe,DIRECT",
		"DOMAIN-SUFFIX,steamserver.net,DIRECT",
		"DOMAIN-SUFFIX,steamcdn-a.akamaihd.net,DIRECT",
		"DOMAIN-SUFFIX,cm.steampowered.com,DIRECT",
		"DOMAIN-SUFFIX,steam.clngaa.com,DIRECT",
		"DOMAIN,cn.download.nvidia.com,DIRECT",
		"DOMAIN-KEYWORD,gov.,DIRECT,no-resolve",
		"DOMAIN-KEYWORD,.cn,DIRECT,no-resolve",
		"DOMAIN,cdn.staticfile.net,DIRECT",

		// --- Rule-sets ---
		"RULE-SET,reject,REJECT",
		"RULE-SET,gfw,PROXY",
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
		"MATCH,PROXY",
	}
}

// BuildDefaultProxyGroups builds proxy-groups from a list of proxy names.
func BuildDefaultProxyGroups(proxyNames []string) []ProxyGroup {
	return []ProxyGroup{
		{
			Name:     "PROXY",
			Type:     "url-test",
			Proxies:  proxyNames,
			URL:      "https://www.gstatic.com/generate_204",
			Interval: 30,
		},
	}
}

// GenerateConfig generates a complete mihomo config from parsed proxies.
// It applies all hardcoded defaults (ports, DNS, proxy-groups, rules, rule-providers).
func GenerateConfig(proxies []Proxy) (*ClashConfig, error) {
	defaultCfg, err := LoadDefaultConfig()
	if err != nil {
		return nil, fmt.Errorf("loading defaults: %w", err)
	}

	// Collect proxy names
	proxyNames := make([]string, 0, len(proxies))
	for _, p := range proxies {
		proxyNames = append(proxyNames, p.Name)
	}

	// Build the full config
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
