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

		// --- US-Only: services that require US/Non-CN nodes ---
		"DOMAIN-SUFFIX,openai.com,US-Only",
		"DOMAIN-SUFFIX,chatgpt.com,US-Only",
		"DOMAIN-SUFFIX,oaistatic.com,US-Only",
		"DOMAIN-SUFFIX,oaiusercontent.com,US-Only",
		"DOMAIN-SUFFIX,bing.com,US-Only",
		"DOMAIN-SUFFIX,bingapis.com,US-Only",
		"DOMAIN-SUFFIX,copilot.microsoft.com,US-Only",
		"DOMAIN-SUFFIX,paypal.com,US-Only",
		"DOMAIN-SUFFIX,paypal.me,US-Only",
		"DOMAIN-KEYWORD,paypal,US-Only",
		"DOMAIN-SUFFIX,claude.ai,US-Only",
		"DOMAIN-SUFFIX,anthropic.com,US-Only",
		"DOMAIN-SUFFIX,gemini.google.com,US-Only",
		"DOMAIN-SUFFIX,perplexity.ai,US-Only",
		"DOMAIN-SUFFIX,amazon.com,US-Only",
		"DOMAIN-SUFFIX,amazonaws.com,US-Only",
		"DOMAIN-SUFFIX,primevideo.com,US-Only",
		"DOMAIN-SUFFIX,hulu.com,US-Only",
		"DOMAIN-SUFFIX,hbomax.com,US-Only",
		"DOMAIN-SUFFIX,disneyplus.com,US-Only",
		"DOMAIN-SUFFIX,netflix.com,US-Only",
		"DOMAIN-SUFFIX,nflximg.com,US-Only",
		"DOMAIN-SUFFIX,nflximg.net,US-Only",
		"DOMAIN-SUFFIX,nflxvideo.net,US-Only",
		"DOMAIN-SUFFIX,nflxso.net,US-Only",
		"DOMAIN-SUFFIX,nflxext.com,US-Only",

		// --- CN-Only: services that require CN/HK/TW nodes ---
		"DOMAIN-KEYWORD,bili,CN-Only",
		"DOMAIN-SUFFIX,bilibili.com,CN-Only",
		"DOMAIN-SUFFIX,bilivideo.com,CN-Only",
		"DOMAIN-SUFFIX,biliapi.com,CN-Only",
		"DOMAIN-SUFFIX,acfun.cn,CN-Only",
		"DOMAIN-SUFFIX,iqiyi.com,CN-Only",
		"DOMAIN-SUFFIX,youku.com,CN-Only",
		"DOMAIN-SUFFIX,tencentvideo.com,CN-Only",
		"DOMAIN-SUFFIX,v.qq.com,CN-Only",
		"DOMAIN-SUFFIX,mgtv.com,CN-Only",
		"DOMAIN-SUFFIX,le.com,CN-Only",
		"DOMAIN-SUFFIX,163.com,CN-Only",
		"DOMAIN-SUFFIX,126.com,CN-Only",
		"DOMAIN-SUFFIX,music.163.com,CN-Only",
		"DOMAIN-SUFFIX,qq.com,CN-Only",
		"DOMAIN-SUFFIX,weibo.com,CN-Only",
		"DOMAIN-SUFFIX,zhihu.com,CN-Only",
		"DOMAIN-SUFFIX,douyin.com,CN-Only",
		"DOMAIN-SUFFIX,tiktokv.com,CN-Only",
		"DOMAIN-SUFFIX,tiktokcdn.com,CN-Only",

		// --- Google: Proxy ---
		"DOMAIN-KEYWORD,mtalk.google.com,Proxy",
		"DOMAIN-SUFFIX,services.googleapis.cn,DIRECT",
		"DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Proxy",
		"DOMAIN-KEYWORD,google,Proxy",
		"DOMAIN-KEYWORD,gmail,Proxy",
		"DOMAIN-SUFFIX,youtube.com,Proxy",
		"DOMAIN-SUFFIX,youtu.be,Proxy",
		"DOMAIN-SUFFIX,gvt1.com,Proxy",
		"DOMAIN-SUFFIX,gvt2.com,Proxy",
		"DOMAIN-SUFFIX,chromium.org,Proxy",
		"DOMAIN-SUFFIX,gstatic.com,Proxy",

		// --- General proxy: social, dev tools, etc. ---
		"DOMAIN-KEYWORD,discord,Proxy",
		"DOMAIN-KEYWORD,whatsapp,Proxy",
		"DOMAIN-KEYWORD,linkedin,Proxy",
		"DOMAIN-KEYWORD,facebook,Proxy",
		"DOMAIN-KEYWORD,twitter,Proxy",
		"DOMAIN-KEYWORD,instagram,Proxy",
		"DOMAIN-KEYWORD,telegram,Proxy",
		"DOMAIN-KEYWORD,blogspot,Proxy",
		"DOMAIN-SUFFIX,fb.me,Proxy",
		"DOMAIN-SUFFIX,fbcdn.net,Proxy",
		"DOMAIN-SUFFIX,twimg.com,Proxy",
		"DOMAIN-SUFFIX,t.me,Proxy",
		"DOMAIN-SUFFIX,tdesktop.com,Proxy",
		"DOMAIN-SUFFIX,telegra.ph,Proxy",
		"DOMAIN-SUFFIX,telesco.pe,Proxy",
		"DOMAIN-SUFFIX,github.com,Proxy",
		"DOMAIN-SUFFIX,githubusercontent.com,Proxy",
		"DOMAIN-SUFFIX,git.io,Proxy",
		"DOMAIN-SUFFIX,dropbox.com,Proxy",
		"DOMAIN-SUFFIX,okx.com,Proxy",
		"DOMAIN-SUFFIX,binance.com,Proxy",
		"DOMAIN-SUFFIX,nodeseek.com,Proxy",
		"DOMAIN-SUFFIX,larksuite.com,Proxy",

		// Telegram IPs
		"IP-CIDR,91.105.192.0/23,Proxy,no-resolve",
		"IP-CIDR,91.108.4.0/22,Proxy,no-resolve",
		"IP-CIDR,91.108.8.0/21,Proxy,no-resolve",
		"IP-CIDR,91.108.16.0/21,Proxy,no-resolve",
		"IP-CIDR,91.108.56.0/22,Proxy,no-resolve",
		"IP-CIDR,95.161.64.0/20,Proxy,no-resolve",
		"IP-CIDR,149.154.160.0/20,Proxy,no-resolve",
		"IP-CIDR6,185.76.151.0/24,Proxy,no-resolve",
		"IP-CIDR6,2001:67c:4e8::/48,Proxy,no-resolve",
		"IP-CIDR6,2001:b28:f23c::/47,Proxy,no-resolve",
		"IP-CIDR6,2001:b28:f23f::/48,Proxy,no-resolve",
		"IP-CIDR6,2a0a:f280::/32,Proxy,no-resolve",

		// --- Direct: Microsoft, Apple, Steam CN ---
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
		"DOMAIN-KEYWORD,steam,Proxy",
		"DOMAIN-KEYWORD,gov.,DIRECT,no-resolve",
		"DOMAIN-KEYWORD,.cn,DIRECT,no-resolve",
		"DOMAIN,cdn.staticfile.net,DIRECT",

		// --- Rule-sets ---
		"RULE-SET,reject,Reject",
		"RULE-SET,gfw,Proxy",
		"RULE-SET,direct,DIRECT",

		// --- Private IPs: Direct ---
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
		"MATCH,Proxy",
	}
}

// BuildDefaultProxyGroups builds proxy-groups from a list of proxy names.
// Groups: Proxy (auto fastest), US-Only (manual select for US-needed services),
// CN-Only (manual select for CN/HK/TW-needed services), Reject (ad blocking).
func BuildDefaultProxyGroups(proxyNames []string) []ProxyGroup {
	allProxies := make([]string, len(proxyNames))
	copy(allProxies, proxyNames)

	return []ProxyGroup{
		{
			Name:     "Proxy",
			Type:     "url-test",
			Proxies:  allProxies,
			URL:      "https://www.gstatic.com/generate_204",
			Interval: 30,
		},
		{
			Name:    "US-Only",
			Type:    "select",
			Proxies: append([]string{"Proxy"}, allProxies...),
		},
		{
			Name:    "CN-Only",
			Type:    "select",
			Proxies: append([]string{"Proxy"}, allProxies...),
		},
		{
			Name:    "Reject",
			Type:    "select",
			Proxies: []string{"REJECT", "DIRECT"},
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
