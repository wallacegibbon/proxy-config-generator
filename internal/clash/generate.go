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
		"DOMAIN-KEYWORD,falun,REJECT",
		"DOMAIN-KEYWORD,minghui,REJECT",
		"DOMAIN-SUFFIX,falunaz.net,REJECT",
		"DOMAIN-SUFFIX,wujieliulan.com,REJECT",
		"DOMAIN-SUFFIX,mhradio.org,REJECT",
		"DOMAIN-SUFFIX,dongtaiwang.com,REJECT",
		"DOMAIN-SUFFIX,epochtimes.com,REJECT",
		"DOMAIN-SUFFIX,ntdtv.com,REJECT",
		"DOMAIN-KEYWORD,mtalk.google.com,Google谷歌应用",
		"DOMAIN-SUFFIX,services.googleapis.cn,DIRECT",
		"DOMAIN-REGEX,^r+[0-9]+(---|\\.)sn-(2x3|ni5|j5o)\\w{5}\\.xn--ngstr-lra8j\\.com$,DIRECT",
		"DOMAIN-SUFFIX,xn--ngstr-lra8j.com,Google谷歌应用",
		"DOMAIN-KEYWORD,google,Google谷歌应用",
		"DOMAIN-KEYWORD,gmail,Google谷歌应用",
		"DOMAIN-SUFFIX,youtube.com,Google谷歌应用",
		"DOMAIN-SUFFIX,youtu.be,Google谷歌应用",
		"DOMAIN-SUFFIX,gvt1.com,Google谷歌应用",
		"DOMAIN-SUFFIX,gvt2.com,Google谷歌应用",
		"DOMAIN-SUFFIX,chromium.org,Google谷歌应用",
		"DOMAIN-SUFFIX,gstatic.com,Google谷歌应用",
		"DOMAIN-KEYWORD,discord,选择节点",
		"DOMAIN-KEYWORD,tron,选择节点",
		"DOMAIN-KEYWORD,token,选择节点",
		"DOMAIN-KEYWORD,intl,选择节点",
		"DOMAIN-KEYWORD,yysub,选择节点",
		"DOMAIN-KEYWORD,blogspot,选择节点",
		"DOMAIN-KEYWORD,whatsapp,选择节点",
		"DOMAIN-KEYWORD,linkedin,选择节点",
		"DOMAIN-SUFFIX,larksuite.com,选择节点",
		"DOMAIN-SUFFIX,okx.com,选择节点",
		"DOMAIN-SUFFIX,binance.com,选择节点",
		"DOMAIN-KEYWORD,amazon,选择节点",
		"DOMAIN-KEYWORD,github,选择节点",
		"DOMAIN-SUFFIX,git.io,选择节点",
		"DOMAIN-KEYWORD,facebook,选择节点",
		"DOMAIN-SUFFIX,fb.me,选择节点",
		"DOMAIN-SUFFIX,fbcdn.net,选择节点",
		"DOMAIN-KEYWORD,twitter,选择节点",
		"DOMAIN-KEYWORD,instagram,选择节点",
		"DOMAIN-KEYWORD,dropbox,选择节点",
		"DOMAIN-SUFFIX,twimg.com,选择节点",
		"DOMAIN-SUFFIX,alibabacloud.com,选择节点",
		"DOMAIN-SUFFIX,nodeseek.com,选择节点",
		"DOMAIN-SUFFIX,tiktokv.com,选择节点",
		"DOMAIN-SUFFIX,tiktokcdn.com,选择节点",
		"DOMAIN-SUFFIX,pexpay.com,选择节点",
		"DOMAIN-SUFFIX,token.im,选择节点",
		"DOMAIN-SUFFIX,changenow.io,选择节点",
		"DOMAIN-SUFFIX,ooklaserver.net,选择节点",
		"DOMAIN-KEYWORD,telegram,选择节点",
		"DOMAIN-SUFFIX,t.me,选择节点",
		"DOMAIN-SUFFIX,tdesktop.com,选择节点",
		"DOMAIN-SUFFIX,telegra.ph,选择节点",
		"DOMAIN-SUFFIX,telesco.pe,选择节点",
		"IP-CIDR,91.105.192.0/23,选择节点,no-resolve",
		"IP-CIDR,91.108.4.0/22,选择节点,no-resolve",
		"IP-CIDR,91.108.8.0/21,选择节点,no-resolve",
		"IP-CIDR,91.108.16.0/21,选择节点,no-resolve",
		"IP-CIDR,91.108.56.0/22,选择节点,no-resolve",
		"IP-CIDR,95.161.64.0/20,选择节点,no-resolve",
		"IP-CIDR,149.154.160.0/20,选择节点,no-resolve",
		"IP-CIDR6,185.76.151.0/24,选择节点,no-resolve",
		"IP-CIDR6,2001:67c:4e8::/48,选择节点,no-resolve",
		"IP-CIDR6,2001:b28:f23c::/47,选择节点,no-resolve",
		"IP-CIDR6,2001:b28:f23f::/48,选择节点,no-resolve",
		"IP-CIDR6,2a0a:f280::/32,选择节点,no-resolve",
		"DOMAIN-SUFFIX,cn.bing.com,DIRECT",
		"DOMAIN-SUFFIX,bing.com,选择节点",
		"DOMAIN-SUFFIX,bingapis.com,选择节点",
		"DOMAIN-SUFFIX,azure.cn,DIRECT",
		"DOMAIN-SUFFIX,copilot.microsoft.com,选择节点",
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
		"DOMAIN-SUFFIX,openai.com,ChatGPT",
		"DOMAIN-SUFFIX,chatgpt.com,ChatGPT",
		"DOMAIN-KEYWORD,paypal,PayPal",
		"DOMAIN-SUFFIX,steamserver.net,DIRECT",
		"DOMAIN-SUFFIX,steamcdn-a.akamaihd.net,DIRECT",
		"DOMAIN-SUFFIX,cm.steampowered.com,DIRECT",
		"DOMAIN-SUFFIX,steam.clngaa.com,DIRECT",
		"DOMAIN,cn.download.nvidia.com,DIRECT",
		"DOMAIN-KEYWORD,steam,海外游戏平台",
		"DOMAIN-SUFFIX,cloudsync-prod.s3.amazonaws.com,海外游戏平台",
		"DOMAIN-SUFFIX,eaasserts-a.akamaihd.net,海外游戏平台",
		"DOMAIN-SUFFIX,origin-a.akamaihd.net,海外游戏平台",
		"DOMAIN-SUFFIX,originasserts.akamaized.net,海外游戏平台",
		"DOMAIN-SUFFIX,rtm.tnt-ea.com,海外游戏平台",
		"DOMAIN-SUFFIX,origin.com,海外游戏平台",
		"DOMAIN-SUFFIX,ea.com,海外游戏平台",
		"DOMAIN-SUFFIX,gamepass.com,海外游戏平台",
		"DOMAIN-KEYWORD,xbox,海外游戏平台",
		"DOMAIN-SUFFIX,helpshift.com,海外游戏平台",
		"DOMAIN-SUFFIX,paragon.com,海外游戏平台",
		"DOMAIN-SUFFIX,unrealengine.com,海外游戏平台",
		"DOMAIN-SUFFIX,epicgames.com,海外游戏平台",
		"DOMAIN-SUFFIX,epicgames.dev,海外游戏平台",
		"DOMAIN-KEYWORD,bili,Bilibili哔哩哔哩",
		"DOMAIN-SUFFIX,xtls.space,主站加速",
		"DOMAIN-KEYWORD,gov.,DIRECT,no-resolve",
		"DOMAIN-KEYWORD,.cn,DIRECT,no-resolve",
		"DOMAIN,cdn.staticfile.net,DIRECT",
		"DOMAIN-SUFFIX,pttime.org,DIRECT",
		"DOMAIN-SUFFIX,bfv.zth.ink,DIRECT",
		"RULE-SET,reject,广告屏蔽",
		"RULE-SET,gfw,选择节点",
		"RULE-SET,direct,DIRECT",
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
		"MATCH,选择节点",
	}
}

// BuildDefaultProxyGroups builds proxy-groups from a list of proxy names.
// The groups follow the pattern from the sample config.
func BuildDefaultProxyGroups(proxyNames []string) []ProxyGroup {
	allProxies := make([]string, len(proxyNames))
	copy(allProxies, proxyNames)

	return []ProxyGroup{
		{
			Name:    "选择节点",
			Type:    "select",
			Proxies: append([]string{"自动选择"}, allProxies...),
		},
		{
			Name:     "自动选择",
			Type:     "url-test",
			Proxies:  allProxies,
			URL:      "https://www.gstatic.com/generate_204",
			Interval: 30,
		},
		{
			Name:    "Google谷歌应用",
			Type:    "select",
			Proxies: append([]string{"选择节点"}, allProxies...),
		},
		{
			Name:    "ChatGPT",
			Type:    "select",
			Proxies: append([]string{"选择节点"}, allProxies...),
		},
		{
			Name:    "PayPal",
			Type:    "select",
			Proxies: append([]string{"选择节点"}, allProxies...),
		},
		{
			Name:    "海外游戏平台",
			Type:    "select",
			Proxies: append([]string{"DIRECT", "选择节点"}, allProxies...),
		},
		{
			Name:    "Bilibili哔哩哔哩",
			Type:    "select",
			Proxies: append([]string{"DIRECT", "选择节点"}, allProxies...),
		},
		{
			Name:    "广告屏蔽",
			Type:    "select",
			Proxies: append([]string{"REJECT", "DIRECT"}, allProxies...),
		},
		{
			Name:     "主站加速",
			Type:     "url-test",
			Proxies:  allProxies,
			URL:      "https://xtls.space",
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
