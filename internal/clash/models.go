package clash

// ClashConfig represents a top-level mihomo configuration.
type ClashConfig struct {
	Port               int                     `yaml:"port"`
	SocksPort          int                     `yaml:"socks-port"`
	RedirPort          int                     `yaml:"redir-port"`
	MixedPort          int                     `yaml:"mixed-port"`
	AllowLan           bool                    `yaml:"allow-lan"`
	BindAddress        string                  `yaml:"bind-address"`
	Mode               string                  `yaml:"mode"`
	LogLevel           string                  `yaml:"log-level"`
	ExternalController string                  `yaml:"external-controller"`
	TCPConcurrent      bool                    `yaml:"tcp-concurrent"`
	UnifiedDelay       bool                    `yaml:"unified-delay"`
	Proxies            []Proxy                 `yaml:"proxies"`
	ProxyGroups        []ProxyGroup            `yaml:"proxy-groups"`
	Rules              []string                `yaml:"rules"`
	RuleProviders      map[string]RuleProvider `yaml:"rule-providers"`
	DNS                DNSConfig               `yaml:"dns"`
}

// Proxy represents an individual proxy server configuration.
// Protocol-specific fields not explicitly defined are stored in Extra
// and serialized inline in YAML output.
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

// DNSConfig represents the DNS configuration section.
type DNSConfig struct {
	DefaultNameservers    []string `yaml:"default-nameserver"`
	DirectNameservers     []string `yaml:"direct-nameserver"`
	Enable                bool     `yaml:"enable"`
	EnhancedMode          string   `yaml:"enhanced-mode"`
	FakeIPRange           string   `yaml:"fake-ip-range"`
	IPv6                  bool     `yaml:"ipv6"`
	ProxyServerNameserver []string `yaml:"proxy-server-nameserver"`
	UseHosts              bool     `yaml:"use-hosts"`
}
