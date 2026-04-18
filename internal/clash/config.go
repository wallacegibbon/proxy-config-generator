package clash

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// IsURIList returns true if more than half of non-empty lines are proxy URIs.
func IsURIList(content string) bool {
	lines := strings.Split(content, "\n")
	total, uriCount := 0, 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		total++
		if IsProxyURI(line) {
			uriCount++
		}
	}
	return uriCount > 0 && uriCount >= total/2
}

// IsProxyURI returns true if the line starts with a known proxy URI scheme.
func IsProxyURI(line string) bool {
	for _, scheme := range proxySchemes {
		if strings.HasPrefix(line, scheme) {
			return true
		}
	}
	return false
}

// ParseURIList parses a list of proxy URI lines into a ClashConfig.
func ParseURIList(content string) (*ClashConfig, error) {
	cfg := &ClashConfig{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		proxy, err := parseProxyURI(line)
		if err != nil {
			os.Stderr.WriteString("Warning: failed to parse URI: " + err.Error() + "\n")
			continue
		}
		if proxy != nil {
			cfg.Proxies = append(cfg.Proxies, *proxy)
		}
	}
	return cfg, nil
}

// ParseContent detects the content format (Clash YAML or URI list) and parses it.
func ParseContent(content string) (*ClashConfig, error) {
	trimmed := strings.TrimSpace(content)
	if IsURIList(trimmed) {
		os.Stderr.WriteString("Detected URI list format, parsing proxy URIs...\n")
		return ParseURIList(trimmed)
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
