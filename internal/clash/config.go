package clash

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// IsProxyURI returns true if the line starts with a known proxy URI scheme.
func IsProxyURI(line string) bool {
	for _, scheme := range proxySchemes {
		if strings.HasPrefix(line, scheme) {
			return true
		}
	}
	return false
}

// parseClashConfig unmarshals a Clash YAML string into a ClashConfig.
func parseClashConfig(content string) (*ClashConfig, error) {
	var cfg ClashConfig
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
