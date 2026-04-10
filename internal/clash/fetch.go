package clash

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const httpTimeout = 30 * time.Second

// FetchContent fetches the subscription URL with a generic User-Agent
// to retrieve the full proxy list.
func FetchContent(url string) (string, error) {
	resp, err := doGET(url, "ProxyConfigUpdater/1.0")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// FetchClashConfig fetches the subscription URL with a Clash-like User-Agent
// to retrieve the Clash YAML format (proxy-groups, rules, DNS config).
// Returns nil if the response is not valid Clash YAML.
func FetchClashConfig(subscriptionURL string) *ClashConfig {
	resp, err := doGET(subscriptionURL, "ClashSubscriptionParser/1.0")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	trimmed := strings.TrimSpace(string(body))
	if !looksLikeClashYAML(trimmed) {
		return nil
	}

	cfg, err := parseClashConfig(trimmed)
	if err != nil {
		return nil
	}
	return cfg
}

// looksLikeClashYAML returns true if the content appears to be a Clash YAML config.
func looksLikeClashYAML(content string) bool {
	if len(content) == 0 {
		return false
	}
	for _, prefix := range []string{
		"mixed-port:",
		"port:",
		"allow-lan:",
		"proxies:",
		"mode:",
	} {
		if strings.HasPrefix(content, prefix) {
			return true
		}
	}
	return false
}

// doGET performs an HTTP GET with the given URL and User-Agent.
func doGET(url, userAgent string) (*http.Response, error) {
	client := &http.Client{Timeout: httpTimeout}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	return client.Do(req)
}
