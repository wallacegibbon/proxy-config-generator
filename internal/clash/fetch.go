package clash

import (
	"fmt"
	"io"
	"net/http"
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
