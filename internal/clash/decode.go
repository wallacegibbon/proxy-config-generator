package clash

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

// DecodeBase64 decodes a string that may be base64 encoded.
func DecodeBase64(encoded string) (string, error) {
	data := []byte(encoded)
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		data = data[3:]
	}

	s := string(data)

	for _, prefix := range []string{
		"data:application/octet-stream;base64,",
		"data:text/plain;base64,",
		"data:application/x-yaml;base64,",
		"data:;base64,",
		"base64,",
	} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}

	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(cleaned); err == nil {
			return string(decoded), nil
		}
	}

	return "", fmt.Errorf("failed to decode base64 content")
}

// base64DecodeCompat tries multiple base64 encodings to decode a string.
func base64DecodeCompat(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if decoded, err := enc.DecodeString(s); err == nil {
			return string(decoded), nil
		}
	}
	return "", fmt.Errorf("failed to decode base64: %s", s)
}
