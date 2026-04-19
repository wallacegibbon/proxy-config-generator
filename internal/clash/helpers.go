package clash

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
)

// base64DecodeCompat tries multiple base64 encodings to decode a string.
// Used by vmess and ss URI parsers which embed base64 in the URI itself.
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
	return "", base64.CorruptInputError(0)
}

// decodeFragment URL-decodes the fragment (after #) of a URI, which may be percent-encoded.
func decodeFragment(fragment string) string {
	decoded, err := url.PathUnescape(fragment)
	if err != nil {
		return fragment
	}
	return decoded
}

// setExtra sets a key-value pair in a proxy's Extra map, creating it if nil.
func setExtra(extra map[string]any, key string, value any) map[string]any {
	if extra == nil {
		extra = make(map[string]any)
	}
	extra[key] = value
	return extra
}

// stringFromMap safely extracts a string value from a map[string]any.
func stringFromMap(m map[string]any, key string) string {
	if val, ok := m[key]; ok {
		if s, ok := val.(string); ok {
			return s
		}
	}
	return ""
}

// intFromMap extracts an int value from a map[string]any (handles float64 and string).
func intFromMap(m map[string]any, key string) int {
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case float64:
			return int(v)
		case string:
			n, _ := strconv.Atoi(v)
			return n
		}
	}
	return 0
}
