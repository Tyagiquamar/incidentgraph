package security

import (
	"encoding/json"
	"strings"
)

func parseJSON(b []byte, v any) error   { return json.Unmarshal(b, v) }
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }

func sensitiveKey(k string) bool {
	ku := strings.ToUpper(k)
	for _, marker := range []string{"PASSWORD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "CREDENTIAL", "AUTHORIZATION"} {
		if strings.Contains(ku, marker) {
			return true
		}
	}
	return false
}

func redactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if sensitiveKey(k) {
				x[k] = redactedPlaceholder
				continue
			}
			x[k] = redactValue(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactValue(x[i])
		}
		return x
	case string:
		return Redact(x)
	default:
		return v
	}
}
