package retrieval

import (
	"regexp"
	"strings"
)

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func mergeMeta(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		if v != nil && v != "" {
			out[k] = v
		}
	}
	return out
}

// NormalizeText strips NULs and normalizes newlines before chunking/embedding.
var crlfRe = regexp.MustCompile(`\r\n?`)

func NormalizeText(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return crlfRe.ReplaceAllString(s, "\n")
}
