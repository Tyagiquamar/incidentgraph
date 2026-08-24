package policy

import (
	"regexp"
	"strings"
)

var dollarTagRe = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*\$`)

// normalizeKeyword strips trailing punctuation from a keyword token.
func normalizeKeyword(t string) string {
	return strings.Trim(t, "();,")
}
