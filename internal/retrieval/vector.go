package retrieval

import (
	"strconv"
	"strings"
)

// VectorLiteral formats a float32 slice as pgvector's text literal "[a,b,c]".
// Passed to Postgres as `$1::vector`. This avoids requiring a registered pgx
// codec and keeps the vector path dependency-light.
func VectorLiteral(v []float32) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, x := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatFloat(float64(x), 'g', -1, 32))
	}
	b.WriteByte(']')
	return b.String()
}
