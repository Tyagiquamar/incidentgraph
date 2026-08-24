package observability

import (
	"crypto/rand"
	"encoding/hex"
)

// NewTraceID returns a 16-hex-char trace id.
func NewTraceID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
