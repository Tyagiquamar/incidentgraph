package bootstrap

import (
	"encoding/json"
	"os"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func osGetenv(k string) string          { return os.Getenv(k) }
