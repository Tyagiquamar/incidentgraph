// Package observability provides structured JSON logging and trace context helpers.
package observability

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

var mu sync.Mutex
var minLevel = LevelInfo

func init() {
	if v := os.Getenv("IG_LOG_LEVEL"); v != "" {
		minLevel = Level(v)
	}
}

func severity(l Level) int {
	switch l {
	case LevelDebug:
		return 0
	case LevelInfo:
		return 1
	case LevelWarn:
		return 2
	default:
		return 3
	}
}

// F is a set of structured log fields.
type F map[string]any

// Logger emits one-JSON-object-per-line records to stdout.
type Logger struct {
	component string
	base      F
}

func New(component string) *Logger {
	return &Logger{component: component, base: F{}}
}

func (l *Logger) With(fields F) *Logger {
	nb := F{}
	for k, v := range l.base {
		nb[k] = v
	}
	for k, v := range fields {
		nb[k] = v
	}
	return &Logger{component: l.component, base: nb}
}

func (l *Logger) log(level Level, msg string, fields F) {
	if severity(level) < severity(minLevel) {
		return
	}
	rec := make(map[string]any, len(fields)+len(l.base)+4)
	for k, v := range l.base {
		rec[k] = v
	}
	for k, v := range fields {
		rec[k] = v
	}
	rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	rec["level"] = string(level)
	rec["component"] = l.component
	rec["msg"] = msg
	b, err := json.Marshal(rec)
	if err != nil {
		b = []byte(`{"level":"error","msg":"log marshal failure"}`)
	}
	mu.Lock()
	defer mu.Unlock()
	os.Stdout.Write(append(b, '\n'))
}

func (l *Logger) Debug(msg string, fields F) { l.log(LevelDebug, msg, fields) }
func (l *Logger) Info(msg string, fields F)  { l.log(LevelInfo, msg, fields) }
func (l *Logger) Warn(msg string, fields F)  { l.log(LevelWarn, msg, fields) }
func (l *Logger) Error(msg string, fields F) { l.log(LevelError, msg, fields) }
