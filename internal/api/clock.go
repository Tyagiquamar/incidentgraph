package api

import (
	"time"
)

func startClock() time.Time { return time.Now() }

func sinceMS(t time.Time) int64 { return time.Since(t).Milliseconds() }
