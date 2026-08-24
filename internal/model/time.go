package model

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// TimeStamp is a RFC3339 timestamp that scans from Postgres timestamptz and
// marshals as RFC3339 in JSON.
type TimeStamp struct{ time.Time }

func Now() TimeStamp { return TimeStamp{time.Now().UTC()} }

func (t TimeStamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Time.UTC().Format(time.RFC3339Nano))
}

func (t *TimeStamp) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}

func (t *TimeStamp) Scan(v any) error {
	switch x := v.(type) {
	case time.Time:
		t.Time = x
		return nil
	case nil:
		t.Time = time.Time{}
		return nil
	default:
		return fmt.Errorf("timestamp: unsupported scan type %T", v)
	}
}

func (t TimeStamp) Value() (driver.Value, error) { return t.Time, nil }
