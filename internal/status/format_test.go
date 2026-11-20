package status

import (
	"testing"
	"time"
)

func TestAge(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{-time.Hour, "0 s"},
		{0, "0 s"},
		{59*time.Second + 900*time.Millisecond, "59 s"},
		{60 * time.Second, "1 min"},
		{59*time.Minute + 59*time.Second, "59 min"},
		{time.Hour, "1 h"},
		{47*time.Hour + 59*time.Minute, "47 h"},
		{48 * time.Hour, "2 days"},
		{100 * time.Hour, "4 days"},
	}
	for _, tt := range tests {
		if got := Age(tt.d); got != tt.want {
			t.Errorf("Age(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestSize(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1024*1024 - 1, "1.0 MiB"},
		{1024*1024 - 52, "1023.9 KiB"},
		{1024 * 1024, "1.0 MiB"},
		{5 * 1024 * 1024 * 1024 / 2, "2.5 GiB"},
		{1024*1024*1024 - 1, "1.0 GiB"},
		{2048 * 1024 * 1024 * 1024, "2.0 TiB"},
	}
	for _, tt := range tests {
		if got := Size(tt.n); got != tt.want {
			t.Errorf("Size(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestStamp(t *testing.T) {
	tests := []struct {
		in   time.Time
		want string
	}{
		{time.Date(2026, 7, 1, 19, 30, 0, 0, time.UTC), "2026-07-01 12:30 PDT"},
		{time.Date(2026, 12, 1, 19, 30, 0, 0, time.UTC), "2026-12-01 11:30 PST"},
	}
	for _, tt := range tests {
		if got := Stamp(tt.in); got != tt.want {
			t.Errorf("Stamp(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
