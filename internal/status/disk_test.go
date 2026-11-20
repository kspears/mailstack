package status

import (
	"path/filepath"
	"testing"
)

func TestReadDisk(t *testing.T) {
	dir := t.TempDir()
	for name, path := range map[string]string{
		"existing": dir,
		"missing":  filepath.Join(dir, "no", "such", "dir"),
	} {
		d, err := ReadDisk(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d.Total == 0 {
			t.Errorf("%s: Total = 0", name)
		}
	}
	a, _ := ReadDisk(dir)
	b, _ := ReadDisk(filepath.Join(dir, "missing"))
	if a.Dev != b.Dev {
		t.Errorf("walk-up Dev = %d, want %d", b.Dev, a.Dev)
	}
}

func TestPercent(t *testing.T) {
	tests := []struct {
		d    Disk
		want float64
	}{
		{Disk{}, 0},
		{Disk{Used: 1, Avail: 3}, 25},
		{Disk{Used: 5}, 100},
	}
	for _, tt := range tests {
		if got := tt.d.Percent(); got != tt.want {
			t.Errorf("%+v: %v, want %v", tt.d, got, tt.want)
		}
	}
}
