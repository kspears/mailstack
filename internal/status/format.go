// Package status evaluates the checks behind the admin status page.
package status

import (
	"fmt"
	"math"
	"time"
	_ "time/tzdata"
)

var zone = func() *time.Location {
	loc, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		panic(err)
	}
	return loc
}()

// Age formats a duration as whole seconds, minutes, hours or days.
func Age(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", max(int64(d/time.Second), 0))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int64(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int64(d/time.Hour))
	}
	return fmt.Sprintf("%d days", int64(d/(24*time.Hour)))
}

// Size formats a byte count in binary units with one decimal.
func Size(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB"}
	v := float64(n) / 1024
	i := 0
	for i < len(units)-1 && math.Round(v*10)/10 >= 1024 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// Stamp formats t in Pacific time.
func Stamp(t time.Time) string {
	return t.In(zone).Format("2006-01-02 15:04 MST")
}
