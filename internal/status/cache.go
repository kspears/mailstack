package status

import (
	"sync"
	"time"
)

// Cache keeps mailbox scans for ttl so reloading the page does not walk every
// maildir each time.
type Cache struct {
	mu    sync.Mutex
	at    time.Time
	boxes map[string]Mailbox
	ttl   time.Duration
	now   func() time.Time
	scan  func(dir string) Mailbox
}

func NewCache(ttl time.Duration, now func() time.Time, scan func(dir string) Mailbox) *Cache {
	return &Cache{ttl: ttl, now: now, scan: scan}
}

// Get returns the scans for paths (address to directory) and the time of the
// last full scan. Callers wait while a scan runs, so a scan happens once.
func (c *Cache) Get(paths map[string]string) (map[string]Mailbox, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := c.now(); c.boxes == nil || now.Sub(c.at) >= c.ttl {
		c.boxes = make(map[string]Mailbox, len(paths))
		for addr, dir := range paths {
			c.boxes[addr] = c.scan(dir)
		}
		c.at = now
	}
	out := make(map[string]Mailbox, len(paths))
	for addr, dir := range paths {
		box, ok := c.boxes[addr]
		if !ok {
			box = c.scan(dir)
			c.boxes[addr] = box
		}
		out[addr] = box
	}
	return out, c.at
}
