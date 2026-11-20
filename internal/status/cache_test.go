package status

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestCache(ttl time.Duration) (*Cache, *fakeClock, *atomic.Int64) {
	clock := &fakeClock{t: testNow}
	var scans atomic.Int64
	c := NewCache(ttl, clock.now, func(dir string) Mailbox {
		scans.Add(1)
		return Mailbox{Size: int64(len(dir))}
	})
	return c, clock, &scans
}

var threePaths = map[string]string{"a@x": "/a", "b@x": "/bb", "c@x": "/ccc"}

func TestCacheWithinTTL(t *testing.T) {
	c, clock, scans := newTestCache(time.Minute)
	c.Get(threePaths)
	clock.advance(59 * time.Second)
	c.Get(threePaths)
	if got := scans.Load(); got != 3 {
		t.Fatalf("scans = %d, want 3", got)
	}
}

func TestCacheExpires(t *testing.T) {
	c, clock, scans := newTestCache(time.Minute)
	c.Get(threePaths)
	clock.advance(time.Minute)
	_, at := c.Get(threePaths)
	if got := scans.Load(); got != 6 {
		t.Fatalf("scans = %d, want 6", got)
	}
	if !at.Equal(clock.now()) {
		t.Errorf("at = %v, want %v", at, clock.now())
	}
}

func TestCacheConcurrent(t *testing.T) {
	c, _, scans := newTestCache(time.Minute)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Get(threePaths)
		}()
	}
	wg.Wait()
	if got := scans.Load(); got != 3 {
		t.Fatalf("scans = %d, want 3", got)
	}
}

func TestCacheNewAddressScannedAlone(t *testing.T) {
	c, clock, scans := newTestCache(time.Minute)
	_, first := c.Get(map[string]string{"a@x": "/a"})
	clock.advance(30 * time.Second)
	got, at := c.Get(map[string]string{"a@x": "/a", "d@x": "/dddd"})
	if n := scans.Load(); n != 2 {
		t.Fatalf("scans = %d, want 2", n)
	}
	if !at.Equal(first) {
		t.Errorf("at moved to %v, want %v", at, first)
	}
	if got["d@x"].Size != 5 {
		t.Errorf("d@x = %+v", got["d@x"])
	}
}

func TestCacheReturnsOnlyRequested(t *testing.T) {
	c, _, _ := newTestCache(time.Minute)
	c.Get(threePaths)
	got, _ := c.Get(map[string]string{"b@x": "/bb"})
	if len(got) != 1 || got["b@x"].Size != 3 {
		t.Fatalf("got %+v", got)
	}
}
