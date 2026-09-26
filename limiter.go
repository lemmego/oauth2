package oauth2

import (
	"container/list"
	"sync"
	"time"
)

// Limiter caps how often an identity may attempt something.
//
// The device verification page needs one: a user code carries about 35 bits,
// and RFC 8628 section 5.1 requires rate limiting because nothing else stops
// a machine from working through them. The token endpoint wants one too,
// being unauthenticated and cheap to call.
//
// The interface lives here rather than in the framework so this package's
// correctness never waits on a framework release, and because the device
// flow's slow_down behaviour is protocol state rather than generic limiting.
type Limiter interface {
	// Allow reports whether an attempt may proceed, and how long to wait if
	// not.
	Allow(ctx Context, key string, limit int, window time.Duration) (bool, time.Duration)
}

// MemoryLimiter is a fixed-window counter held in this process.
//
// It works with no configuration, which is what makes the server safe out of
// the box. It counts per process, so a deployment running several instances
// gets its limit multiplied by the instance count — a limiter backed by a
// shared cache is the answer there, and WithLimiter takes one.
//
// The entry count is bounded so the limiter cannot itself become a
// memory-exhaustion vector: the keys are attacker-influenced (an IP, a
// client id), so an unbounded map would be the vulnerability it exists to
// prevent.
type MemoryLimiter struct {
	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List
	max     int
	clock   func() time.Time
}

type limiterEntry struct {
	key       string
	count     int
	windowEnd time.Time
}

// NewMemoryLimiter returns a limiter holding at most 10,000 keys.
func NewMemoryLimiter() *MemoryLimiter { return NewMemoryLimiterWithSize(10000) }

// NewMemoryLimiterWithSize returns a limiter holding at most max keys,
// evicting the least recently used.
func NewMemoryLimiterWithSize(max int) *MemoryLimiter {
	if max <= 0 {
		max = 10000
	}
	return &MemoryLimiter{
		entries: make(map[string]*list.Element, max),
		order:   list.New(),
		max:     max,
		clock:   time.Now,
	}
}

func (l *MemoryLimiter) Allow(_ Context, key string, limit int, window time.Duration) (bool, time.Duration) {
	if limit <= 0 || window <= 0 {
		return true, 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	if element, ok := l.entries[key]; ok {
		entry := element.Value.(*limiterEntry)
		if now.Before(entry.windowEnd) {
			l.order.MoveToFront(element)
			if entry.count >= limit {
				return false, entry.windowEnd.Sub(now)
			}
			entry.count++
			return true, 0
		}
		// The window has passed; start a new one in place.
		entry.count = 1
		entry.windowEnd = now.Add(window)
		l.order.MoveToFront(element)
		return true, 0
	}

	// Evicting the least recently used key is a deliberate trade: an
	// attacker who floods the limiter with distinct keys can push a real
	// counter out, but the alternative — growing without bound on
	// attacker-supplied keys — is worse.
	for l.order.Len() >= l.max {
		oldest := l.order.Back()
		if oldest == nil {
			break
		}
		l.order.Remove(oldest)
		delete(l.entries, oldest.Value.(*limiterEntry).key)
	}

	l.entries[key] = l.order.PushFront(&limiterEntry{
		key:       key,
		count:     1,
		windowEnd: now.Add(window),
	})
	return true, 0
}

// Len reports how many keys are being tracked.
func (l *MemoryLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

// unlimited allows everything, for a caller that has turned limiting off.
type unlimited struct{}

func (unlimited) Allow(Context, string, int, time.Duration) (bool, time.Duration) {
	return true, 0
}

// Unlimited returns a limiter that never refuses. It exists so turning
// limiting off is explicit rather than a nil check scattered through the
// grants.
func Unlimited() Limiter { return unlimited{} }
