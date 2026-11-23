// Package xray runs the second protocol: VLESS over REALITY, served by the
// Xray-core binary.
//
// There are two dataplanes in this server and they are deliberately different
// in kind. WireGuard is a device that the kernel or an embedded userspace
// implementation terminates, and a peer exists while it is in the interface.
// Xray is a process this server starts, and a user exists while the process is
// told about it. That difference is why this package exists: it owns the
// process, the configuration file, the runtime API that adds and removes users,
// and the counters that are the only thing the two have in common.
package xray

import (
	"fmt"
	"sync"
	"time"
)

// Traffic is one user's counters, as the server last read them. They are
// cumulative for the life of the process, not for the life of a device.
type Traffic struct {
	Uplink   int64
	Downlink int64
}

// User is one client of the VLESS inbound. The id is the device's VLESS id,
// which is also the address the counters are keyed by.
type User struct {
	ID string
}

// Dataplane is what the rest of the server needs from the second protocol: a
// user per device, counters per user, and a way to say whether it is alive.
//
// A no-op implementation is what a server with VLESS disabled runs, so the
// device manager never has to ask whether the feature is on.
type Dataplane interface {
	// Upsert makes sure the user exists. It is idempotent: calling it for a
	// user that is already there changes nothing.
	Upsert(id string) error
	// Remove deletes the user. Removing one that is not there is not an
	// error, for the same reason as in the WireGuard dataplane: the caller
	// applies a state, it does not describe a transition.
	Remove(id string) error
	// Stats returns the counters of every user the process knows, keyed by
	// the user id.
	Stats() (map[string]Traffic, error)
	// Ping reports whether the process answers.
	Ping() error
}

// disabled is the dataplane of a server that does not serve VLESS.
type disabled struct{}

// NewDisabled returns a dataplane that does nothing and is always alive.
func NewDisabled() Dataplane {
	return disabled{}
}

func (disabled) Upsert(string) error { return nil }
func (disabled) Remove(string) error { return nil }
func (disabled) Stats() (map[string]Traffic, error) {
	return map[string]Traffic{}, nil
}
func (disabled) Ping() error { return nil }

// backoff is how long the supervisor waits before starting the process again,
// doubling up to the maximum. A process that crashes on every start would
// otherwise spin: this makes it one attempt every 30 seconds at worst.
type backoff struct {
	min, max time.Duration
	current  time.Duration
}

func newBackoff() *backoff {
	return &backoff{min: time.Second, max: 30 * time.Second}
}

func (b *backoff) next() time.Duration {
	if b.current == 0 {
		b.current = b.min
		return b.current
	}
	b.current *= 2
	if b.current > b.max {
		b.current = b.max
	}
	return b.current
}

func (b *backoff) reset() {
	b.current = 0
}

// users is the set of users the process is supposed to have. It is the state
// the supervisor renders on every (re)start, so a user added while the process
// was down is not lost, and a user removed while it was down never appears.
type users struct {
	mu  sync.Mutex
	set map[string]struct{}
}

func newUsers() *users {
	return &users{set: map[string]struct{}{}}
}

func (u *users) add(id string) (alreadyKnown bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.set[id]; ok {
		return true
	}
	u.set[id] = struct{}{}
	return false
}

func (u *users) remove(id string) (wasKnown bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.set[id]; !ok {
		return false
	}
	delete(u.set, id)
	return true
}

func (u *users) list() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	ids := make([]string, 0, len(u.set))
	for id := range u.set {
		ids = append(ids, id)
	}
	return ids
}

// validateUserID refuses an empty id early: everything downstream - the
// configuration, the API call, the counter key - would otherwise carry it, and
// a user that cannot be removed is worse than a device that cannot be added.
func validateUserID(id string) error {
	if id == "" {
		return fmt.Errorf("a VLESS user id is empty")
	}
	return nil
}
