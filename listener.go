package main

// Caps how many connections exist at once.
//
// The webhook URL is public and unauthenticated by nature: anyone who learns
// it can open connections. Request timeouts bound how long each one lives, but
// nothing bounds how many are alive together, and each costs a goroutine, its
// stack, and a body buffer of up to maxBodyBytes. On a 128 MB board that is
// the cheapest way to bring the daemon down, and it never reaches the RSA
// semaphore, so the CPU cap does not help.
//
// Excess connections are accepted and immediately closed rather than left
// queued in the kernel backlog: a caller learns straight away, and the daemon
// holds no state for them. Kick retries a failed delivery, so a refused
// connection under attack costs a retry, not an event.

import (
	"net"
	"sync/atomic"
)

// Sized so the worst case is bounded and small: this many connections, each
// holding at most maxBodyBytes, is a few megabytes. Kick delivers webhooks
// sequentially per subscription, so legitimate traffic never approaches it.
const maxConnections = 64

type limitedListener struct {
	net.Listener
	slots chan struct{}
	// Refusals are counted rather than logged per event: under a flood the
	// logging itself becomes the load.
	refused atomic.Int64
}

func limitListener(inner net.Listener, limit int) *limitedListener {
	return &limitedListener{Listener: inner, slots: make(chan struct{}, limit)}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: conn, release: l.release}, nil
		default:
			l.refused.Add(1)
			conn.Close()
			// Keep accepting: the goal is to shed the excess, not to stop
			// serving. Returning the error here would kill the server.
		}
	}
}

func (l *limitedListener) release() {
	select {
	case <-l.slots:
	default:
	}
}

// Refusals reports how many connections were shed, for /health.
func (l *limitedListener) Refusals() int64 { return l.refused.Load() }

// InFlight reports how many connections are currently open.
func (l *limitedListener) InFlight() int { return len(l.slots) }

type limitedConn struct {
	net.Conn
	release func()
	once    atomic.Bool
}

func (c *limitedConn) Close() error {
	// Close can be called more than once; the slot must be freed exactly once
	// or the limit erodes until the daemon refuses everything.
	if c.once.CompareAndSwap(false, true) {
		c.release()
	}
	return c.Conn.Close()
}
