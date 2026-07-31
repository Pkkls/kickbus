package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// The defect this guards: a public webhook URL plus unbounded concurrent
// connections meant an attacker could hold thousands of goroutines and buffers
// open, never reaching the RSA semaphore, and exhaust a 128 MB board.
func TestListenerCapsConcurrentConnections(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := limitListener(inner, 3)
	defer limited.Close()

	go func() {
		for {
			conn, err := limited.Accept()
			if err != nil {
				return
			}
			// Hold it, like a handler blocked reading a slow body.
			go func(c net.Conn) {
				io.ReadAll(c)
				c.Close()
			}(conn)
		}
	}()

	addr := inner.Addr().String()
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	// Three connections fit.
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("connection %d refused, the limit should allow it: %v", i, err)
		}
		held = append(held, c)
	}
	waitFor(t, func() bool { return limited.InFlight() == 3 })

	// The fourth is accepted then dropped, which the client sees as EOF.
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial should still succeed, the excess is shed after accept: %v", err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("the connection over the limit should have been closed")
	}
	waitFor(t, func() bool { return limited.Refusals() >= 1 })

	// Freeing one slot must let a new connection through: the limit is a
	// gate, not a fuse.
	held[0].Close()
	held = held[1:]
	waitFor(t, func() bool { return limited.InFlight() == 2 })

	back, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("a freed slot must be reusable: %v", err)
	}
	held = append(held, back)
	waitFor(t, func() bool { return limited.InFlight() == 3 })
}

// Close being called twice must not free the slot twice, or the effective
// limit erodes on every reused connection until nothing is accepted.
func TestDoubleCloseFreesOneSlot(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := limitListener(inner, 2)
	defer limited.Close()

	limited.slots <- struct{}{}
	limited.slots <- struct{}{}
	conn := &limitedConn{Conn: nopConn{}, release: limited.release}
	conn.Close()
	conn.Close()
	if got := limited.InFlight(); got != 1 {
		t.Fatalf("two closes freed %d slots, expected 1", 2-got)
	}
}

// A real server behind the limiter still serves requests correctly.
func TestServerStillWorksBehindTheLimiter(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	limited := limitListener(inner, 8)
	srv := &http.Server{
		Handler:     http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }),
		ReadTimeout: 5 * time.Second,
	}
	go srv.Serve(limited)
	defer srv.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := http.Get("http://" + inner.Addr().String() + "/")
			if err != nil {
				errs <- err
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	// Some may be refused under the cap, but the server must keep serving and
	// slots must be returned, so the last requests succeed.
	res, err := http.Get("http://" + inner.Addr().String() + "/")
	if err != nil {
		t.Fatalf("server stopped serving after a burst: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("unexpected body %q", body)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached in time")
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error { return nil }
