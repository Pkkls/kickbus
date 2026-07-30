package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tests sign with their own key pair so they depend on no Kick secret.
func sign(t *testing.T, priv *rsa.PrivateKey, id, ts, body string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s.%s.%s", id, ts, body)))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func post(t *testing.T, ts *httptest.Server, id, stamp, body, sig, evType string) int {
	t.Helper()
	req, err := http.NewRequest("POST", ts.URL+"/kick/webhook", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Kick-Event-Message-Id", id)
	req.Header.Set("Kick-Event-Message-Timestamp", stamp)
	req.Header.Set("Kick-Event-Signature", sig)
	req.Header.Set("Kick-Event-Type", evType)
	req.Header.Set("Kick-Event-Version", "1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	return res.StatusCode
}

func TestKickPublicKeyParses(t *testing.T) {
	if _, err := parsePublicKey([]byte(kickPublicKeyPEM)); err != nil {
		t.Fatalf("the embedded Kick key must parse: %v", err)
	}
}

func TestWebhookSignature(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&priv.PublicKey, 10)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	const body = `{"broadcaster":{"user_id":123},"content":"hello"}`
	stamp := time.Now().UTC().Format(time.RFC3339)
	good := sign(t, priv, "msg1", stamp, body)

	if got := post(t, ts, "msg1", stamp, body, good, "chat.message.sent"); got != 200 {
		t.Fatalf("valid signature rejected: %d", got)
	}
	if got := post(t, ts, "msg2", stamp, body, "Zm9v", "chat.message.sent"); got != 401 {
		t.Fatalf("junk signature accepted: %d", got)
	}
	// Same signature, altered body: must fail.
	if got := post(t, ts, "msg1", stamp, body+" ", good, "chat.message.sent"); got != 401 {
		t.Fatalf("altered body accepted: %d", got)
	}
	// Same body, different message id: the signature must not be replayable.
	if got := post(t, ts, "other", stamp, body, good, "chat.message.sent"); got != 401 {
		t.Fatalf("signature replayed onto another id accepted: %d", got)
	}
	if got := post(t, ts, "", stamp, body, good, "chat.message.sent"); got != 400 {
		t.Fatalf("missing header accepted: %d", got)
	}

	// Duplicate: 200 (otherwise Kick retries then unsubscribes) but no republish.
	if got := post(t, ts, "msg1", stamp, body, good, "chat.message.sent"); got != 200 {
		t.Fatalf("duplicate must answer 200, got %d", got)
	}
	if _, total, _ := srv.hub.stats(); total != 1 {
		t.Fatalf("duplicate was republished: total=%d", total)
	}

	if got := srv.hub.Recent(0); len(got) != 1 || got[0].Broadcaster != "123" {
		t.Fatalf("broadcaster not extracted: %+v", got)
	}
}

func TestSSEDeliveryAndFilters(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&priv.PublicKey, 10)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	res, err := http.Get(ts.URL + "/events?type=chat.message.sent&broadcaster=123")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("expected SSE content-type, got %q", ct)
	}

	// Wait for the subscription to register before publishing.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if subs, _, _ := srv.hub.stats(); subs == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SSE subscriber never registered")
		}
		time.Sleep(5 * time.Millisecond)
	}

	stamp := time.Now().UTC().Format(time.RFC3339)
	filtered := `{"broadcaster":{"user_id":999},"content":"other channel"}`
	post(t, ts, "m-other", stamp, filtered, sign(t, priv, "m-other", stamp, filtered), "chat.message.sent")

	wrongType := `{"broadcaster":{"user_id":123}}`
	post(t, ts, "m-follow", stamp, wrongType, sign(t, priv, "m-follow", stamp, wrongType), "channel.followed")

	wanted := `{"broadcaster":{"user_id":123},"content":"for me"}`
	post(t, ts, "m-ok", stamp, wanted, sign(t, priv, "m-ok", stamp, wanted), "chat.message.sent")

	// The first event read must be the one passing both filters.
	type sseEvent struct {
		Type string `json:"type"`
		Data json.RawMessage
	}
	scanner := bufio.NewScanner(res.Body)
	var got sseEvent
	done := make(chan struct{})
	go func() {
		defer close(done)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &got)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("no SSE event received")
	}

	if got.Type != "chat.message.sent" {
		t.Fatalf("wrong type received: %q", got.Type)
	}
	if !strings.Contains(string(got.Data), "for me") {
		t.Fatalf("filters let the wrong event through: %s", got.Data)
	}
	// All three were accepted by the webhook, only one is deliverable.
	if _, total, _ := srv.hub.stats(); total != 3 {
		t.Fatalf("expected total 3, got %d", total)
	}
}

// An old message replayed beyond the dedupe window must be refused, and without
// triggering an RSA computation.
func TestStaleTimestampRejectedBeforeVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&priv.PublicKey, 10)
	// No token available: if the handler attempted verification it would block
	// then return 503. A 400 proves the rejection happens first.
	srv.verify = make(chan struct{})
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	const body = `{"broadcaster":{"user_id":1}}`
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if got := post(t, ts, "old", old, body, sign(t, priv, "old", old, body), "chat.message.sent"); got != 400 {
		t.Fatalf("stale timestamp: expected 400, got %d", got)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if got := post(t, ts, "future", future, body, sign(t, priv, "future", future, body), "chat.message.sent"); got != 400 {
		t.Fatalf("future timestamp: expected 400, got %d", got)
	}
	if got := post(t, ts, "junk", "not-a-date", body, "Zm9v", "chat.message.sent"); got != 400 {
		t.Fatalf("unparseable timestamp: expected 400, got %d", got)
	}
	if _, total, _ := srv.hub.stats(); total != 0 {
		t.Fatalf("nothing should be published, got %d", total)
	}
}

// Under saturation, refuse fast instead of queuing RSA work.
func TestOverloadRefusesInsteadOfBurningCPU(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&priv.PublicKey, 10)
	srv.verify = make(chan struct{}) // no tokens: permanently saturated
	srv.wait = 20 * time.Millisecond
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	body := `{"broadcaster":{"user_id":1}}`
	stamp := time.Now().UTC().Format(time.RFC3339)
	start := time.Now()
	got := post(t, ts, "flood", stamp, body, sign(t, priv, "flood", stamp, body), "chat.message.sent")
	if got != 503 {
		t.Fatalf("under saturation: expected 503, got %d", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("refusal must be fast, took %v", elapsed)
	}
}

// On a 128 MB board the buffer must cap by weight, not just by entry count.
func TestRecentBufferBoundedByBytes(t *testing.T) {
	hub := NewHub(500)
	big := make([]byte, 32<<10)
	for i := range big {
		big[i] = 'x'
	}
	payload := append(append([]byte(`{"p":"`), big...), '"', '}')

	for i := 0; i < 300; i++ {
		hub.Publish(Event{ID: fmt.Sprint(i), Type: "chat.message.sent", Data: payload})
	}

	got := hub.Recent(0)
	if len(got) >= 300 {
		t.Fatalf("buffer should have been trimmed by weight, kept %d entries", len(got))
	}
	total := 0
	for _, e := range got {
		total += len(e.Data)
	}
	if total > maxRecentBytes {
		t.Fatalf("buffer at %d bytes, cap %d", total, maxRecentBytes)
	}
	// The newest events are the ones kept.
	if got[len(got)-1].ID != "299" {
		t.Fatalf("expected last event 299, got %s", got[len(got)-1].ID)
	}
}

// Past the subscriber cap, refuse rather than allocate another queue.
func TestSubscriberLimit(t *testing.T) {
	hub := NewHub(5)
	for i := 0; i < maxSubscribers; i++ {
		if !hub.add(&subscriber{ch: make(chan Event, 1), types: map[string]bool{}}) {
			t.Fatalf("subscriber %d should have been accepted", i)
		}
	}
	extra := &subscriber{ch: make(chan Event, 1), types: map[string]bool{}}
	if hub.add(extra) {
		t.Fatal("subscriber past the cap should have been refused")
	}
	// A freed slot becomes available again.
	for s := range hub.subs {
		hub.remove(s)
		break
	}
	if !hub.add(extra) {
		t.Fatal("a freed slot must be reusable")
	}
}

func TestSSEOverLimitGets503(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&priv.PublicKey, 10)
	for i := 0; i < maxSubscribers; i++ {
		srv.hub.add(&subscriber{ch: make(chan Event, 1), types: map[string]bool{}})
	}
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	res, err := http.Get(ts.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when the bus is full, got %d", res.StatusCode)
	}
}

func TestSlowConsumerIsDroppedNotBlocking(t *testing.T) {
	hub := NewHub(5)
	sub := &subscriber{ch: make(chan Event, 1), types: map[string]bool{}}
	hub.add(sub)

	for i := 0; i < 50; i++ {
		hub.Publish(Event{ID: fmt.Sprint(i), Type: "chat.message.sent"})
	}
	if _, _, dropped := hub.stats(); dropped == 0 {
		t.Fatal("a blocked consumer must produce counted drops, not a stall")
	}
	if got := len(hub.Recent(0)); got != 5 {
		t.Fatalf("buffer must stay bounded at keep=5, got %d", got)
	}
}
