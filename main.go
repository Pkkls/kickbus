// kickbus receives webhooks from the official Kick API, verifies their signature,
// and fans the events out to local consumers over SSE.
//
// Why it exists: kick.com's realtime gateway is closed to server clients
// (Cloudflare blocks both the viewer token and the wss handshake, even behind a
// Chrome TLS fingerprint). The public API pushes the same events to a URL you
// control, and an app access token is enough to subscribe to any channel without
// the streamer's involvement.
//
// Setup:
//  1. https://kick.com/settings/developer, create an app, enable webhooks, point
//     the URL at <host>/kick/webhook
//  2. kickbus -subscribe -broadcaster <user_id>
//  3. consumers listen on GET /events, filtered by type and channel
package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Kick's public key (docs.kick.com/events/webhook-security), also served by
// https://api.kick.com/public/v1/public-key
const kickPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq/+l1WnlRrGSolDMA+A8
6rAhMbQGmQ2SapVcGM3zq8ANXjnhDWocMqfWcTd95btDydITa10kDvHzw9WQOqp2
MZI7ZyrfzJuz5nhTPCiJwTwnEtWft7nV14BYRDHvlfqPUaZ+1KR4OCaO/wWIk/rQ
L/TjY0M70gse8rlBkbo2a8rKhu69RQTRsoaf4DVhDPEeSeI5jVrRDGAMGL3cGuyY
6CLKGdjVEM78g3JfYOvDU/RvfqD7L89TZ3iN94jrmWdGz34JNlEI5hqK8dd7C5EF
BEbZ5jgB8s8ReQV8H+MkuffjdAj3ajDDX3DOJMIut1lBrUVD1AaSrGCKHooWoL2e
twIDAQAB
-----END PUBLIC KEY-----`

const (
	// A Kick chat payload is a few kilobytes. 64 KB leaves plenty of room while
	// preventing a single event from eating the RAM of a board that only has
	// 128 MB.
	maxBodyBytes = 64 << 10

	// The /recent buffer is capped by weight as well as by count: 500 events of
	// 64 KB would be 32 MB, a quarter of the board.
	maxRecentBytes = 2 << 20

	dedupeTTL     = 10 * time.Minute
	heartbeatEvry = 20 * time.Second

	// Every subscriber holds a queue of events, and an event can weigh up to
	// maxBodyBytes. These two bounds cap consumer memory at roughly 16 MB in the
	// worst case.
	slowClientCap  = 16
	maxSubscribers = 16

	// The webhook URL is public and every request costs an RSA verification:
	// 26us on a desktop CPU, roughly 2ms on the board's C906. Unbounded, a few
	// hundred junk requests per second would saturate it. Cap concurrent
	// verifications and wait briefly before giving up, so legitimate bursts are
	// absorbed without ever letting CPU run away.
	maxConcurrentVerify = 4
	verifyWaitBudget    = 2 * time.Second

	// Freshness required of a webhook. The timestamp is covered by the
	// signature, so this check closes replay of an old message beyond dedupeTTL.
	maxClockSkew = 5 * time.Minute
)

type Event struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"`
	Version     string          `json:"version"`
	Broadcaster string          `json:"broadcaster,omitempty"`
	ReceivedAt  time.Time       `json:"received_at"`
	Data        json.RawMessage `json:"data"`
}

func parsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("no PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}
	return key, nil
}

// verifySignature checks Kick's signature: RSA-SHA256 over "<id>.<timestamp>.<body>".
func verifySignature(key *rsa.PublicKey, messageID, timestamp string, body []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("signature is not base64: %w", err)
	}
	signed := make([]byte, 0, len(messageID)+len(timestamp)+len(body)+2)
	signed = append(signed, messageID...)
	signed = append(signed, '.')
	signed = append(signed, timestamp...)
	signed = append(signed, '.')
	signed = append(signed, body...)
	sum := sha256.Sum256(signed)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig)
}

// broadcasterID pulls the channel identifier out of the payload so the bus can
// filter on it. Kick payloads don't all share one shape, so try the known spots
// and leave it empty otherwise.
func broadcasterID(data json.RawMessage) string {
	var probe struct {
		Broadcaster struct {
			UserID json.Number `json:"user_id"`
		} `json:"broadcaster"`
		BroadcasterUserID json.Number `json:"broadcaster_user_id"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return ""
	}
	if s := probe.Broadcaster.UserID.String(); s != "" {
		return s
	}
	return probe.BroadcasterUserID.String()
}

type subscriber struct {
	ch          chan Event
	types       map[string]bool // empty means all
	broadcaster string          // empty means all
}

func (s *subscriber) wants(e Event) bool {
	if len(s.types) > 0 && !s.types[e.Type] {
		return false
	}
	if s.broadcaster != "" && s.broadcaster != e.Broadcaster {
		return false
	}
	return true
}

type Hub struct {
	mu          sync.Mutex
	subs        map[*subscriber]struct{}
	recent      []Event
	recentBytes int
	keep        int
	seen        map[string]time.Time
	dropped     int
	total       int
}

func NewHub(keep int) *Hub {
	return &Hub{subs: map[*subscriber]struct{}{}, keep: keep, seen: map[string]time.Time{}}
}

// seenBefore records the message ID and reports whether it was already handled.
// Kick retries deliveries and the ID is meant as the idempotency key.
func (h *Hub) seenBefore(id string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if t, ok := h.seen[id]; ok && now.Sub(t) < dedupeTTL {
		return true
	}
	// ponytail: linear sweep on every new ID, fine below a few thousand events
	// per TTL; switch to a queue if that ever changes.
	for k, t := range h.seen {
		if now.Sub(t) >= dedupeTTL {
			delete(h.seen, k)
		}
	}
	h.seen[id] = now
	return false
}

func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	h.total++
	h.recent = append(h.recent, e)
	h.recentBytes += len(e.Data)
	// Two bounds: event count and cumulative weight. The second is the one that
	// matters on a 128 MB board.
	for len(h.recent) > h.keep || (h.recentBytes > maxRecentBytes && len(h.recent) > 1) {
		h.recentBytes -= len(h.recent[0].Data)
		// Release the payload: without this it stays pinned by the backing array
		// until the next reallocation.
		h.recent[0] = Event{}
		h.recent = h.recent[1:]
	}
	targets := make([]*subscriber, 0, len(h.subs))
	for s := range h.subs {
		if s.wants(e) {
			targets = append(targets, s)
		}
	}
	h.mu.Unlock()

	for _, s := range targets {
		select {
		case s.ch <- e:
		default:
			// Consumer too slow: drop the event rather than stall the whole bus.
			// The counter shows up in /health.
			h.mu.Lock()
			h.dropped++
			h.mu.Unlock()
		}
	}
}

// add refuses past maxSubscribers: a consumer that retries beats a board that
// runs out of memory.
func (h *Hub) add(s *subscriber) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= maxSubscribers {
		return false
	}
	h.subs[s] = struct{}{}
	return true
}

func (h *Hub) remove(s *subscriber) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (h *Hub) Recent(n int) []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	if n <= 0 || n > len(h.recent) {
		n = len(h.recent)
	}
	out := make([]Event, n)
	copy(out, h.recent[len(h.recent)-n:])
	return out
}

func (h *Hub) stats() (subs, total, dropped int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs), h.total, h.dropped
}

type Server struct {
	hub    *Hub
	key    *rsa.PublicKey
	start  time.Time
	verify chan struct{} // tokens bounding concurrent RSA verifications
	wait   time.Duration // how long to wait for a token before returning 503
	now    func() time.Time
}

func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST expected", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	msgID := r.Header.Get("Kick-Event-Message-Id")
	ts := r.Header.Get("Kick-Event-Message-Timestamp")
	sig := r.Header.Get("Kick-Event-Signature")
	if msgID == "" || ts == "" || sig == "" {
		http.Error(w, "missing Kick headers", http.StatusBadRequest)
		return
	}

	// Free checks first: an attacker must not be able to trigger an RSA
	// computation with an obviously invalid request.
	stamp, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		http.Error(w, "unparseable timestamp", http.StatusBadRequest)
		return
	}
	if drift := s.now().Sub(stamp); drift > maxClockSkew || drift < -maxClockSkew {
		http.Error(w, "timestamp out of window", http.StatusBadRequest)
		return
	}

	select {
	case s.verify <- struct{}{}:
		defer func() { <-s.verify }()
	case <-time.After(s.wait):
		// Saturated: refuse without burning CPU. Kick will retry.
		w.Header().Set("Retry-After", "5")
		http.Error(w, "overloaded", http.StatusServiceUnavailable)
		return
	case <-r.Context().Done():
		return
	}

	if err := verifySignature(s.key, msgID, ts, body, sig); err != nil {
		log.Printf("signature rejected (msg %s): %v", msgID, err)
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	if !json.Valid(body) {
		http.Error(w, "body is not JSON", http.StatusBadRequest)
		return
	}
	// Answer 200 even on a duplicate: otherwise Kick retries, and after a day of
	// failures it unsubscribes the app.
	if s.hub.seenBefore(msgID, s.now()) {
		w.WriteHeader(http.StatusOK)
		return
	}
	e := Event{
		ID:         msgID,
		Type:       r.Header.Get("Kick-Event-Type"),
		Version:    r.Header.Get("Kick-Event-Version"),
		ReceivedAt: s.now().UTC(),
		Data:       json.RawMessage(body),
	}
	e.Broadcaster = broadcasterID(e.Data)
	s.hub.Publish(e)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	sub := &subscriber{ch: make(chan Event, slowClientCap), types: map[string]bool{}}
	if raw := r.URL.Query().Get("type"); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			if t = strings.TrimSpace(t); t != "" {
				sub.types[t] = true
			}
		}
	}
	sub.broadcaster = strings.TrimSpace(r.URL.Query().Get("broadcaster"))

	// Register before writing the response: once the 200 is out we can no longer
	// refuse, and any event published in between would be lost.
	if !s.hub.add(sub) {
		w.Header().Set("Retry-After", "10")
		http.Error(w, "too many subscribers", http.StatusServiceUnavailable)
		return
	}
	defer s.hub.remove(sub)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ticker := time.NewTicker(heartbeatEvry)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case e := <-sub.ch:
			payload, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", e.ID, e.Type, payload)
			flusher.Flush()
		}
	}
}

func (s *Server) handleRecent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.hub.Recent(0))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	subs, total, dropped := s.hub.stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"uptime_seconds": int(time.Since(s.start).Seconds()),
		"subscribers":    subs,
		"events_total":   total,
		"events_dropped": dropped,
	})
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/kick/webhook", s.handleWebhook)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/recent", s.handleRecent)
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

func NewServer(key *rsa.PublicKey, keep int) *Server {
	return &Server{
		hub:    NewHub(keep),
		key:    key,
		start:  time.Now(),
		verify: make(chan struct{}, maxConcurrentVerify),
		wait:   verifyWaitBudget,
		now:    time.Now,
	}
}

func main() {
	addr := flag.String("addr", ":8787", "listen address")
	keyPath := flag.String("key", "", "path to a PEM public key (default: embedded Kick key)")
	keep := flag.Int("keep", 500, "how many events to retain for /recent")
	subscribe := flag.Bool("subscribe", false, "create a subscription, then exit")
	list := flag.Bool("list", false, "list subscriptions, then exit")
	clientID := flag.String("client-id", os.Getenv("KICK_CLIENT_ID"), "Kick app client ID")
	clientSecret := flag.String("client-secret", os.Getenv("KICK_CLIENT_SECRET"), "Kick app client secret")
	broadcaster := flag.String("broadcaster", "", "broadcaster user ID to follow")
	events := flag.String("events", "chat.message.sent", "comma-separated events to follow")
	flag.Parse()

	if *subscribe || *list {
		if *clientID == "" || *clientSecret == "" {
			log.Fatal("client-id and client-secret are required (or KICK_CLIENT_ID / KICK_CLIENT_SECRET)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		token, err := appAccessToken(ctx, *clientID, *clientSecret)
		if err != nil {
			log.Fatalf("token: %v", err)
		}
		var out string
		if *list {
			out, err = listSubscriptions(ctx, token)
		} else {
			out, err = createSubscriptions(ctx, token, *broadcaster, strings.Split(*events, ","))
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(out)
		return
	}

	pemBytes := []byte(kickPublicKeyPEM)
	if *keyPath != "" {
		b, err := os.ReadFile(*keyPath)
		if err != nil {
			log.Fatalf("read key: %v", err)
		}
		pemBytes = b
	}
	key, err := parsePublicKey(pemBytes)
	if err != nil {
		log.Fatalf("public key: %v", err)
	}

	srv := NewServer(key, *keep)
	log.Printf("kickbus listening on %s (webhook: POST /kick/webhook, stream: GET /events)", *addr)
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(httpSrv.ListenAndServe())
}
