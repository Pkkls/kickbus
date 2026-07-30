package main

// Kick publishes its signing key at a documented endpoint. Pinning only the
// embedded copy makes key rotation a silent outage: every webhook would fail
// signature checks, and Kick unsubscribes an app after a day of failures.
//
// So the key is fetched at startup and refreshed periodically, with the
// embedded copy as the offline fallback. api.kick.com answers plain HTTP
// clients, unlike the kick.com gateway.

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

var publicKeyURL = "https://api.kick.com/public/v1/public-key"

const keyRefreshEvery = 6 * time.Hour

func fetchPublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicKeyURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("public key http %d", res.StatusCode)
	}
	var parsed struct {
		Data struct {
			PublicKey string `json:"public_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	if parsed.Data.PublicKey == "" {
		return nil, fmt.Errorf("no public_key in response")
	}
	return parsePublicKey([]byte(parsed.Data.PublicKey))
}

// keyHolder lets the verification path read the current key without locking
// while a refresh swaps it underneath.
type keyHolder struct {
	current   atomic.Pointer[rsa.PublicKey]
	published atomic.Bool // false means we are still on the compiled-in copy
}

func newKeyHolder(key *rsa.PublicKey) *keyHolder {
	h := &keyHolder{}
	h.current.Store(key)
	return h
}

func (h *keyHolder) get() *rsa.PublicKey { return h.current.Load() }

// source names where the active key came from, so a remote operator can tell
// from /health whether the daemon ever reached Kick.
func (h *keyHolder) source() string {
	if h.published.Load() {
		return "published"
	}
	return "embedded"
}

// refresh swaps in the published key and reports whether it changed.
func (h *keyHolder) refresh(ctx context.Context) (rotated bool, err error) {
	fetched, err := fetchPublicKey(ctx)
	if err != nil {
		return false, err
	}
	previous := h.current.Load()
	h.published.Store(true)
	if previous != nil && previous.Equal(fetched) {
		return false, nil
	}
	h.current.Store(fetched)
	return true, nil
}

// watchPublicKey keeps the key current for the lifetime of the process. A
// failed refresh is not fatal: the key we already hold stays valid.
func (h *keyHolder) watch(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rotated, err := h.refresh(ctx)
			switch {
			case err != nil:
				log.Printf("public key refresh failed, keeping the current one: %v", err)
			case rotated:
				log.Print("public key rotated, now verifying against the new one")
			}
		}
	}
}
