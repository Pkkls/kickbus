package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func pemOf(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func keyServer(t *testing.T, body string, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func TestFetchPublicKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{
		"data": map[string]string{"public_key": pemOf(t, &priv.PublicKey)},
	})

	srv := keyServer(t, string(payload), 200)
	defer srv.Close()
	publicKeyURL = srv.URL

	got, err := fetchPublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(&priv.PublicKey) {
		t.Fatal("fetched key does not match the served one")
	}
}

func TestFetchPublicKeyErrors(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
	}{
		{"http error", `{}`, 500},
		{"empty field", `{"data":{"public_key":""}}`, 200},
		{"not a key", `{"data":{"public_key":"hello"}}`, 200},
		{"not json", `<html>`, 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := keyServer(t, c.body, c.status)
			defer srv.Close()
			publicKeyURL = srv.URL
			if _, err := fetchPublicKey(context.Background()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// Rotation is the failure this whole file exists for: signatures made with the
// new key must verify once the holder has refreshed.
func TestRotationIsPickedUpAndVerifies(t *testing.T) {
	oldKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	newKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	payload, _ := json.Marshal(map[string]any{
		"data": map[string]string{"public_key": pemOf(t, &newKey.PublicKey)},
	})
	keySrv := keyServer(t, string(payload), 200)
	defer keySrv.Close()
	publicKeyURL = keySrv.URL

	srv := NewServer(&oldKey.PublicKey, 10)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	body := `{"broadcaster":{"user_id":7}}`
	stamp := time.Now().UTC().Format(time.RFC3339)
	sig := sign(t, newKey, "rotated", stamp, body)

	// Before the refresh the new signature is correctly rejected.
	if got := post(t, ts, "rotated", stamp, body, sig, "chat.message.sent"); got != 401 {
		t.Fatalf("expected 401 before rotation, got %d", got)
	}

	rotated, err := srv.keys.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("refresh should have reported a rotation")
	}

	if got := post(t, ts, "rotated", stamp, body, sig, "chat.message.sent"); got != 200 {
		t.Fatalf("expected 200 after rotation, got %d", got)
	}
}

func TestRefreshReportsNoChangeForSameKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	payload, _ := json.Marshal(map[string]any{
		"data": map[string]string{"public_key": pemOf(t, &priv.PublicKey)},
	})
	srv := keyServer(t, string(payload), 200)
	defer srv.Close()
	publicKeyURL = srv.URL

	holder := newKeyHolder(&priv.PublicKey)
	rotated, err := holder.refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rotated {
		t.Fatal("an identical key must not be reported as rotated")
	}
}

func TestKeySourceReporting(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	holder := newKeyHolder(&priv.PublicKey)
	if holder.source() != "embedded" {
		t.Fatalf("before any fetch the source is embedded, got %q", holder.source())
	}

	payload, _ := json.Marshal(map[string]any{
		"data": map[string]string{"public_key": pemOf(t, &priv.PublicKey)},
	})
	srv := keyServer(t, string(payload), 200)
	defer srv.Close()
	publicKeyURL = srv.URL

	if _, err := holder.refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if holder.source() != "published" {
		t.Fatalf("after a successful fetch the source is published, got %q", holder.source())
	}
}

// A failed refresh must never leave the daemon without a usable key.
func TestFailedRefreshKeepsCurrentKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := keyServer(t, `{}`, 503)
	defer srv.Close()
	publicKeyURL = srv.URL

	holder := newKeyHolder(&priv.PublicKey)
	if _, err := holder.refresh(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if got := holder.get(); got == nil || !got.Equal(&priv.PublicKey) {
		t.Fatal("the previous key must survive a failed refresh")
	}
}

// The key Kick documents must be the one we ship, otherwise the offline
// fallback is already wrong on day one.
func TestEmbeddedKeyMatchesPublishedKey(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	publicKeyURL = "https://api.kick.com/public/v1/public-key"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	published, err := fetchPublicKey(ctx)
	if err != nil {
		t.Skipf("Kick unreachable: %v", err)
	}
	embedded, err := parsePublicKey([]byte(kickPublicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if !embedded.Equal(published) {
		t.Errorf("embedded key differs from the published one, update %s", strings.TrimSpace("kickPublicKeyPEM"))
	}
}
