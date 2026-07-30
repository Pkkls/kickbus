package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Checks the exact shape of the outgoing calls, with no Kick credentials.
func TestAppAccessTokenAndSubscribe(t *testing.T) {
	var gotTokenForm string
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotTokenForm = string(b)
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content-type, got %q", ct)
		}
		w.Write([]byte(`{"access_token":"tok-abc","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenSrv.Close()

	var gotAuth string
	var gotBody map[string]any
	subSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":[{"subscription_id":"sub-1"}]}`))
	}))
	defer subSrv.Close()

	tokenURL, subscriptionURL = tokenSrv.URL, subSrv.URL
	ctx := context.Background()

	token, err := appAccessToken(ctx, "id42", "secret42")
	if err != nil {
		t.Fatal(err)
	}
	if token != "tok-abc" {
		t.Fatalf("token badly extracted: %q", token)
	}
	for _, want := range []string{"grant_type=client_credentials", "client_id=id42", "client_secret=secret42"} {
		if !strings.Contains(gotTokenForm, want) {
			t.Fatalf("token form missing %q: %s", want, gotTokenForm)
		}
	}

	if _, err := createSubscriptions(ctx, token, "123", []string{"chat.message.sent", "channel.followed"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Fatalf("Authorization header: %q", gotAuth)
	}
	if gotBody["method"] != "webhook" {
		t.Fatalf("expected method webhook, got %v", gotBody["method"])
	}
	// JSON numbers decode to float64: the API wants a number here, not a string.
	if gotBody["broadcaster_user_id"] != float64(123) {
		t.Fatalf("broadcaster not passed through as a number: %#v", gotBody["broadcaster_user_id"])
	}
	evs, _ := gotBody["events"].([]any)
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %v", gotBody["events"])
	}
	first, _ := evs[0].(map[string]any)
	if first["name"] != "chat.message.sent" || first["version"] != float64(1) {
		t.Fatalf("malformed event: %v", first)
	}
}

// The API types broadcaster_user_id as an integer. A permissive test double
// hid this once already, so assert the wire type, not just the value.
func TestBroadcasterIsSentAsANumber(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	subscriptionURL = srv.URL

	if _, err := createSubscriptions(context.Background(), "tok", "123456", []string{"chat.message.sent"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"broadcaster_user_id":"`) {
		t.Fatalf("broadcaster_user_id must be a JSON number, got %s", raw)
	}
	if !strings.Contains(string(raw), `"broadcaster_user_id":123456`) {
		t.Fatalf("broadcaster_user_id missing or wrong: %s", raw)
	}
}

func TestSubscribeRejectsBadInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be sent for invalid input")
	}))
	defer srv.Close()
	subscriptionURL = srv.URL

	if _, err := createSubscriptions(context.Background(), "tok", "not-a-number", []string{"chat.message.sent"}); err == nil {
		t.Fatal("a non-numeric broadcaster must be refused")
	}
	if _, err := createSubscriptions(context.Background(), "tok", "123", []string{"", "  "}); err == nil {
		t.Fatal("an empty event list must be refused")
	}
}

func TestMissingEvents(t *testing.T) {
	subs := []Subscription{
		{Event: "chat.message.sent", BroadcasterUserID: 123},
		{Event: "channel.followed", BroadcasterUserID: 999},
	}
	wanted := []string{"chat.message.sent", "channel.followed"}

	got := missingEvents(subs, "123", wanted)
	if len(got) != 1 || got[0] != "channel.followed" {
		t.Fatalf("a subscription for another channel must not count, got %v", got)
	}
	if got := missingEvents(subs, "123", []string{"chat.message.sent"}); got != nil {
		t.Fatalf("nothing should be missing, got %v", got)
	}
	if got := missingEvents(nil, "123", wanted); len(got) != 2 {
		t.Fatalf("an empty list means everything is missing, got %v", got)
	}
	// Without a broadcaster filter, any channel counts.
	if got := missingEvents(subs, "", wanted); got != nil {
		t.Fatalf("unfiltered, nothing is missing, got %v", got)
	}
}

// The outage this exists for: Kick dropped the subscriptions, the daemon must
// notice and recreate exactly what is missing.
func TestEnsureSubscriptionsRepairsWhatIsMissing(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
	defer tokenSrv.Close()
	tokenURL = tokenSrv.URL

	var created []map[string]any
	existing := `{"data":[]}`
	subSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			created = append(created, body)
			// After creation the listing reflects the new subscription.
			existing = `{"data":[{"id":"s1","event":"chat.message.sent","broadcaster_user_id":123,"method":"webhook"}]}`
			w.Write([]byte(`{"data":[{"subscription_id":"s1"}]}`))
			return
		}
		w.Write([]byte(existing))
	}))
	defer subSrv.Close()
	subscriptionURL = subSrv.URL

	count, err := ensureSubscriptions(context.Background(), "id", "secret", "123", []string{"chat.message.sent"})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 subscription after repair, got %d", count)
	}
	if len(created) != 1 {
		t.Fatalf("expected exactly one create call, got %d", len(created))
	}

	// Second pass: nothing is missing, so nothing must be created again.
	created = nil
	if _, err := ensureSubscriptions(context.Background(), "id", "secret", "123", []string{"chat.message.sent"}); err != nil {
		t.Fatal(err)
	}
	if len(created) != 0 {
		t.Fatalf("an existing subscription must not be recreated, got %d calls", len(created))
	}
}

func TestSubscriptionHealthReporting(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer tokenSrv.Close()
	tokenURL = tokenSrv.URL

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv := NewServer(&priv.PublicKey, 10)
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	health := func() map[string]any {
		res, err := http.Get(ts.URL + "/health")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		json.NewDecoder(res.Body).Decode(&out)
		return out
	}

	if _, present := health()["subscriptions_checked_at"]; present {
		t.Fatal("nothing should be reported before the first check")
	}

	srv.checkSubscriptions(context.Background(), "id", "secret", "123", []string{"chat.message.sent"})

	after := health()
	if _, present := after["subscriptions_checked_at"]; !present {
		t.Fatal("the check timestamp must be reported")
	}
	msg, _ := after["subscriptions_error"].(string)
	if !strings.Contains(msg, "invalid_client") {
		t.Fatalf("the failure must surface in health, got %v", after["subscriptions_error"])
	}
}

func TestTokenErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()
	tokenURL = srv.URL

	_, err := appAccessToken(context.Background(), "bad", "bad")
	if err == nil {
		t.Fatal("an error was expected")
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("the error body must surface: %v", err)
	}
}
