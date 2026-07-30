package main

import (
	"context"
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
	if gotBody["broadcaster_user_id"] != "123" {
		t.Fatalf("broadcaster not passed through: %v", gotBody["broadcaster_user_id"])
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
