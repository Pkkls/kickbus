package main

// Without a subscription the bus never receives anything. These helpers make the
// two calls the public Kick API needs. That API is reachable from a server,
// unlike the kick.com gateway which Cloudflare closes off:
//   1. app access token via client_credentials on id.kick.com
//   2. POST/GET of subscriptions on api.kick.com
//
// An app token is enough to subscribe to any channel: all it takes is the
// broadcaster's user ID.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const subscriptionCheckEvery = 30 * time.Minute

// Variables rather than constants: tests point them at a local server.
var (
	tokenURL        = "https://id.kick.com/oauth/token"
	subscriptionURL = "https://api.kick.com/public/v1/events/subscriptions"
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

func appAccessToken(ctx context.Context, clientID, clientSecret string) (string, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token http %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", err
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return parsed.AccessToken, nil
}

func createSubscriptions(ctx context.Context, token, broadcasterID string, events []string) (string, error) {
	type eventRef struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	}
	payload := struct {
		// The API types this as an integer. Sending a string here is rejected,
		// which is exactly the kind of mistake a permissive test double hides.
		BroadcasterUserID int64      `json:"broadcaster_user_id,omitempty"`
		Events            []eventRef `json:"events"`
		Method            string     `json:"method"`
	}{Method: "webhook"}

	if broadcasterID != "" {
		id, err := strconv.ParseInt(strings.TrimSpace(broadcasterID), 10, 64)
		if err != nil {
			return "", fmt.Errorf("broadcaster must be a numeric user ID, got %q", broadcasterID)
		}
		payload.BroadcasterUserID = id
	}
	for _, name := range events {
		if name = strings.TrimSpace(name); name != "" {
			payload.Events = append(payload.Events, eventRef{Name: name, Version: 1})
		}
	}
	if len(payload.Events) == 0 {
		return "", fmt.Errorf("no events to subscribe to")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, subscriptionURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("subscription http %d: %s", res.StatusCode, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Subscription mirrors the documented shape of a listed subscription.
type Subscription struct {
	ID                string `json:"id"`
	Event             string `json:"event"`
	BroadcasterUserID int64  `json:"broadcaster_user_id"`
	Method            string `json:"method"`
	Version           int    `json:"version"`
}

func fetchSubscriptions(ctx context.Context, token string) ([]Subscription, error) {
	raw, err := listSubscriptions(ctx, token)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []Subscription `json:"data"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, err
	}
	return parsed.Data, nil
}

// missingEvents reports which of the wanted events are not currently subscribed
// for this broadcaster. Kick drops an app's subscriptions after a day of failed
// deliveries, so a bus can end up perfectly healthy and permanently silent.
func missingEvents(subs []Subscription, broadcasterID string, wanted []string) []string {
	have := map[string]bool{}
	for _, s := range subs {
		if broadcasterID == "" || strconv.FormatInt(s.BroadcasterUserID, 10) == strings.TrimSpace(broadcasterID) {
			have[s.Event] = true
		}
	}
	var missing []string
	for _, name := range wanted {
		if name = strings.TrimSpace(name); name != "" && !have[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// ensureSubscriptions recreates whatever is missing and returns how many
// subscriptions exist afterwards.
func ensureSubscriptions(ctx context.Context, clientID, clientSecret, broadcasterID string, wanted []string) (int, error) {
	token, err := appAccessToken(ctx, clientID, clientSecret)
	if err != nil {
		return 0, err
	}
	subs, err := fetchSubscriptions(ctx, token)
	if err != nil {
		return 0, err
	}
	missing := missingEvents(subs, broadcasterID, wanted)
	if len(missing) == 0 {
		return len(subs), nil
	}
	log.Printf("resubscribing to %v (Kick dropped them)", missing)
	if _, err := createSubscriptions(ctx, token, broadcasterID, missing); err != nil {
		return len(subs), err
	}
	subs, err = fetchSubscriptions(ctx, token)
	if err != nil {
		return 0, err
	}
	return len(subs), nil
}

// checkSubscriptions runs one repair pass and records the outcome for /health.
func (s *Server) checkSubscriptions(ctx context.Context, clientID, clientSecret, broadcasterID string, wanted []string) {
	count, err := ensureSubscriptions(ctx, clientID, clientSecret, broadcasterID, wanted)
	s.subsCheckedUnix.Store(s.now().Unix())
	if err != nil {
		msg := err.Error()
		s.subsErr.Store(&msg)
		log.Printf("subscription check failed: %v", err)
		return
	}
	s.subsErr.Store(nil)
	s.subsCount.Store(int64(count))
}

// watchSubscriptions keeps the app subscribed for the lifetime of the process.
func (s *Server) watchSubscriptions(ctx context.Context, clientID, clientSecret, broadcasterID string, wanted []string, every time.Duration) {
	s.checkSubscriptions(ctx, clientID, clientSecret, broadcasterID, wanted)

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkSubscriptions(ctx, clientID, clientSecret, broadcasterID, wanted)
		}
	}
}

func listSubscriptions(ctx context.Context, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscriptionURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("list http %d: %s", res.StatusCode, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
