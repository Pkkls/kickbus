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
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
		BroadcasterUserID string     `json:"broadcaster_user_id,omitempty"`
		Events            []eventRef `json:"events"`
		Method            string     `json:"method"`
	}{BroadcasterUserID: broadcasterID, Method: "webhook"}
	for _, name := range events {
		payload.Events = append(payload.Events, eventRef{Name: name, Version: 1})
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
