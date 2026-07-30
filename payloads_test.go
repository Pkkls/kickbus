package main

import (
	"encoding/json"
	"testing"
)

// Payloads taken from docs.kick.com/events/event-types, trimmed to the fields
// this daemon reads. The broadcaster filter is a headline feature and it rests
// entirely on the shape of these documents, so it gets asserted against the
// documented shape rather than against a payload invented by the test.
//
// The docs render these with // comments and trailing commas, which are not
// valid JSON. They are cleaned up here, not reshaped.
var documentedPayloads = map[string]string{
	"chat.message.sent": `{
	  "message_id": "unique_message_id_123",
	  "replies_to": {
	    "message_id": "unique_message_id_456",
	    "content": "This is the parent message!",
	    "sender": {"is_anonymous": false, "user_id": 12345, "username": "parent_sender_name"}
	  },
	  "broadcaster": {
	    "is_anonymous": false, "user_id": 123456789, "username": "broadcaster_name",
	    "is_verified": true, "channel_slug": "broadcaster_channel", "identity": null
	  },
	  "sender": {
	    "is_anonymous": false, "user_id": 987654321, "username": "sender_name",
	    "identity": {
	      "username_color": "#FF5733",
	      "badges": [{"text": "Moderator", "type": "moderator"}]
	    }
	  },
	  "content": "Hello [emote:4148074:HYPERCLAP]",
	  "emotes": [{"emote_id": "4148074", "positions": [{"s": 6, "e": 30}]}],
	  "created_at": "2025-01-14T16:08:06Z"
	}`,

	"channel.followed": `{
	  "broadcaster": {"is_anonymous": false, "user_id": 123456789, "username": "broadcaster_name"},
	  "follower": {"is_anonymous": false, "user_id": 987654321, "username": "follower_name"}
	}`,

	"channel.subscription.renewal": `{
	  "broadcaster": {"is_anonymous": false, "user_id": 123456789, "username": "broadcaster_name"},
	  "subscriber": {"is_anonymous": false, "user_id": 987654321, "username": "subscriber_name"},
	  "duration": 1, "created_at": "2025-01-14T16:08:06Z", "expires_at": "2025-02-14T16:08:06Z"
	}`,

	"channel.reward.redemption.updated": `{
	  "broadcaster": {"is_anonymous": false, "user_id": 123456789, "username": "broadcaster_name"},
	  "redeemer": {"is_anonymous": false, "user_id": 987654321, "username": "redeemer_name"},
	  "reward": {"id": "r1", "title": "A reward", "cost": 100, "description": "desc"},
	  "id": "redemption-1", "status": "fulfilled", "user_input": "", "redeemed_at": "2025-01-14T16:08:06Z"
	}`,

	"livestream.status.updated": `{
	  "broadcaster": {"is_anonymous": false, "user_id": 123456789, "username": "broadcaster_name"},
	  "is_live": true, "title": "Stream title",
	  "started_at": "2025-01-14T16:08:06Z", "ended_at": null
	}`,

	"livestream.metadata.updated": `{
	  "broadcaster": {"is_anonymous": false, "user_id": 123456789, "username": "broadcaster_name"},
	  "metadata": {"title": "New title", "language": "en", "has_mature_content": false,
	    "category": {"id": 1, "name": "Just Chatting"}}
	}`,
}

func TestBroadcasterExtractedFromDocumentedPayloads(t *testing.T) {
	for eventType, payload := range documentedPayloads {
		t.Run(eventType, func(t *testing.T) {
			if !json.Valid([]byte(payload)) {
				t.Fatal("fixture is not valid JSON")
			}
			got := broadcasterID(json.RawMessage(payload))
			if got != "123456789" {
				t.Fatalf("broadcaster not extracted, got %q. The SSE broadcaster filter silently matches nothing when this breaks", got)
			}
		})
	}
}

// The filter must not fall back to matching everything when the field is absent.
func TestBroadcasterAbsentIsEmptyNotWrong(t *testing.T) {
	for _, payload := range []string{
		`{"metadata":{"title":"x"}}`,
		`{"broadcaster":null}`,
		`{"broadcaster":{"username":"no id here"}}`,
		`[]`,
		`not json`,
	} {
		if got := broadcasterID(json.RawMessage(payload)); got != "" {
			t.Fatalf("payload %s should yield no broadcaster, got %q", payload, got)
		}
	}
}

// A consumer asking for one channel must never be handed another channel's
// events, whatever the payload looks like.
func TestFilterNeverLeaksAcrossChannels(t *testing.T) {
	sub := &subscriber{ch: make(chan Event, 1), types: map[string]bool{}, broadcaster: "123456789"}

	for eventType, payload := range documentedPayloads {
		e := Event{Type: eventType, Data: json.RawMessage(payload)}
		e.Broadcaster = broadcasterID(e.Data)
		if !sub.wants(e) {
			t.Fatalf("%s for the subscribed channel was filtered out", eventType)
		}
	}

	other := Event{Type: "chat.message.sent", Data: json.RawMessage(`{"broadcaster":{"user_id":999}}`)}
	other.Broadcaster = broadcasterID(other.Data)
	if sub.wants(other) {
		t.Fatal("another channel's event leaked through the filter")
	}

	unknown := Event{Type: "chat.message.sent", Data: json.RawMessage(`{}`)}
	unknown.Broadcaster = broadcasterID(unknown.Data)
	if sub.wants(unknown) {
		t.Fatal("an event with no broadcaster must not match a channel-filtered subscriber")
	}
}
