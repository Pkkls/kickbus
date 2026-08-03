# kickbus

[![ci](https://github.com/Pkkls/kickbus/actions/workflows/ci.yml/badge.svg)](https://github.com/Pkkls/kickbus/actions/workflows/ci.yml)

Receives webhooks from the official Kick API, verifies their signature, and fans the events out to local consumers over Server-Sent Events.

One daemon holds the relationship with Kick. Every bot on your network reads from it with a single HTTP request, and none of them needs credentials.

## Why

kick.com's realtime gateway is closed to server clients. Cloudflare rejects both the viewer token endpoint and the websocket handshake, including behind a Chrome TLS fingerprint. The public API solves this from the other direction: Kick pushes events to a URL you control, and an app access token is enough to subscribe to any channel without the streamer being involved.

## Setup

Build first. The module path is local, so `go install` does not apply:

```sh
git clone https://github.com/Pkkls/kickbus.git
cd kickbus && go build
```

Kick pushes to you, so the daemon needs an address Kick can reach over HTTPS. A reverse proxy or a tunnel in front of `:8787` is enough; nothing here terminates TLS.

Create an app at [kick.com/settings/developer](https://kick.com/settings/developer), enable webhooks, and point the webhook URL at `https://your-host/kick/webhook`.

Then subscribe:

```sh
export KICK_CLIENT_ID=... KICK_CLIENT_SECRET=...
kickbus -subscribe -broadcaster 123456
kickbus -list
```

And run the daemon:

```sh
kickbus -addr :8787
```

Give the daemon the same credentials and it keeps the subscription alive by itself:

```sh
KICK_CLIENT_ID=... KICK_CLIENT_SECRET=... kickbus -addr :8787 -broadcaster 123456
```

Every thirty minutes it lists the app's subscriptions and recreates whatever is missing. Without credentials it still runs, it just cannot repair anything, and it says so at startup.

## Consuming

```sh
curl -N "http://localhost:8787/events?type=chat.message.sent&broadcaster=123456"
```

Both query parameters are optional. `type` accepts a comma-separated list.

Each event arrives as a standard SSE frame, the data being Kick's payload passed through untouched:

```
id: 01K4...
event: chat.message.sent
data: {"message_id":"...","broadcaster":{...},"sender":{...},"content":"hello"}
```

`-subscribe` defaults to `chat.message.sent`; pass `-events` a comma-separated list for anything else Kick publishes.

`examples/consumer.py` is a working consumer in about sixty lines of standard library Python, with reconnection and backoff:

```sh
python examples/consumer.py --url http://localhost:8787 --broadcaster 123456
```

| Endpoint | Purpose |
| --- | --- |
| `POST /kick/webhook` | where Kick delivers events |
| `GET /events` | SSE stream, filtered by `type` and `broadcaster` |
| `GET /recent` | buffered recent events as JSON |
| `GET /health` | uptime, subscribers, totals, drops, key source, time since the last event |

## Build

```sh
go test ./...
go build
```

`build.sh` cross-compiles a static `riscv64` binary, and `S99kickbus` is a busybox init script for boards running busybox init.

## Design notes

The daemon is sized for a 128 MB single-board computer, so several limits are deliberate rather than arbitrary.

Bodies cap at 64 KB and the `/recent` buffer caps at 2 MB total, not just at an event count. Subscribers cap at 16, each with a 16-event queue, which bounds consumer memory at roughly 16 MB. A slow consumer loses events, counted in `/health`, instead of stalling the bus.

The webhook URL is public and every request costs an RSA verification, measured at 26us on a desktop CPU and roughly 2ms on a RISC-V C906. So the cheap checks run first: a 5 minute freshness window on the signed timestamp, then a cap of 4 concurrent verifications that answers 503 rather than queuing work. Duplicates answer 200 on purpose, because Kick unsubscribes an app after a day of failed deliveries.

Signature verification follows the documented scheme: RSA-SHA256 over `<message-id>.<timestamp>.<raw body>`, base64 in the `Kick-Event-Signature` header, against Kick's published public key.

A bus that stopped being fed looks exactly like a healthy idle one, and Kick unsubscribes an app after a day of failed deliveries. So `/health` reports `seconds_since_last_event`, null until the first event ever arrives. That is the field worth alerting on.

Reporting that outage is not the same as surviving it, so given credentials the daemon repairs it: it lists the app's subscriptions every thirty minutes and recreates only what is missing, leaving existing ones untouched. `/health` carries `subscriptions`, `subscriptions_checked_at`, and `subscriptions_error` when the last attempt failed.

That key is not pinned. A copy is embedded so the daemon works offline, but at startup and every six hours it fetches the key Kick publishes and switches if it changed. Pinning would turn a key rotation into a silent outage: every webhook would fail verification and Kick unsubscribes an app after a day of failures. `/health` reports `key_source` as `published` or `embedded`, which is the first thing to check when signatures start failing. Use `-offline` to skip the fetch entirely.

## Related projects

- [kick-core](https://github.com/Pkkls/kick-core), the browser-side counterpart: Kick's realtime gateway from an extension service worker
- [kick-chat-translator](https://github.com/Pkkls/kick-chat-translator), live chat translation, on the Chrome Web Store and Mozilla Add-ons
- [kick-ad-blocker](https://github.com/Pkkls/kick-ad-blocker), blocks Kick's pre-roll and overlay ads
- [kick-drops-miner](https://github.com/Pkkls/kick-drops-miner), Windows app that progresses Kick drop watch-time

## License

MIT
