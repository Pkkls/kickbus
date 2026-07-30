# kickbus

Receives webhooks from the official Kick API, verifies their signature, and fans the events out to local consumers over Server-Sent Events.

One daemon holds the relationship with Kick. Every bot on your network reads from it with a single HTTP request, and none of them needs credentials.

## Why

kick.com's realtime gateway is closed to server clients. Cloudflare rejects both the viewer token endpoint and the websocket handshake, including behind a Chrome TLS fingerprint. The public API solves this from the other direction: Kick pushes events to a URL you control, and an app access token is enough to subscribe to any channel without the streamer being involved.

## Setup

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

## Consuming

```sh
curl -N "http://localhost:8787/events?type=chat.message.sent&broadcaster=123456"
```

Both query parameters are optional. `type` accepts a comma-separated list.

| Endpoint | Purpose |
| --- | --- |
| `POST /kick/webhook` | where Kick delivers events |
| `GET /events` | SSE stream, filtered by `type` and `broadcaster` |
| `GET /recent` | buffered recent events as JSON |
| `GET /health` | uptime, subscriber count, totals, drops |

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

## License

MIT
