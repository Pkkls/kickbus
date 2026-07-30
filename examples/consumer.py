"""Minimal kickbus consumer: reads the SSE stream and prints chat messages.

Standard library only. Reconnects on its own, because a bus restart or a
network blip should not kill a bot.

    python consumer.py --url http://localhost:8787 --broadcaster 123456
"""
import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request


def stream(url, timeout=60):
    """Yields parsed events from an SSE endpoint until the connection drops."""
    req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
    with urllib.request.urlopen(req, timeout=timeout) as res:
        for raw in res:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            # Comments are keepalives, blank lines separate events, and the id
            # and event fields are already inside the JSON payload.
            if not line.startswith("data: "):
                continue
            try:
                yield json.loads(line[6:])
            except json.JSONDecodeError:
                continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8787")
    ap.add_argument("--type", default="chat.message.sent")
    ap.add_argument("--broadcaster", default="")
    args = ap.parse_args()

    query = {k: v for k, v in (("type", args.type), ("broadcaster", args.broadcaster)) if v}
    endpoint = f"{args.url.rstrip('/')}/events?{urllib.parse.urlencode(query)}"

    backoff = 1
    while True:
        try:
            print(f"connecting to {endpoint}", flush=True)
            for event in stream(endpoint):
                backoff = 1
                data = event.get("data") or {}
                sender = (data.get("sender") or {}).get("username", "?")
                print(f"[{event.get('type')}] {sender}: {data.get('content', '')}", flush=True)
            print("stream ended", flush=True)
        except urllib.error.HTTPError as err:
            # 503 means the bus is at its subscriber limit: back off and retry.
            print(f"http {err.code}, retrying in {backoff}s", flush=True)
        except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
            print(f"{err}, retrying in {backoff}s", flush=True)

        time.sleep(backoff)
        backoff = min(30, backoff * 2)


if __name__ == "__main__":
    main()
