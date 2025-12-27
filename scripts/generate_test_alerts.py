import argparse
import datetime
import json
import random
import time
import urllib.error
import urllib.request
import uuid

# Default URL
DEFAULT_URL = "http://localhost:8080/alerts/event"


def generate_alert():
    # Use timezone-aware UTC datetime
    now = (
        datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    )

    alert_id = str(uuid.uuid4())

    alert = {
        "id": alert_id,
        "name": "Pod TEST'api-service-production' lacks memory",
        "status": "firing",
        "lastReceived": now,
        "environment": "production",
        "service": "backend",
        "source": ["prometheus"],
        "message": "The pod 'api-service-production' lacks memory causing high error rate",
        "description": "Due to the lack of memory, the pod 'api-service-production' is experiencing high error rate",
        "severity": "critical",
        "pushed": True,
        "url": f"https://www.keephq.dev?alertId={alert_id}",
        "labels": {
            "pod": "api-service-production",
            "region": "us-east-1",
            "cpu": str(random.randint(80, 99)),
            "memory": f"{random.randint(100, 500)}Mi",
        },
        "ticket_url": "https://www.keephq.dev?enrichedTicketId=456",
        "fingerprint": str(uuid.uuid4()),
    }
    return alert


def send_alert(url, alert, api_key):
    data = json.dumps(alert).encode("utf-8")
    headers = {"Content-Type": "application/json", "x-api-key": api_key}
    req = urllib.request.Request(url, data=data, headers=headers)

    try:
        with urllib.request.urlopen(req) as response:
            status_code = response.getcode()
            if 200 <= status_code < 300:
                print(
                    f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Sent alert {alert['id']}: Success ({status_code})"
                )
            else:
                print(
                    f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Sent alert {alert['id']}: Failed ({status_code})"
                )
    except urllib.error.HTTPError as e:
        print(
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Sent alert {alert['id']}: Failed ({e.code}) - {e.reason}"
        )
    except urllib.error.URLError as e:
        print(
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error sending alert: {e.reason}"
        )
    except Exception as e:
        print(
            f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Error sending alert: {e}"
        )


def main(url, interval, api_key):
    print(f"Starting alert generator. Target: {url}, Interval: {interval}s")
    try:
        while True:
            alert = generate_alert()
            send_alert(url, alert, api_key)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping alert generator.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate random alerts.")
    parser.add_argument("--url", default=DEFAULT_URL, help="Target URL for alerts")
    parser.add_argument(
        "--interval", type=float, default=1.0, help="Interval between alerts in seconds"
    )
    parser.add_argument(
        "--api-key",
        default="dummy-api-key",
        help="API Key to include in the request headers",
    )
    args = parser.parse_args()

    main(args.url, args.interval, args.api_key)
