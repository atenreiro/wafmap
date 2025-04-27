# ---------- wafmap/rate_limiter.py ----------
import time
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import click


def test_rate_limiter(
    url: str,
    method: str = "GET",
    rps: int = 10,
    window: int = 5
) -> None:
    """
    Test rate-limiting behavior by sending multiple requests over a time window.

    Args:
        url (str): Target URL to test.
        method (str): HTTP method to use (GET or POST).
        rps (int): Requests per second.
        window (int): Duration of test window in seconds.
    """
    total_requests = rps * window
    interval = 1 / rps
    statuses: dict[str, int] = defaultdict(int)
    session = requests.Session()

    def send_request() -> str:
        try:
            if method.upper() == "POST":
                resp = session.post(url, timeout=5)
            else:
                resp = session.get(url, timeout=5)
            code = str(resp.status_code)
            statuses[code] += 1
            return code
        except requests.RequestException:
            statuses["ERR"] += 1
            return "ERR"

    def print_live_table() -> None:
        total = sum(statuses.values())
        click.clear()
        click.secho(
            f"\n→ Sending {total_requests} requests to {url} "
            f"({rps} RPS for {window} seconds)...\n",
            fg="cyan",
        )
        click.echo("  Status Code      Count     Percent")
        click.echo("  ----------------------------------")
        for code, count in sorted(
            statuses.items(),
            key=lambda x: int(x[0]) if x[0].isdigit() else float("inf"),
        ):
            percent = (count / total) * 100 if total else 0
            if code.startswith("2"):
                color = "green"
            elif code.startswith(("4", "5")):
                color = "red"
            else:
                color = "yellow"
            click.secho(
                f"  {code:<17}{count:<10}{percent:5.1f}%", fg=color
            )

    start = time.time()
    with ThreadPoolExecutor(max_workers=rps * 2) as executor:
        futures = []
        for _ in range(total_requests):
            futures.append(executor.submit(send_request))
            time.sleep(interval)
            print_live_table()

        for future in as_completed(futures):
            future.result()

    duration = time.time() - start
    click.secho(f"\nTotal time: {duration:.2f} seconds", fg="magenta")
