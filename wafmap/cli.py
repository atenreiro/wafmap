"""WAFMap CLI tool for WAF/CDN detection and testing."""
import json
import random
from datetime import datetime
from importlib import resources, metadata
from typing import List, Set, Optional

import click
import requests
from prettytable import PrettyTable, FRAME

from .discovery import detect_vendors
from .rate_limiter import test_rate_limiter
from .report import generate_html_report, generate_json_report
from wafmap.plugins import load_detection_plugins, load_attack_plugins


# Constants
__version__ = metadata.version("wafmap")
DEFAULT_USER_AGENT = f"wafmap-{__version__}"
BLOCKED_STATUS_CODES = {400, 401, 403, 429}
DEFAULT_TIMEOUT = 5
MAX_PAYLOAD_DISPLAY_LENGTH = 32

# Global session for connection pooling
_session = None


def get_session() -> requests.Session:
    """Get or create a shared requests session."""
    global _session
    if _session is None:
        _session = requests.Session()
    return _session


def load_user_agents() -> List[str]:
    """Load a flattened list of User-Agents from config/useragents.json."""
    with resources.open_text("wafmap.config", "useragents.json") as fh:
        data = json.load(fh)
    return [ua for group in data.values() for ua in group]


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme; default to HTTPS if missing."""
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    return url


def prepare_results_table(verbose: bool = False) -> PrettyTable:
    """Initialize and configure the results table."""
    fields = ["Category", "ID", "Payload", "Status"]
    if verbose:
        fields.append("HTTP Code")
    
    table = PrettyTable(fields)
    table.align = "l"
    table.border = True
    table.junction_char = "+"
    table.vertical_char = "|"
    table.horizontal_char = "-"
    table.hrules = FRAME  # Only top and bottom borders
    table.max_width = 80  # Prevent overflow
    
    if verbose:
        table.align["HTTP Code"] = "c"
    
    return table


def get_user_agent(user_agent: Optional[str]) -> str:
    """Resolve the User-Agent string based on input."""
    if user_agent is None:
        return DEFAULT_USER_AGENT
    if user_agent.lower() == "random":
        uas = load_user_agents()
        return random.choice(uas) if uas else DEFAULT_USER_AGENT
    return user_agent


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "--version", "-V", message="wafmap %(version)s")
def cli():
    """wafmap: discover WAF/CDN defenses and test for signature or rate-limit gaps."""
    pass


def _handle_discover_output(url: str, vendors: List[str], headers: dict,
                          verbose: bool, debug: bool, user_agent: str,
                          html: Optional[str], json: Optional[str]):
    """Handle output generation for discover command."""
    result = {
        "command": "discover",
        "target": url,
        "detected": vendors,
        "timestamp": datetime.now().isoformat(),
        "debug": {
            "headers": dict(headers) if debug else None,
            "user_agent": user_agent
        } if (debug or verbose) else None
    }

    # Console output
    click.secho(
        f"CDN/WAF Detected: {', '.join(vendors)}" if vendors 
        else "CDN/WAF Detected: Not detected",
        fg="green" if vendors else "yellow"
    )

    if verbose and vendors:
        click.echo("\nMatched Headers:")
        lower_map = {k.lower(): (k, v) for k, v in headers.items()}
        for vendor in vendors:
            plugin = next(
                (p for p in load_detection_plugins() or [] 
                 if p and p.get('name') == vendor), 
                {}
            )
            for pat in plugin.get('patterns', []):
                key = pat.get('header', '').lower()
                entry = lower_map.get(key)
                if not entry:
                    continue
                orig, val = entry
                if 'contains' in pat and pat['contains'].lower() in val.lower():
                    click.echo(f"  [{vendor}] {orig}: {val}")
                    break
                elif 'contains' not in pat:
                    click.echo(f"  [{vendor}] {orig}: {val}")
                    break

    # Generate reports if requested
    if html:
        generate_html_report(result, html)
    if json:
        generate_json_report(result, json)


@cli.command()
@click.argument("url")
@click.option("-v", "--verbose", is_flag=True, 
             help="Show verbose details (matched headers).")
@click.option("-d", "--debug", is_flag=True, 
             help="Show raw HTTP response headers for debugging.")
@click.option("-u", "--user-agent", "user_agent", metavar="UA", default=None,
             help="Override User-Agent header. Use 'random' to pick a random UA.")
@click.option("--html", help="Export results to HTML file")
@click.option("--json", help="Export results to JSON file")
def discover(url: str, verbose: bool, debug: bool, 
            user_agent: Optional[str], html: Optional[str], json: Optional[str]):
    """Discover which WAFs/CDNs a site is using by header heuristics."""
    url = normalize_url(url)
    session = get_session()
    final_user_agent = get_user_agent(user_agent)
    session.headers.update({"User-Agent": final_user_agent})

    try:
        resp = session.head(url, allow_redirects=True, timeout=DEFAULT_TIMEOUT)
        headers = resp.headers

        if debug:
            click.echo("\n[DEBUG] Raw Response Headers:")
            for h, v in headers.items():
                if h.lower() not in {"authorization", "cookie"}:
                    click.echo(f"  {h}: {v}")

        vendors = detect_vendors(url, session=session)
        _handle_discover_output(
            url, vendors, headers, verbose, debug, final_user_agent, html, json
        )

    except requests.RequestException as e:
        error_data = {
            "command": "discover",
            "target": url,
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }
        click.secho(f"[ERROR] Failed to retrieve headers: {e}", fg="red", err=True)
        
        if html:
            generate_html_report(error_data, html)
        if json:
            generate_json_report(error_data, json)


def _execute_test_payload(session: requests.Session, url: str, plugin: dict, 
                         pl: dict, blocked_statuses: Set[int]) -> List:
    """Execute a single test payload and return results."""
    method = plugin.get('request', {}).get('method', 'GET').upper()
    param = plugin.get('request', {}).get('param')
    pid = pl.get('id', '')
    raw = pl.get('payload', '')
    trimmed = (raw if len(raw) <= MAX_PAYLOAD_DISPLAY_LENGTH 
               else raw[:MAX_PAYLOAD_DISPLAY_LENGTH] + '...')

    try:
        if method == 'GET':
            if param:
                resp = session.get(url, params={param: raw}, timeout=DEFAULT_TIMEOUT)
            else:
                target = url.rstrip('/') + '/' + raw.lstrip('/')
                resp = session.get(target, timeout=DEFAULT_TIMEOUT)
        else:
            if param:
                resp = session.post(url, data={param: raw}, timeout=DEFAULT_TIMEOUT)
            else:
                return []

        code = resp.status_code
        if code in blocked_statuses:
            status_text = click.style("BLOCKED", fg="red")
        elif 500 <= code < 600:
            status_text = click.style("ERROR", fg="yellow")
        else:
            status_text = click.style("PASSED", fg="green")
    except requests.RequestException:
        code = None
        status_text = click.style("ERROR", fg="yellow")

    return [plugin.get('name', ''), pid, trimmed, status_text, 
            code if code is not None else 'ERR']


@cli.command()
@click.argument("url")
@click.option("-v", "--verbose", is_flag=True, 
             help="Show HTTP status codes in output.")
@click.option("-u", "--user-agent", "user_agent", metavar="UA", default=None,
             help="Override User-Agent header. Use 'random' to pick a random UA.")
@click.option("--only", "only_plugins", metavar="CATEGORIES", default="",
             help="Only run specific plugin categories (comma-separated)")
@click.option("--sort-by", "sort_column", default="category",
             type=click.Choice(["category", "id", "status", "code"], 
                             case_sensitive=False),
             help="Sort results by column")
def test(url: str, verbose: bool, user_agent: Optional[str], 
        only_plugins: str, sort_column: str):
    """Run signature-gap tests against a site."""
    url = normalize_url(url)
    session = get_session()
    session.headers.update({"User-Agent": get_user_agent(user_agent)})

    table = prepare_results_table(verbose)
    plugins = load_attack_plugins() or []
    
    if only_plugins:
        selected_categories = [c.strip().upper() for c in only_plugins.split(",")]
        plugins = [p for p in plugins if p.get('name', '').upper() in selected_categories]

    if not plugins:
        click.secho("[ERROR] No matching attack plugins found.", fg="red")
        return

    click.clear()
    click.echo(f"Signature-gap Test Results for {url}:\n")
    click.echo(table)

    with click.progressbar(plugins, label="Testing plugins") as bar:
        for plugin in bar:
            blocked_statuses = (
                set(plugin.get('match_criteria', {}).get('blocked_statuses', [])) | 
                BLOCKED_STATUS_CODES
            )
            
            for pl in plugin.get('payloads', []):
                row = _execute_test_payload(session, url, plugin, pl, blocked_statuses)
                if not row:
                    continue
                    
                if not verbose:
                    row = row[:-1]  # Remove HTTP code if not verbose
                    
                table.add_row(row)
                click.clear()
                click.echo(f"Signature-gap Test Results for {url}:\n")
                click.echo(table.get_string(sortby=sort_column.title()))


@cli.command("rate-limit")
@click.argument("url")
@click.option("--rps", default=10, type=int, help="Requests per second.")
@click.option("--window", default=5, type=int, help="Time window in seconds.")
@click.option("--method", default="GET",
             type=click.Choice(["GET", "POST"], case_sensitive=False),
             help="HTTP method to use.")
def rate_limit(url: str, rps: int, window: int, method: str):
    """Run a rate-limit stress test on a given URL."""
    url = normalize_url(url)
    test_rate_limiter(url=url, method=method, rps=rps, window=window)


def _handle_ja4_output(url: str, port: int, client_fp: Optional[str], 
                      server_fp: Optional[str], debug_info: dict):
    """Handle output for JA4 command."""
    click.echo("\nJA4 Results:")
    click.echo(f"Target: {url}:{port}")
    click.echo(f"Client: {client_fp or 'Not detected'}")
    click.echo(f"Server: {server_fp or 'Not detected'}")
    
    if not debug_info:
        return
        
    click.echo("\nDebug Information:")
    click.echo(f"Resolved IP: {debug_info.get('dns_resolution', 'Failed')}")
    click.echo(f"Packets Captured: {debug_info.get('packets_captured', 0)}")
    click.echo(f"TLS Handshakes: {debug_info.get('tls_handshakes', 0)}")
    
    if 'client_hello' in debug_info:
        click.echo("\nClient Hello Details:")
        click.echo(f"Cipher Suites: {len(debug_info['client_hello']['cipher_suites'])} offered")
        click.echo(f"Extensions: {debug_info['client_hello']['extensions']}")
    
    if 'server_hello' in debug_info:
        click.echo("\nServer Hello Details:")
        click.echo(f"Selected Cipher: {debug_info['server_hello']['cipher_suite']}")
        click.echo(f"Extensions: {debug_info['server_hello']['extensions']}")
    
    if debug_info.get('raw_packets'):
        click.echo("\nPacket Capture Summary:")
        for pkt in debug_info['raw_packets'][:5]:
            click.echo(f"{pkt.get('timestamp')}: {pkt.get('summary')}")


@cli.command()
@click.argument("url")
@click.argument("port", required=False, default=443)
@click.option("--debug", is_flag=True, help="Show detailed debugging information")
def ja4(url: str, port: int, debug: bool):
    """Perform JA4 TLS fingerprinting"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
            
        from wafmap.ja4_detection import capture_ja4
        client_fp, server_fp, debug_info = capture_ja4(url, port, debug=debug)
        _handle_ja4_output(url, port, client_fp, server_fp, debug_info)
        
    except Exception as e:
        click.secho(f"\nError: {str(e)}", fg='red')
        if debug:
            import traceback
            click.echo("\nStack Trace:")
            click.echo(traceback.format_exc())


def _handle_http2_output(url: str, port: int, result: dict):
    """Handle output for HTTP/2 commands."""
    click.echo(f"\nHTTP/2 Support: {'YES' if result['supported'] else 'NO'}")
    
    if not result.get('debug_info'):
        return
        
    click.echo("\nDebug Information:")
    click.echo(f"Target: {url}:{port}")
    for step in result['debug_info'].get('connection_steps', []):
        click.echo(f"- {step}")
        
    if 'frames' in result['debug_info']:
        click.echo("\nHTTP/2 Frames:")
        for frame in result['debug_info']['frames'][:5]:
            click.echo(f"  {frame}")
            
    if result['debug_info'].get('error'):
        click.secho(f"Error: {result['debug_info']['error']}", fg='red')


@cli.command()
@click.argument("url")
@click.option("--port", default=443, help="Port to test (default: 443)")
@click.option("--debug", is_flag=True, help="Show debug information")
def http2(url: str, port: int, debug: bool):
    """Check if target supports HTTP/2"""
    try:
        from wafmap.http2_detection import detect_http2
        result = detect_http2(url, port=port, debug=debug)
        _handle_http2_output(url, port, result)
                
    except ImportError:
        click.secho("Error: h2 package required. Install with: pip install h2", fg='red')
    except Exception as e:
        click.secho(f"Error: {str(e)}", fg='red')


def _handle_http2_fingerprint_output(url: str, port: int, result: dict):
    """Handle output for HTTP/2 fingerprinting."""
    if result['waf']:
        click.secho(f"\nDetected WAF: {result['waf'].upper()}", fg='green')
    else:
        click.echo("\nNo known WAF detected via HTTP/2")
    
    if not result.get('debug'):
        return
        
    click.echo("\nDebug Information:")
    click.echo(f"Target: {url}:{port}")
    click.echo("\nFrame Sequence:")
    for i, frame in enumerate(result['debug']['frames'][:5]):
        click.echo(f"{i+1}. {frame}")
    
    if result['debug']['errors']:
        click.secho("\nErrors:", fg='yellow')
        for error in result['debug']['errors']:
            click.echo(f"- {error}")


@cli.command()
@click.argument("url")
@click.option("--port", default=443, help="Port to test (default: 443)")
@click.option("--debug", is_flag=True, help="Show debug information")
def http2fingerprint(url: str, port: int, debug: bool):
    """Detect WAF using HTTP/2 fingerprinting"""
    try:
        from wafmap.http2_fingerprinting import fingerprint_http2
        result = fingerprint_http2(url, port=port, debug=debug)
        _handle_http2_fingerprint_output(url, port, result)
                    
    except ImportError:
        click.secho("Error: Required packages not found", fg='red')
        click.echo("Install with: pip install h2 hyperframe")


if __name__ == "__main__":
    cli()