# wafmap/http2_fingerprinting.py
import socket
import time
import ssl
import traceback  # <-- Add this import
from typing import Dict, Optional, List
from urllib.parse import urlparse
import h2.connection
import h2.config
import h2.events

# Define signatures at module level (not inside function)
HTTP2_WAF_SIGNATURES = {
    'cloudflare': {
        'settings': {'HEADER_TABLE_SIZE': 65536},
        'frame_order': ['SETTINGS', 'WINDOW_UPDATE', 'HEADERS'],
        'error_pattern': 'GOAWAY'
    },
    'akamai': {
        'settings': {'MAX_CONCURRENT_STREAMS': 256},
        'frame_order': ['SETTINGS', 'PING', 'HEADERS'],
        'error_pattern': 'PING'
    }
}

def get_frame_type(event) -> str:
    """Enhanced frame type detection"""
    if isinstance(event, h2.events.Event):
        return event.__class__.__name__.replace("Event", "").upper()
    return 'UNKNOWN'

def fingerprint_http2(url: str, port: int = 443, debug: bool = False) -> Dict:
    """
    Enhanced HTTP/2 fingerprinting with deep debugging
    """
    result = {
        'waf': None,
        'signatures': {},
        'debug': {
            'connection_steps': [],
            'frames': [],
            'raw_data': [],
            'errors': []
        } if debug else None
    }

    sock = None
    try:
        # Extract hostname
        hostname = urlparse(url).hostname or url.split('//')[-1].split('/')[0].split(':')[0]
        if debug:
            result['debug']['connection_steps'].append(f"Resolved hostname: {hostname}")

        # Create TLS connection
        context = ssl.create_default_context()
        context.set_alpn_protocols(['h2', 'http/1.1'])
        
        sock = socket.create_connection((hostname, port), timeout=10)
        if debug:
            result['debug']['connection_steps'].append(f"TCP connection established to {hostname}:{port}")

        tls_sock = context.wrap_socket(sock, server_hostname=hostname)
        if debug:
            result['debug']['connection_steps'].append(
                f"TLS established. Protocol: {tls_sock.version()}, "
                f"ALPN: {tls_sock.selected_alpn_protocol()}"
            )

        # Verify HTTP/2 support
        if tls_sock.selected_alpn_protocol() != 'h2':
            if debug:
                result['debug']['errors'].append({
                    'time': time.time(),
                    'error': 'Server does not support HTTP/2 via ALPN',
                    'protocol': tls_sock.selected_alpn_protocol()
                })
            return result

        # Configure HTTP/2 connection
        config = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        tls_sock.sendall(conn.data_to_send())
        if debug:
            result['debug']['connection_steps'].append("Sent HTTP/2 preface")

        # Receive data
        all_data = b''
        tls_sock.settimeout(10)
        try:
            while True:
                data = tls_sock.recv(65536)
                if not data:
                    break
                all_data += data
                if debug:
                    result['debug']['raw_data'].append({
                        'length': len(data),
                        'hex_sample': data[:32].hex() + '...' if data else None
                    })
        except socket.timeout:
            pass

        if debug:
            result['debug']['connection_steps'].append(f"Received total {len(all_data)} bytes")

        # Process frames
        events = conn.receive_data(all_data)
        frame_sequence = []
        
        for event in events:
            frame_type = get_frame_type(event)
            frame_sequence.append(frame_type)
            
            if debug:
                frame_info = {
                    'type': frame_type,
                    'time': time.time(),
                    'details': str(event)
                }
                if frame_type == 'SETTINGS':
                    frame_info['settings'] = getattr(event, 'changed_settings', {})
                result['debug']['frames'].append(frame_info)

        # Signature matching
        for waf, sig in HTTP2_WAF_SIGNATURES.items():  # <-- Now properly defined
            if any(
                all(
                    i < len(frame_sequence) and
                    frame_sequence[i] == expected
                    for i, expected in enumerate(sig['frame_order'])
                )
                for frame_sequence in [frame_sequence]
            ):
                result['waf'] = waf
                result['signatures'] = sig
                break

    except Exception as e:
        if debug:
            result['debug']['errors'].append({
                'time': time.time(),
                'type': type(e).__name__,
                'error': str(e),
                'stack': traceback.format_exc()  # <-- Now properly imported
            })
    finally:
        if sock:
            sock.close()

    return result