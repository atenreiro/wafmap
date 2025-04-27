# wafmap/http2_detection.py
import socket
from urllib.parse import urlparse
from typing import Dict, Optional
import h2.connection
import h2.config

def detect_http2(url: str, port: int = 443, timeout: float = 5.0, debug: bool = False) -> Dict:
    """
    Detect HTTP/2 support and gather debug information
    Returns:
        {
            'supported': bool,
            'debug_info': dict (if debug=True)
        }
    """
    result = {
        'supported': False,
        'debug_info': {
            'url': url,
            'port': port,
            'error': None,
            'connection_steps': []
        } if debug else None
    }

    try:
        # Extract hostname
        hostname = urlparse(url).hostname or url.split('//')[-1].split('/')[0]
        
        # Create TCP connection
        sock = socket.create_connection((hostname, port), timeout=timeout)
        if debug:
            result['debug_info']['connection_steps'].append('TCP connection established')

        # Set up HTTP/2 connection
        config = h2.config.H2Configuration(client_side=True)
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())
        if debug:
            result['debug_info']['connection_steps'].append('HTTP/2 preface sent')

        # Check server response
        data = sock.recv(1024)
        if debug:
            result['debug_info']['connection_steps'].append(f'Received {len(data)} bytes')

        if data.startswith(b'HTTP/2.0') or b'HTTP/2' in data[:100]:
            result['supported'] = True
            if debug:
                result['debug_info']['frames'] = [
                    str(event) for event in conn.receive_data(data)
                ]

    except Exception as e:
        if debug:
            result['debug_info']['error'] = str(e)
        return result

    finally:
        sock.close()
    
    return result