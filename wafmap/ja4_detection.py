# wafmap/ja4_detection.py
import socket
import json
from urllib.parse import urlparse
from typing import Tuple, Optional, Dict
from scapy.layers.inet import TCP, IP
from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
from scapy.sendrecv import sniff

def extract_hostname(url: str) -> str:
    """Extract hostname from URL with debug info"""
    parsed = urlparse(url)
    if not parsed.netloc:
        return url.split('/')[0].split(':')[0]
    return parsed.netloc.split(':')[0]

def capture_ja4(url: str, port: int = 443, timeout: int = 5, debug: bool = False) -> Tuple[Optional[str], Optional[str], Optional[Dict]]:
    """
    Capture JA4 fingerprints with debug capabilities
    Returns: (client_ja4, server_ja4, debug_info)
    """
    debug_info = {
        'target': url,
        'dns_resolution': None,
        'packets_captured': 0,
        'tls_handshakes': 0,
        'raw_packets': [] if debug else None
    }
    
    try:
        hostname = extract_hostname(url)
        debug_info['hostname'] = hostname
        
        # DNS resolution
        target_ip = socket.gethostbyname(hostname)
        debug_info['dns_resolution'] = target_ip
        
        results = {"client": None, "server": None}
        
        def packet_callback(pkt):
            debug_info['packets_captured'] += 1
            
            if pkt.haslayer(TLS):
                debug_info['tls_handshakes'] += 1
                
                if debug:
                    raw = {
                        'timestamp': pkt.time,
                        'layers': list(pkt.layers()),
                        'summary': pkt.summary()
                    }
                    debug_info['raw_packets'].append(raw)
                
                if TCP in pkt and pkt[TCP].dport == port:
                    if pkt.haslayer(TLSClientHello):
                        try:
                            results["client"] = pkt[TLS].ja4_fingerprint
                            if debug:
                                debug_info['client_hello'] = {
                                    'cipher_suites': pkt[TLSClientHello].cipher_suites,
                                    'extensions': [ext.type for ext in pkt[TLSClientHello].extensions]
                                }
                        except AttributeError:
                            pass
                
                elif TCP in pkt and pkt[TCP].sport == port:
                    if pkt.haslayer(TLSServerHello):
                        try:
                            results["server"] = pkt[TLS].ja4s_fingerprint
                            if debug:
                                debug_info['server_hello'] = {
                                    'cipher_suite': pkt[TLSServerHello].cipher_suite,
                                    'compression': pkt[TLSServerHello].compression,
                                    'extensions': [ext.type for ext in pkt[TLSServerHello].extensions]
                                }
                        except AttributeError:
                            pass
        
        sniff(filter=f"host {target_ip} and port {port}", 
              prn=packet_callback, 
              timeout=timeout,
              store=False)
        
        return results["client"], results["server"], debug_info
    
    except Exception as e:
        debug_info['error'] = str(e)
        return None, None, debug_info