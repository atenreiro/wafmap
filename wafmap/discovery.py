# wafmap/discovery.py

import requests
from typing import List, Dict, Set
from wafmap.plugins import load_detection_plugins

def detect_waf(headers: Dict[str, str]) -> List[str]:
    """
    Returns a deduplicated list of plugin names whose patterns match:
    - If a pattern has "contains": match only when the substring appears
    - If a pattern has NO "contains": match purely on header existence
    
    Args:
        headers: Dictionary of HTTP headers (case-insensitive matching)
    
    Returns:
        List of detected WAF/CDN vendor names
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    matches: Set[str] = set()

    for plugin in load_detection_plugins() or []:
        if not plugin:
            continue
            
        name = plugin.get("name")
        if not name:
            continue

        for pat in plugin.get("patterns", []):
            header_key = pat.get("header", "").lower()
            if header_key not in lower_headers:
                continue

            val = lower_headers[header_key]
            if "contains" in pat:
                if pat["contains"].lower() in val.lower():
                    matches.add(name)
                    break
            else:
                matches.add(name)
                break

    return sorted(matches)

def detect_vendors(url: str, session: requests.Session = None, timeout: int = 5) -> List[str]:
    """
    Perform an HTTP HEAD to fetch headers, then call detect_waf.
    
    Args:
        url: Target URL to test
        session: Optional existing requests Session
        timeout: Request timeout in seconds
        
    Returns:
        List of detected WAF/CDN vendor names
    """
    session = session or requests.Session()
    
    try:
        resp = session.head(url, allow_redirects=True, timeout=timeout)
        return detect_waf(resp.headers)
    except requests.RequestException:
        return []