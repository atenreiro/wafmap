# wafmap/signature_tests.py

import requests
from typing import Dict, Union, Optional
from wafmap.plugins import load_attack_plugins

DEFAULT_BLOCKED_STATUSES = {400, 401, 403, 406, 429}

def test_signatures(
    url: str,
    session: Optional[requests.Session] = None,
    include_status: bool = False,
    timeout: int = 5,
    plugin_filter: Optional[List[str]] = None
) -> Dict[str, Union[bool, Dict[str, Union[bool, int]]]]:
    """
    Execute payloads from attack plugins and return test results.
    
    Args:
        url: Target URL to test
        session: Optional existing requests Session
        include_status: Whether to include HTTP status in results
        timeout: Request timeout in seconds
        plugin_filter: List of plugin names to test (None for all)
        
    Returns:
        Dict mapping payload_id -> bool (blocked) or 
        payload_id -> {'blocked': bool, 'http_status': int}
    """
    session = session or requests.Session()
    results = {}
    
    for plugin in load_attack_plugins() or []:
        if not plugin:
            continue
            
        plugin_name = plugin.get('name')
        if not plugin_name or (plugin_filter and plugin_name not in plugin_filter):
            continue

        method = plugin.get('request', {}).get('method', 'GET').upper()
        param = plugin.get('request', {}).get('param')
        blocked_statuses = set(plugin.get('match_criteria', {}).get('blocked_statuses', [])) | DEFAULT_BLOCKED_STATUSES

        for payload in plugin.get('payloads', []):
            pid = payload.get('id')
            if not pid:
                continue
                
            data = payload.get('payload', '')
            
            try:
                if method == 'GET':
                    if param:
                        resp = session.get(url, params={param: data}, timeout=timeout)
                    else:
                        resp = session.get(f"{url.rstrip('/')}/{data.lstrip('/')}", timeout=timeout)
                else:
                    if param:
                        resp = session.post(url, data={param: data}, timeout=timeout)
                    else:
                        continue

                blocked = resp.status_code in blocked_statuses
                if include_status:
                    results[f"{plugin_name}_{pid}"] = {
                        'blocked': blocked,
                        'http_status': resp.status_code,
                        'plugin': plugin_name
                    }
                else:
                    results[f"{plugin_name}_{pid}"] = blocked
                    
            except requests.RequestException:
                if include_status:
                    results[f"{plugin_name}_{pid}"] = {
                        'blocked': False,
                        'http_status': None,
                        'plugin': plugin_name,
                        'error': True
                    }
                else:
                    results[f"{plugin_name}_{pid}"] = False

    return results