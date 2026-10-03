"""
DNS Query Collector — Captures DNS queries from Windows DNS Client cache.

Detects:
- C2 communication (suspicious domains)
- DNS tunneling (long/encoded domains)
- DGA (Domain Generation Algorithms)
- Data exfiltration via DNS
- Unusual TLDs and query patterns

UNSW-NB15 Compatibility: DNS queries are critical network features.
"""

import subprocess
import re
import socket
import getpass
import sys
import os
from datetime import datetime
from typing import List

import logging
import platform

from tools.collectors.schema import StandardEvent, create_event

_log = logging.getLogger("soc.collectors")


def is_suspicious_domain(domain: str) -> tuple[bool, list[str]]:
    """
    Detect suspicious domain patterns.
    
    Returns:
        (is_suspicious, list_of_indicators)
    """
    indicators = []
    domain_lower = domain.lower()
    
    # DGA detection: High entropy, random-looking strings
    if len(domain) > 30:
        indicators.append("long_domain")
    
    # Check for excessive subdomains (DNS tunneling)
    subdomain_count = domain.count('.')
    if subdomain_count > 4:
        indicators.append("excessive_subdomains")
    
    # Check for numeric-heavy domains (suspicious)
    digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    if digit_ratio > 0.3:
        indicators.append("high_digit_ratio")
    
    # Check for unusual TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw']
    if any(domain_lower.endswith(tld) for tld in suspicious_tlds):
        indicators.append("suspicious_tld")
    
    # Check for base64-like patterns (data exfiltration)
    if re.search(r'[A-Za-z0-9+/]{20,}', domain):
        indicators.append("base64_pattern")
    
    # Check for hex patterns
    if re.search(r'[0-9a-f]{16,}', domain_lower):
        indicators.append("hex_pattern")
    
    # Known C2 patterns (simplified)
    c2_keywords = ['admin', 'panel', 'login', 'gate', 'bot', 'cmd', 'shell']
    if any(keyword in domain_lower for keyword in c2_keywords):
        indicators.append("c2_keyword")
    
    return (len(indicators) > 0, indicators)


def parse_dns_cache() -> List[dict]:
    """Windows only (uses `ipconfig /displaydns`, fixed arguments, no shell).
    Parse Windows DNS Client cache using ipconfig /displaydns.
    
    Returns:
        List of DNS cache entries with domain, record type, and data.
    """
    try:
        # Run ipconfig /displaydns
        result = subprocess.run(
            ['ipconfig', '/displaydns'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode != 0:
            _log.info(f"[dns_collector] Error running ipconfig: {result.stderr}")
            return []
        
        output = result.stdout
        entries = []
        current_entry = {}
        
        # Parse the output
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            
            # New record starts with a domain name (no leading spaces in original)
            if line and not line.startswith('Record Name') and ':' not in line and line[0].isalpha():
                # Save previous entry if exists
                if current_entry:
                    entries.append(current_entry)
                current_entry = {'domain': line}
            
            # Record Name
            elif 'Record Name' in line:
                match = re.search(r'Record Name[.\s]*:\s*(.+)', line)
                if match:
                    current_entry['domain'] = match.group(1).strip()
            
            # Record Type
            elif 'Record Type' in line:
                match = re.search(r'Record Type[.\s]*:\s*(\d+)', line)
                if match:
                    record_type_num = match.group(1)
                    # Map common types: 1=A, 5=CNAME, 28=AAAA, 16=TXT
                    type_map = {'1': 'A', '5': 'CNAME', '28': 'AAAA', '16': 'TXT', '12': 'PTR'}
                    current_entry['record_type'] = type_map.get(record_type_num, f'TYPE{record_type_num}')
            
            # Data (IP address or other data)
            elif 'A (Host) Record' in line or 'AAAA Record' in line:
                match = re.search(r':\s*([0-9a-fA-F.:]+)', line)
                if match:
                    current_entry['data'] = match.group(1).strip()
            
            # CNAME Record
            elif 'CNAME Record' in line:
                match = re.search(r':\s*(.+)', line)
                if match:
                    current_entry['data'] = match.group(1).strip()
        
        # Add last entry
        if current_entry:
            entries.append(current_entry)
        
        return entries
    
    except subprocess.TimeoutExpired:
        _log.info("[dns_collector] ipconfig command timed out")
        return []
    except Exception as e:
        _log.info(f"[dns_collector] Error parsing DNS cache: {e}")
        return []


def collect_dns_queries() -> List[StandardEvent]:
    """
    Collect DNS queries from Windows DNS Client cache.
    
    Returns:
        List of StandardEvent objects for DNS queries.
    """
    events = []
    user_id = getpass.getuser()
    device_id = socket.gethostname()
    timestamp = datetime.now().isoformat()
    
    try:
        dns_entries = parse_dns_cache()
        
        if not dns_entries:
            _log.info("[dns_collector] No DNS cache entries found")
            return events
        
        _log.info(f"[dns_collector] Found {len(dns_entries)} DNS cache entries")
        
        for entry in dns_entries:
            domain = entry.get('domain', 'unknown')
            record_type = entry.get('record_type', 'UNKNOWN')
            data = entry.get('data', '')
            
            # Skip empty or invalid entries
            if not domain or domain == 'unknown':
                continue
            
            # Check for suspicious patterns
            is_suspicious, indicators = is_suspicious_domain(domain)
            
            # Determine sensitivity level
            sensitivity = 0
            if is_suspicious:
                if 'c2_keyword' in indicators or 'base64_pattern' in indicators:
                    sensitivity = 3  # Critical
                elif 'suspicious_tld' in indicators or 'hex_pattern' in indicators:
                    sensitivity = 2  # High
                else:
                    sensitivity = 1  # Medium
            
            # Create event
            event = create_event(
                event_type="network_connection",
                event_category="network",
                action="dns_query",
                resource=domain,
                user_id=user_id,
                device_id=device_id,
                source="dns_cache",
                timestamp=timestamp,
                # DNS-specific metadata
                domain=domain,
                dns_record_type=record_type,
                dns_response=data,
                is_suspicious=is_suspicious,
                suspicious_indicators=','.join(indicators) if indicators else None,
                sensitivity_level=sensitivity,
            )
            
            events.append(event)
        
        _log.info(f"[dns_collector] Processed {len(events)} DNS queries")
        return events
    
    except Exception as e:
        _log.info(f"[dns_collector] Error collecting DNS queries: {e}")
        return events
