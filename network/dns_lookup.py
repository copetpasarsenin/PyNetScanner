"""
DNS Lookup Module
Provides DNS resolution and reverse lookup functionality
"""
import socket
from typing import List, Optional


def resolve_hostname(hostname: str) -> dict:
    """
    Resolve a hostname to IP address(es)
    
    Args:
        hostname: Domain name to resolve
        
    Returns:
        dict with keys: hostname, ip_addresses, error
    """
    result = {
        'hostname': hostname,
        'ip_addresses': [],
        'ipv4': [],
        'ipv6': [],
        'error': None
    }
    
    try:
        # Get all address info (IPv4 and IPv6)
        addr_info = socket.getaddrinfo(hostname, None)
        
        seen = set()
        for info in addr_info:
            family, _, _, _, sockaddr = info
            ip = sockaddr[0]
            
            if ip not in seen:
                seen.add(ip)
                result['ip_addresses'].append(ip)
                
                if family == socket.AF_INET:
                    result['ipv4'].append(ip)
                elif family == socket.AF_INET6:
                    result['ipv6'].append(ip)
                    
    except socket.gaierror as e:
        result['error'] = f'DNS resolution failed: {e}'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def reverse_lookup(ip_address: str) -> dict:
    """
    Perform reverse DNS lookup (IP to hostname)
    
    Args:
        ip_address: IP address to lookup
        
    Returns:
        dict with keys: ip_address, hostname, aliases, error
    """
    result = {
        'ip_address': ip_address,
        'hostname': None,
        'aliases': [],
        'error': None
    }
    
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip_address)
        result['hostname'] = hostname
        result['aliases'] = aliases
        
    except socket.herror as e:
        result['error'] = f'Reverse lookup failed: {e}'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_fqdn(hostname: str) -> str:
    """
    Get fully qualified domain name
    
    Args:
        hostname: Hostname to lookup
        
    Returns:
        Fully qualified domain name or original hostname
    """
    try:
        return socket.getfqdn(hostname)
    except Exception:
        return hostname


def validate_ip(ip_string: str) -> dict:
    """
    Validate if a string is a valid IP address
    
    Args:
        ip_string: String to validate
        
    Returns:
        dict with keys: valid, ip_version, error
    """
    result = {
        'valid': False,
        'ip_version': None,
        'error': None
    }
    
    # Try IPv4
    try:
        socket.inet_pton(socket.AF_INET, ip_string)
        result['valid'] = True
        result['ip_version'] = 4
        return result
    except socket.error:
        pass
    
    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, ip_string)
        result['valid'] = True
        result['ip_version'] = 6
        return result
    except socket.error:
        pass
    
    result['error'] = 'Not a valid IP address'
    return result


def dns_lookup_all(target: str) -> dict:
    """
    Comprehensive DNS lookup - determines if target is IP or hostname
    and performs appropriate lookup
    
    Args:
        target: IP address or hostname
        
    Returns:
        Combined results from forward or reverse lookup
    """
    ip_check = validate_ip(target)
    
    if ip_check['valid']:
        # It's an IP address, do reverse lookup
        reverse = reverse_lookup(target)
        return {
            'type': 'reverse',
            'input': target,
            'result': reverse
        }
    else:
        # It's a hostname, do forward lookup
        forward = resolve_hostname(target)
        return {
            'type': 'forward',
            'input': target,
            'result': forward
        }
