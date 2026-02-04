"""
Service Detection Module
Provides banner grabbing and service identification
"""
import socket
import re
from typing import Optional


# Service signatures for identification
SERVICE_SIGNATURES = {
    'SSH': [b'SSH-', b'OpenSSH'],
    'HTTP': [b'HTTP/', b'<!DOCTYPE', b'<html', b'<HTML'],
    'FTP': [b'220', b'FTP'],
    'SMTP': [b'220', b'ESMTP', b'SMTP'],
    'POP3': [b'+OK'],
    'IMAP': [b'* OK', b'IMAP'],
    'MySQL': [b'mysql', b'\x00\x00\x00\x0a'],
    'Redis': [b'-ERR', b'+PONG', b'redis'],
    'MongoDB': [b'MongoDB'],
    'PostgreSQL': [b'PostgreSQL'],
}


def grab_banner(host: str, port: int, timeout: float = 3.0) -> dict:
    """
    Attempt to grab the service banner from a port
    
    Args:
        host: Target IP address or hostname
        port: Port number
        timeout: Connection timeout
        
    Returns:
        dict with keys: port, banner, service, error
    """
    result = {
        'host': host,
        'port': port,
        'banner': None,
        'service': None,
        'error': None
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # Try to receive banner
        try:
            # Some services send banner immediately
            banner = sock.recv(1024)
            result['banner'] = banner.decode('utf-8', errors='ignore').strip()
        except socket.timeout:
            # Try sending a probe for HTTP
            if port in [80, 8080, 443, 8443]:
                sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                try:
                    banner = sock.recv(1024)
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                except:
                    pass
            else:
                # Try generic probe
                sock.send(b'\r\n')
                try:
                    banner = sock.recv(1024)
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
                except:
                    pass
        
        sock.close()
        
        # Identify service from banner
        if result['banner']:
            result['service'] = identify_service(result['banner'].encode())
            
    except socket.timeout:
        result['error'] = 'Connection timed out'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def identify_service(banner: bytes) -> str:
    """
    Identify service from banner content
    
    Args:
        banner: Raw banner bytes
        
    Returns:
        Service name or 'Unknown'
    """
    banner_upper = banner.upper()
    
    for service, signatures in SERVICE_SIGNATURES.items():
        for sig in signatures:
            if sig.upper() in banner_upper:
                return service
    
    return 'Unknown'


def detect_service(host: str, port: int, timeout: float = 3.0) -> dict:
    """
    Detect service running on a port
    
    Args:
        host: Target IP address or hostname
        port: Port number
        timeout: Connection timeout
        
    Returns:
        dict with service detection results
    """
    return grab_banner(host, port, timeout)


def get_http_headers(url: str, timeout: float = 5.0) -> dict:
    """
    Get HTTP headers from a URL
    
    Args:
        url: Target URL (with or without http://)
        timeout: Request timeout
        
    Returns:
        dict with headers info
    """
    result = {
        'url': url,
        'status_code': None,
        'headers': {},
        'server': None,
        'error': None
    }
    
    try:
        import requests
        
        # Add http:// if not present
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url
        
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        result['status_code'] = response.status_code
        result['headers'] = dict(response.headers)
        result['server'] = response.headers.get('Server', 'Unknown')
        
    except ImportError:
        # Fallback to socket-based HTTP request
        try:
            # Parse URL
            if url.startswith('http://'):
                url = url[7:]
            elif url.startswith('https://'):
                result['error'] = 'HTTPS not supported without requests library'
                return result
            
            host = url.split('/')[0]
            path = '/' + '/'.join(url.split('/')[1:]) if '/' in url else '/'
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, 80))
            
            request = f'HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
            sock.send(request.encode())
            
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()
            
            # Parse response
            lines = response.split('\r\n')
            if lines:
                status_match = re.search(r'HTTP/\d\.\d (\d+)', lines[0])
                if status_match:
                    result['status_code'] = int(status_match.group(1))
                
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        result['headers'][key.strip()] = value.strip()
                        if key.lower() == 'server':
                            result['server'] = value.strip()
                            
        except Exception as e:
            result['error'] = str(e)
            
    except Exception as e:
        result['error'] = str(e)
    
    return result
