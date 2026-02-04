"""
Port Scanner Module
Provides TCP port scanning functionality
"""
import socket
from typing import List, Callable, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed


# Well-known ports and their services
COMMON_PORTS = {
    20: 'FTP-Data',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Scan a single port on the target host
    
    Args:
        host: Target IP address or hostname
        port: Port number to scan
        timeout: Connection timeout in seconds
        
    Returns:
        dict with keys: port, status, service, error
    """
    result = {
        'port': port,
        'status': 'closed',
        'service': COMMON_PORTS.get(port, 'Unknown'),
        'error': None
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        connection_result = sock.connect_ex((host, port))
        
        if connection_result == 0:
            result['status'] = 'open'
        else:
            result['status'] = 'closed'
            
        sock.close()
        
    except socket.timeout:
        result['status'] = 'filtered'
        result['error'] = 'Connection timed out'
    except socket.gaierror:
        result['status'] = 'error'
        result['error'] = 'Could not resolve hostname'
    except Exception as e:
        result['status'] = 'error'
        result['error'] = str(e)
    
    return result


def scan_port_range(
    host: str, 
    start_port: int, 
    end_port: int, 
    callback: Optional[Callable] = None,
    timeout: float = 1.0,
    max_threads: int = 100
) -> List[dict]:
    """
    Scan a range of ports on the target host using threading
    
    Args:
        host: Target IP address or hostname
        start_port: Starting port number
        end_port: Ending port number
        callback: Optional callback function(port, total, result)
        timeout: Connection timeout per port
        max_threads: Maximum concurrent threads
        
    Returns:
        List of scan results for all ports
    """
    results = []
    total_ports = end_port - start_port + 1
    scanned = 0
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all port scans
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port 
            for port in range(start_port, end_port + 1)
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                results.append(result)
                scanned += 1
                
                if callback:
                    callback(scanned, total_ports, result)
                    
            except Exception as e:
                results.append({
                    'port': port,
                    'status': 'error',
                    'service': COMMON_PORTS.get(port, 'Unknown'),
                    'error': str(e)
                })
                scanned += 1
    
    # Sort by port number
    results.sort(key=lambda x: x['port'])
    return results


def scan_common_ports(
    host: str, 
    callback: Optional[Callable] = None,
    timeout: float = 1.0
) -> List[dict]:
    """
    Scan common/well-known ports on the target host
    
    Args:
        host: Target IP address or hostname
        callback: Optional callback function
        timeout: Connection timeout per port
        
    Returns:
        List of scan results for common ports
    """
    results = []
    ports = list(COMMON_PORTS.keys())
    total = len(ports)
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port 
            for port in ports
        }
        
        scanned = 0
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                results.append(result)
                scanned += 1
                
                if callback:
                    callback(scanned, total, result)
                    
            except Exception as e:
                results.append({
                    'port': port,
                    'status': 'error',
                    'service': COMMON_PORTS.get(port, 'Unknown'),
                    'error': str(e)
                })
                scanned += 1
    
    results.sort(key=lambda x: x['port'])
    return results


def get_open_ports(results: List[dict]) -> List[dict]:
    """Filter and return only open ports from scan results"""
    return [r for r in results if r['status'] == 'open']
