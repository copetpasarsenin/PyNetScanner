"""
Host Discovery Module
Scans local network to find active hosts
"""
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Optional
import re
import subprocess
import platform


def get_local_network_range() -> Optional[str]:
    """
    Get the local network IP range (e.g., 192.168.1.0/24)
    
    Returns:
        Network range in CIDR notation or None
    """
    try:
        # Get local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Assume /24 subnet (most common for home/office)
        parts = local_ip.split('.')
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return network
    except Exception:
        return None


def get_ip_range_from_cidr(cidr: str) -> List[str]:
    """
    Generate list of IPs from CIDR notation
    
    Args:
        cidr: Network in CIDR format (e.g., 192.168.1.0/24)
        
    Returns:
        List of IP addresses
    """
    try:
        network, prefix = cidr.split('/')
        prefix = int(prefix)
        
        # Parse network address
        parts = [int(p) for p in network.split('.')]
        base = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        
        # Calculate number of hosts
        host_bits = 32 - prefix
        num_hosts = (1 << host_bits) - 2  # Exclude network and broadcast
        
        # Limit to /24 to avoid too many hosts
        if num_hosts > 254:
            num_hosts = 254
        
        ips = []
        for i in range(1, num_hosts + 1):
            ip_int = base + i
            ip = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
            ips.append(ip)
        
        return ips
    except Exception:
        return []


def ping_host_quick(ip: str, timeout: int = 1) -> bool:
    """
    Quick ping to check if host is up
    
    Args:
        ip: IP address to ping
        timeout: Timeout in seconds
        
    Returns:
        True if host responds, False otherwise
    """
    try:
        system = platform.system().lower()
        if system == 'windows':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip]
            creationflags = subprocess.CREATE_NO_WINDOW
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip]
            creationflags = 0
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
            creationflags=creationflags
        )
        return result.returncode == 0
    except Exception:
        return False


def get_hostname_for_ip(ip: str) -> Optional[str]:
    """Get hostname for an IP address"""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def get_mac_from_arp(ip: str) -> Optional[str]:
    """Get MAC address from ARP table"""
    try:
        system = platform.system().lower()
        if system == 'windows':
            result = subprocess.run(
                ['arp', '-a', ip],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            # Parse Windows ARP output
            match = re.search(r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})', result.stdout)
            if match:
                return match.group(1).replace('-', ':').upper()
        else:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True,
                text=True
            )
            match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', result.stdout)
            if match:
                return match.group(1).upper()
    except Exception:
        pass
    return None


def discover_hosts(
    network_range: str = None,
    callback: Optional[Callable] = None,
    max_threads: int = 50
) -> dict:
    """
    Discover active hosts on the network
    
    Args:
        network_range: Network in CIDR format (auto-detect if None)
        callback: Optional callback(current, total, host_info)
        max_threads: Maximum concurrent threads
        
    Returns:
        dict with discovered hosts
    """
    result = {
        'network': network_range,
        'hosts': [],
        'total_scanned': 0,
        'total_found': 0,
        'error': None
    }
    
    try:
        # Auto-detect network if not provided
        if network_range is None:
            network_range = get_local_network_range()
            if network_range is None:
                result['error'] = 'Could not detect local network'
                return result
        
        result['network'] = network_range
        
        # Get list of IPs to scan
        ip_list = get_ip_range_from_cidr(network_range)
        if not ip_list:
            result['error'] = 'Invalid network range'
            return result
        
        total = len(ip_list)
        result['total_scanned'] = total
        scanned = 0
        
        # Scan hosts using thread pool
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {executor.submit(ping_host_quick, ip): ip for ip in ip_list}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                scanned += 1
                
                try:
                    is_up = future.result()
                    
                    if is_up:
                        host_info = {
                            'ip': ip,
                            'hostname': get_hostname_for_ip(ip),
                            'mac': get_mac_from_arp(ip),
                            'status': 'up'
                        }
                        result['hosts'].append(host_info)
                        result['total_found'] += 1
                    
                    if callback:
                        callback(scanned, total, {'ip': ip, 'is_up': is_up})
                        
                except Exception:
                    pass
        
        # Sort by IP
        result['hosts'].sort(key=lambda x: [int(p) for p in x['ip'].split('.')])
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def quick_discover(network_range: str = None) -> List[str]:
    """
    Quick discovery returning only IP addresses
    
    Args:
        network_range: Network in CIDR format
        
    Returns:
        List of active IP addresses
    """
    result = discover_hosts(network_range)
    return [h['ip'] for h in result['hosts']]
