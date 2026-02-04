"""
Network Info Module
Provides local network interface information
"""
import socket
import platform
import subprocess
import re
from typing import List, Optional


def get_local_ip() -> str:
    """
    Get the local IP address used for external connections
    
    Returns:
        Local IP address as string
    """
    try:
        # Create a socket and connect to external address
        # This doesn't actually send data, just determines the local interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_hostname() -> str:
    """
    Get the local hostname
    
    Returns:
        Hostname as string
    """
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def get_fqdn() -> str:
    """
    Get the fully qualified domain name
    
    Returns:
        FQDN as string
    """
    try:
        return socket.getfqdn()
    except Exception:
        return get_hostname()


def get_all_interfaces() -> List[dict]:
    """
    Get information about all network interfaces
    
    Returns:
        List of dicts with interface info
    """
    interfaces = []
    
    try:
        import psutil
        
        # Get all network interfaces
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for iface_name, addresses in net_if_addrs.items():
            iface_info = {
                'name': iface_name,
                'ipv4': None,
                'ipv6': None,
                'mac': None,
                'netmask': None,
                'is_up': False,
                'speed': None
            }
            
            # Get addresses
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    iface_info['ipv4'] = addr.address
                    iface_info['netmask'] = addr.netmask
                elif addr.family == socket.AF_INET6:
                    if not addr.address.startswith('fe80'):  # Skip link-local
                        iface_info['ipv6'] = addr.address
                elif addr.family == psutil.AF_LINK:
                    iface_info['mac'] = addr.address
            
            # Get stats
            if iface_name in net_if_stats:
                stats = net_if_stats[iface_name]
                iface_info['is_up'] = stats.isup
                iface_info['speed'] = stats.speed if stats.speed > 0 else None
            
            interfaces.append(iface_info)
            
    except ImportError:
        # Fallback without psutil
        interfaces.append({
            'name': 'Primary',
            'ipv4': get_local_ip(),
            'ipv6': None,
            'mac': None,
            'netmask': None,
            'is_up': True,
            'speed': None
        })
    except Exception as e:
        interfaces.append({
            'name': 'Error',
            'error': str(e)
        })
    
    return interfaces


def get_default_gateway() -> Optional[str]:
    """
    Get the default gateway IP address
    
    Returns:
        Gateway IP address or None
    """
    try:
        import psutil
        
        # Get network connections to find gateway
        # This is a workaround as psutil doesn't directly expose gateway
        system = platform.system().lower()
        
        if system == 'windows':
            # Use ipconfig on Windows
            result = subprocess.run(
                ['ipconfig'], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            # Find default gateway
            match = re.search(r'Default Gateway.*?:\s*([\d.]+)', result.stdout)
            if match:
                return match.group(1)
        else:
            # Use ip route on Linux
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'], 
                capture_output=True, 
                text=True
            )
            match = re.search(r'default via ([\d.]+)', result.stdout)
            if match:
                return match.group(1)
                
    except Exception:
        pass
    
    return None


def get_network_summary() -> dict:
    """
    Get a summary of network information
    
    Returns:
        dict with hostname, local_ip, gateway, interfaces
    """
    return {
        'hostname': get_hostname(),
        'fqdn': get_fqdn(),
        'local_ip': get_local_ip(),
        'gateway': get_default_gateway(),
        'interfaces': get_all_interfaces()
    }
