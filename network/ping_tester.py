"""
Ping Tester Module
Provides ICMP ping functionality to check host connectivity
"""
import subprocess
import platform
import re
from typing import Tuple, Optional


def ping_host(host: str, count: int = 4) -> dict:
    """
    Ping a host and return statistics
    
    Args:
        host: IP address or hostname to ping
        count: Number of ping packets to send
        
    Returns:
        dict with keys: success, packets_sent, packets_received, 
        packet_loss, min_ms, avg_ms, max_ms, error
    """
    result = {
        'success': False,
        'host': host,
        'packets_sent': count,
        'packets_received': 0,
        'packet_loss': 100.0,
        'min_ms': None,
        'avg_ms': None,
        'max_ms': None,
        'error': None,
        'raw_output': ''
    }
    
    try:
        # Determine ping command based on OS
        system = platform.system().lower()
        if system == 'windows':
            cmd = ['ping', '-n', str(count), host]
        else:
            cmd = ['ping', '-c', str(count), host]
        
        # Execute ping command
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if system == 'windows' else 0
        )
        stdout, stderr = process.communicate(timeout=30)
        
        result['raw_output'] = stdout
        
        if stderr:
            result['error'] = stderr
            return result
        
        # Parse results based on OS
        if system == 'windows':
            # Parse Windows ping output
            received_match = re.search(r'Received = (\d+)', stdout)
            if received_match:
                result['packets_received'] = int(received_match.group(1))
            
            loss_match = re.search(r'\((\d+)% loss\)', stdout)
            if loss_match:
                result['packet_loss'] = float(loss_match.group(1))
            
            # Parse timing - Windows format: Minimum = Xms, Maximum = Xms, Average = Xms
            time_match = re.search(r'Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms', stdout)
            if time_match:
                result['min_ms'] = float(time_match.group(1))
                result['max_ms'] = float(time_match.group(2))
                result['avg_ms'] = float(time_match.group(3))
                result['success'] = True
            elif result['packets_received'] > 0:
                result['success'] = True
        else:
            # Parse Linux/Mac ping output
            received_match = re.search(r'(\d+) received', stdout)
            if received_match:
                result['packets_received'] = int(received_match.group(1))
            
            loss_match = re.search(r'(\d+(?:\.\d+)?)% packet loss', stdout)
            if loss_match:
                result['packet_loss'] = float(loss_match.group(1))
            
            # Parse timing - Linux format: min/avg/max/mdev = X/X/X/X ms
            time_match = re.search(r'= ([\d.]+)/([\d.]+)/([\d.]+)', stdout)
            if time_match:
                result['min_ms'] = float(time_match.group(1))
                result['avg_ms'] = float(time_match.group(2))
                result['max_ms'] = float(time_match.group(3))
                result['success'] = True
            elif result['packets_received'] > 0:
                result['success'] = True
                
    except subprocess.TimeoutExpired:
        result['error'] = 'Ping timeout - no response'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def quick_ping(host: str, timeout: int = 2) -> Tuple[bool, Optional[float]]:
    """
    Quick single ping to check if host is reachable
    
    Args:
        host: IP address or hostname
        timeout: Timeout in seconds
        
    Returns:
        Tuple of (is_reachable, latency_ms)
    """
    try:
        system = platform.system().lower()
        if system == 'windows':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), host]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if system == 'windows' else 0
        )
        stdout, _ = process.communicate(timeout=timeout + 5)
        
        if process.returncode == 0:
            # Extract latency
            if system == 'windows':
                match = re.search(r'time[=<](\d+)ms', stdout)
            else:
                match = re.search(r'time=([\d.]+)', stdout)
            
            if match:
                return True, float(match.group(1))
            return True, None
        return False, None
        
    except Exception:
        return False, None
