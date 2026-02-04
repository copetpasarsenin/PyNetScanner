"""
Traceroute Module
Traces the network path to a target host
"""
import subprocess
import platform
import re
from typing import List, Callable, Optional


def traceroute(
    target: str, 
    max_hops: int = 15, 
    timeout: int = 3,
    callback: Optional[Callable] = None
) -> dict:
    """
    Perform traceroute to target host
    
    Args:
        target: Target IP address or hostname
        max_hops: Maximum number of hops (reduced to 15 for speed)
        timeout: Timeout per hop in seconds
        callback: Optional callback function(hop_number, hop_data)
        
    Returns:
        dict with keys: target, hops, complete, error
    """
    result = {
        'target': target,
        'hops': [],
        'complete': False,
        'error': None
    }
    
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            # Use shorter timeout and fewer hops for Windows
            cmd = ['tracert', '-d', '-h', str(max_hops), '-w', str(timeout * 1000), target]
            creationflags = subprocess.CREATE_NO_WINDOW
        else:
            cmd = ['traceroute', '-n', '-m', str(max_hops), '-w', str(timeout), target]
            creationflags = 0
        
        # Run with a total timeout to prevent hanging
        total_timeout = (max_hops * timeout) + 30  # Max time for entire traceroute
        
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=total_timeout,
                creationflags=creationflags
            )
            
            output = completed.stdout
            
            # Parse the output
            hop_pattern_windows = re.compile(
                r'^\s*(\d+)\s+(?:(\d+)\s*ms|[<*])\s+(?:(\d+)\s*ms|[<*])\s+(?:(\d+)\s*ms|[<*])\s+([\d.]+|Request timed out\.?|\*)'
            )
            
            for line in output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Skip header lines
                if 'Tracing route' in line or 'over a maximum' in line:
                    continue
                if 'Trace complete' in line:
                    result['complete'] = True
                    continue
                
                # Try to parse hop line
                match = hop_pattern_windows.match(line)
                if match:
                    hop_num = int(match.group(1))
                    times = []
                    for i in range(2, 5):
                        if match.group(i):
                            try:
                                times.append(int(match.group(i)))
                            except ValueError:
                                pass
                    
                    ip = match.group(5)
                    if ip == '*' or 'Request timed out' in ip:
                        ip = '*'
                        avg_time = None
                    else:
                        avg_time = sum(times) / len(times) if times else None
                    
                    hop_data = {
                        'hop': hop_num,
                        'ip': ip,
                        'times_ms': times,
                        'avg_ms': avg_time
                    }
                    
                    result['hops'].append(hop_data)
                    
                    if callback:
                        callback(hop_data['hop'], hop_data)
                    
                    # Check if we reached the target
                    if hop_data['ip'] == target:
                        result['complete'] = True
                else:
                    # Try simpler pattern for lines like "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
                    simple_match = re.search(r'^\s*(\d+)\s+.*?([\d.]+)\s*$', line)
                    if simple_match:
                        hop_num = int(simple_match.group(1))
                        ip = simple_match.group(2)
                        
                        # Extract times with <1 ms support
                        time_matches = re.findall(r'(\d+)\s*ms|<1\s*ms', line)
                        times = []
                        for t in time_matches:
                            if t:
                                times.append(int(t))
                            else:
                                times.append(1)  # <1 ms = 1ms
                        
                        avg_time = sum(times) / len(times) if times else None
                        
                        hop_data = {
                            'hop': hop_num,
                            'ip': ip,
                            'times_ms': times[:3],
                            'avg_ms': avg_time
                        }
                        
                        result['hops'].append(hop_data)
                        
                        if callback:
                            callback(hop_data['hop'], hop_data)
            
            if completed.returncode == 0 or result['hops']:
                result['complete'] = True
                
        except subprocess.TimeoutExpired:
            result['error'] = f'Traceroute timed out after {total_timeout}s'
            
    except FileNotFoundError:
        result['error'] = 'Traceroute command not found'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def quick_traceroute(target: str, max_hops: int = 10) -> List[str]:
    """
    Quick traceroute returning just IP addresses
    
    Args:
        target: Target IP or hostname
        max_hops: Maximum hops
        
    Returns:
        List of IP addresses in the path
    """
    result = traceroute(target, max_hops)
    return [hop['ip'] for hop in result['hops'] if hop['ip'] != '*']
