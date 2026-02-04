"""
Speed Test Module
Provides network speed and latency testing
"""
import socket
import time
import urllib.request
from typing import Callable, Optional


# Test file URLs for download speed (various sizes)
TEST_URLS = [
    ('http://speedtest.tele2.net/1MB.zip', 1),      # 1 MB
    ('http://speedtest.tele2.net/10MB.zip', 10),    # 10 MB
    ('http://ipv4.download.thinkbroadband.com/5MB.zip', 5),  # 5 MB
]


def test_download_speed(
    url: str = None,
    expected_mb: float = 1,
    callback: Optional[Callable] = None
) -> dict:
    """
    Test download speed by downloading a file
    
    Args:
        url: URL to download (uses default if None)
        expected_mb: Expected file size in MB
        callback: Optional callback(downloaded_bytes, total_bytes, speed_mbps)
        
    Returns:
        dict with speed test results
    """
    result = {
        'url': url,
        'file_size_mb': expected_mb,
        'download_time_sec': None,
        'speed_mbps': None,
        'speed_mbps_formatted': None,
        'error': None
    }
    
    if url is None:
        url = TEST_URLS[0][0]
        expected_mb = TEST_URLS[0][1]
        result['url'] = url
        result['file_size_mb'] = expected_mb
    
    try:
        # Start download
        start_time = time.time()
        
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'PyNetScanner/1.0')
        
        response = urllib.request.urlopen(request, timeout=60)
        total_size = int(response.headers.get('Content-Length', expected_mb * 1024 * 1024))
        
        downloaded = 0
        chunk_size = 8192
        
        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break
            downloaded += len(chunk)
            
            if callback:
                elapsed = time.time() - start_time
                current_speed = (downloaded / elapsed) * 8 / 1_000_000 if elapsed > 0 else 0
                callback(downloaded, total_size, current_speed)
        
        end_time = time.time()
        download_time = end_time - start_time
        
        # Calculate speed
        result['download_time_sec'] = round(download_time, 2)
        bytes_downloaded = downloaded
        bits_downloaded = bytes_downloaded * 8
        speed_bps = bits_downloaded / download_time
        speed_mbps = speed_bps / 1_000_000
        
        result['speed_mbps'] = round(speed_mbps, 2)
        result['speed_mbps_formatted'] = f"{speed_mbps:.2f} Mbps"
        
    except urllib.error.URLError as e:
        result['error'] = f"URL error: {e.reason}"
    except Exception as e:
        result['error'] = str(e)
    
    return result


def test_latency(host: str = "8.8.8.8", port: int = 80, count: int = 5) -> dict:
    """
    Test network latency using TCP connection time
    
    Args:
        host: Target host
        port: Target port
        count: Number of tests
        
    Returns:
        dict with latency results
    """
    result = {
        'host': host,
        'port': port,
        'count': count,
        'latencies_ms': [],
        'min_ms': None,
        'max_ms': None,
        'avg_ms': None,
        'packet_loss': 0.0,
        'error': None
    }
    
    successful = 0
    
    for _ in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            start = time.time()
            sock.connect((host, port))
            end = time.time()
            sock.close()
            
            latency = (end - start) * 1000  # Convert to ms
            result['latencies_ms'].append(round(latency, 2))
            successful += 1
            
        except Exception:
            pass
    
    if result['latencies_ms']:
        result['min_ms'] = round(min(result['latencies_ms']), 2)
        result['max_ms'] = round(max(result['latencies_ms']), 2)
        result['avg_ms'] = round(sum(result['latencies_ms']) / len(result['latencies_ms']), 2)
    
    result['packet_loss'] = round((count - successful) / count * 100, 1)
    
    if successful == 0:
        result['error'] = "All connection attempts failed"
    
    return result


def test_network_quality(host: str = "8.8.8.8") -> dict:
    """
    Comprehensive network quality test
    
    Args:
        host: Target host to test against
        
    Returns:
        dict with quality metrics
    """
    # Test latency
    latency = test_latency(host, 80, 10)
    
    # Rate quality
    quality = "Unknown"
    if latency['avg_ms'] is not None:
        avg = latency['avg_ms']
        if avg < 20:
            quality = "Excellent"
        elif avg < 50:
            quality = "Good"
        elif avg < 100:
            quality = "Fair"
        elif avg < 200:
            quality = "Poor"
        else:
            quality = "Bad"
    
    return {
        'host': host,
        'latency': latency,
        'quality_rating': quality
    }
