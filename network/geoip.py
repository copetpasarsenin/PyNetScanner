"""
GeoIP Location Module
Gets geographic location of IP addresses
"""
import urllib.request
import json
from typing import Optional


def get_ip_location(ip: str) -> dict:
    """
    Get geographic location for an IP address using free API
    
    Args:
        ip: IP address to lookup
        
    Returns:
        dict with location information
    """
    result = {
        'ip': ip,
        'country': None,
        'country_code': None,
        'region': None,
        'city': None,
        'zip': None,
        'latitude': None,
        'longitude': None,
        'timezone': None,
        'isp': None,
        'org': None,
        'as': None,
        'error': None
    }
    
    # Check for private/local IPs
    if is_private_ip(ip):
        result['error'] = 'Private/local IP address - no geolocation available'
        result['country'] = 'Local Network'
        return result
    
    try:
        # Use ip-api.com (free, no key, 45 requests/minute)
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as"
        
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'PyNetScanner/1.0')
        
        response = urllib.request.urlopen(request, timeout=10)
        data = json.loads(response.read().decode('utf-8'))
        
        if data.get('status') == 'success':
            result['country'] = data.get('country')
            result['country_code'] = data.get('countryCode')
            result['region'] = data.get('regionName')
            result['city'] = data.get('city')
            result['zip'] = data.get('zip')
            result['latitude'] = data.get('lat')
            result['longitude'] = data.get('lon')
            result['timezone'] = data.get('timezone')
            result['isp'] = data.get('isp')
            result['org'] = data.get('org')
            result['as'] = data.get('as')
        else:
            result['error'] = data.get('message', 'Unknown error')
            
    except urllib.error.HTTPError as e:
        result['error'] = f'API error: {e.code}'
    except urllib.error.URLError as e:
        result['error'] = f'Network error: {e.reason}'
    except json.JSONDecodeError:
        result['error'] = 'Invalid response from API'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def is_private_ip(ip: str) -> bool:
    """
    Check if IP is a private/local address
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private, False otherwise
    """
    try:
        parts = [int(p) for p in ip.split('.')]
        
        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        
        # 127.0.0.0/8 (loopback)
        if parts[0] == 127:
            return True
        
        # 169.254.0.0/16 (link-local)
        if parts[0] == 169 and parts[1] == 254:
            return True
        
        return False
    except Exception:
        return False


def get_my_public_ip() -> dict:
    """
    Get the user's public IP address and location
    
    Returns:
        dict with public IP and location info
    """
    result = {
        'ip': None,
        'location': None,
        'error': None
    }
    
    try:
        # First get public IP
        url = "https://api.ipify.org?format=json"
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'PyNetScanner/1.0')
        
        response = urllib.request.urlopen(request, timeout=10)
        data = json.loads(response.read().decode('utf-8'))
        
        result['ip'] = data.get('ip')
        
        # Then get location for that IP
        if result['ip']:
            result['location'] = get_ip_location(result['ip'])
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def format_location(location_data: dict) -> str:
    """
    Format location data as a readable string
    
    Args:
        location_data: Location dict from get_ip_location
        
    Returns:
        Formatted location string
    """
    if location_data.get('error'):
        return f"Location unavailable: {location_data['error']}"
    
    parts = []
    
    if location_data.get('city'):
        parts.append(location_data['city'])
    
    if location_data.get('region'):
        parts.append(location_data['region'])
    
    if location_data.get('country'):
        country = location_data['country']
        if location_data.get('country_code'):
            country += f" ({location_data['country_code']})"
        parts.append(country)
    
    if parts:
        return ", ".join(parts)
    
    return "Unknown location"
