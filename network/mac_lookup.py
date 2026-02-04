"""
MAC Vendor Lookup Module
Identifies device manufacturer from MAC address
"""
import urllib.request
import json
from typing import Optional

# Common MAC prefixes (OUI) database - offline fallback
MAC_VENDORS = {
    '00:00:0C': 'Cisco Systems',
    '00:1A:2B': 'Cisco Systems',
    '00:50:56': 'VMware',
    '00:0C:29': 'VMware',
    '00:15:5D': 'Microsoft (Hyper-V)',
    '00:1C:42': 'Parallels',
    '08:00:27': 'Oracle VirtualBox',
    '00:16:3E': 'Xen',
    '00:1B:21': 'Intel',
    '00:1E:67': 'Intel',
    '00:1F:3B': 'Intel',
    '3C:5A:B4': 'Google',
    '00:1A:11': 'Google',
    'F4:F5:D8': 'Google',
    '00:17:88': 'Philips',
    'AC:CF:85': 'Huawei',
    '00:E0:4C': 'Realtek',
    '52:54:00': 'QEMU/KVM',
    'B8:27:EB': 'Raspberry Pi',
    'DC:A6:32': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi',
    '00:23:24': 'Apple',
    '00:25:00': 'Apple',
    '00:26:08': 'Apple',
    '3C:15:C2': 'Apple',
    'AC:DE:48': 'Apple',
    'F0:18:98': 'Apple',
    '00:1D:D8': 'Microsoft',
    '00:03:FF': 'Microsoft',
    '00:0D:3A': 'Microsoft',
    '00:12:5A': 'Microsoft',
    '00:50:F2': 'Microsoft',
    '28:18:78': 'Microsoft',
    '7C:1E:52': 'Microsoft',
    'D4:81:D7': 'Dell',
    '00:14:22': 'Dell',
    '00:1E:4F': 'Dell',
    'F8:DB:88': 'Dell',
    '00:1A:A0': 'Dell',
    '00:21:9B': 'Dell',
    '18:03:73': 'Dell',
    '00:1E:68': 'HP',
    '00:25:B3': 'HP',
    '00:30:C1': 'HP',
    '2C:41:38': 'HP',
    '00:17:A4': 'HP',
    '00:1C:C4': 'HP',
    '00:60:B0': 'HP',
    '00:01:E6': 'HP',
    '00:30:6E': 'HP',
    '00:0F:20': 'HP',
    'C8:CB:B8': 'HP',
    '00:23:AE': 'Dell',
    'F8:B1:56': 'Dell',
    '00:1D:09': 'Dell',
    '00:26:B9': 'Dell',
    '74:86:7A': 'Dell',
    '00:24:E8': 'Dell',
    '78:2B:CB': 'Dell',
    '00:1F:C6': 'ASUS',
    '00:1A:92': 'ASUS',
    '00:22:15': 'ASUS',
    '00:24:8C': 'ASUS',
    '00:E0:18': 'ASUS',
    '00:0C:6E': 'ASUS',
    '00:13:D4': 'ASUS',
    '00:15:F2': 'ASUS',
    '00:17:31': 'ASUS',
    '04:D4:C4': 'ASUS',
    '08:60:6E': 'ASUS',
    '10:C3:7B': 'ASUS',
    '14:DA:E9': 'ASUS',
    '1C:87:2C': 'ASUS',
    '2C:4D:54': 'ASUS',
    '2C:56:DC': 'ASUS',
    '30:85:A9': 'ASUS',
    '30:5A:3A': 'ASUS',
    '38:D5:47': 'ASUS',
    '54:04:A6': 'ASUS',
    '60:45:CB': 'ASUS',
    '74:D0:2B': 'ASUS',
    '00:0E:A6': 'ASUS',
    'AC:9E:17': 'ASUS',
    'B0:6E:BF': 'ASUS',
    'BC:EE:7B': 'ASUS',
    'C8:60:00': 'ASUS',
    'D8:50:E6': 'ASUS',
    'E0:3F:49': 'ASUS',
    'E8:9C:25': 'ASUS',
    'F4:6D:04': 'ASUS',
    'F8:32:E4': 'ASUS',
    '00:E0:66': 'Lenovo',
    '00:09:2D': 'Lenovo',
    '00:06:1B': 'Lenovo',
    '88:70:8C': 'Lenovo',
    '00:1E:37': 'Lenovo',
    '70:F1:A1': 'Lenovo',
    '00:12:FE': 'Lenovo',
    '00:16:D3': 'Lenovo',
    '00:18:8B': 'Lenovo',
    '00:1A:6B': 'Lenovo',
    '00:21:5E': 'Lenovo',
    '00:22:67': 'Lenovo',
    '00:23:7D': 'Lenovo',
    '00:24:7E': 'Lenovo',
    '00:26:2D': 'Lenovo',
    '00:27:13': 'Lenovo',
    '04:7D:7B': 'Lenovo',
    '08:9E:01': 'Lenovo',
    '28:D2:44': 'Lenovo',
    '3C:97:0E': 'Lenovo',
    '40:B0:34': 'Lenovo',
    '44:8A:5B': 'Lenovo',
    '50:7B:9D': 'Lenovo',
    '54:EE:75': 'Lenovo',
    '5C:B9:01': 'Lenovo',
    '60:D9:C7': 'Lenovo',
    '6C:0B:84': 'Lenovo',
    '74:E5:0B': 'Lenovo',
    '7C:7A:91': 'Lenovo',
    '84:7B:EB': 'Lenovo',
    '8C:16:45': 'Lenovo',
    '98:FA:9B': 'Lenovo',
    'C8:1F:66': 'Lenovo',
    'CC:52:AF': 'Lenovo',
    'D0:57:7B': 'Lenovo',
    'D8:D3:85': 'Lenovo',
    'E8:40:40': 'Lenovo',
    'EC:89:14': 'Lenovo',
    'F0:DE:F1': 'Lenovo',
    'F4:8E:38': 'Lenovo',
    'F8:0D:44': 'Lenovo',
    'FC:F8:AE': 'Lenovo',
    '00:1C:BF': 'TP-Link',
    '00:27:19': 'TP-Link',
    '14:CC:20': 'TP-Link',
    '14:CF:92': 'TP-Link',
    '18:A6:F7': 'TP-Link',
    '1C:FA:68': 'TP-Link',
    '30:B5:C2': 'TP-Link',
    '50:C7:BF': 'TP-Link',
    '54:C8:0F': 'TP-Link',
    '5C:89:9A': 'TP-Link',
    '60:E3:27': 'TP-Link',
    '64:66:B3': 'TP-Link',
    '64:70:02': 'TP-Link',
    '6C:B0:CE': 'TP-Link',
    '78:44:76': 'TP-Link',
    '78:A1:06': 'TP-Link',
    '88:25:93': 'TP-Link',
    '90:F6:52': 'TP-Link',
    '94:0C:6D': 'TP-Link',
    '98:DA:C4': 'TP-Link',
    'A0:F3:C1': 'TP-Link',
    'AC:84:C6': 'TP-Link',
    'B0:48:7A': 'TP-Link',
    'B0:BE:76': 'TP-Link',
    'C0:25:E9': 'TP-Link',
    'C4:6E:1F': 'TP-Link',
    'C8:3A:35': 'TP-Link',
    'CC:32:E5': 'TP-Link',
    'D4:6E:0E': 'TP-Link',
    'D8:07:B6': 'TP-Link',
    'E0:05:C5': 'TP-Link',
    'E4:D3:32': 'TP-Link',
    'E8:94:F6': 'TP-Link',
    'E8:DE:27': 'TP-Link',
    'EC:08:6B': 'TP-Link',
    'EC:88:8F': 'TP-Link',
    'F0:F3:36': 'TP-Link',
    'F4:EC:38': 'TP-Link',
    'F8:1A:67': 'TP-Link',
    'FC:D7:33': 'TP-Link',
    '00:18:E7': 'D-Link',
    '00:1B:11': 'D-Link',
    '00:1C:F0': 'D-Link',
    '00:1E:58': 'D-Link',
    '00:21:91': 'D-Link',
    '00:22:B0': 'D-Link',
    '00:24:01': 'D-Link',
    '00:26:5A': 'D-Link',
    '1C:5F:2B': 'D-Link',
    '1C:7E:E5': 'D-Link',
    '28:10:7B': 'D-Link',
    '2C:B0:5D': 'D-Link',
    '34:08:04': 'D-Link',
    '3C:1E:04': 'D-Link',
    '44:AD:D9': 'D-Link',
    '5C:D9:98': 'D-Link',
    '60:63:4C': 'D-Link',
    '78:32:1B': 'D-Link',
    '78:54:2E': 'D-Link',
    '84:C9:B2': 'D-Link',
    '90:8D:78': 'D-Link',
    '90:94:E4': 'D-Link',
    '9C:D6:43': 'D-Link',
    'AC:F1:DF': 'D-Link',
    'B8:A3:86': 'D-Link',
    'BC:F6:85': 'D-Link',
    'C0:A0:BB': 'D-Link',
    'C4:12:F5': 'D-Link',
    'C8:BE:19': 'D-Link',
    'CC:B2:55': 'D-Link',
    'D8:FE:E3': 'D-Link',
    'E4:6F:13': 'D-Link',
    'E8:CC:18': 'D-Link',
    'EC:22:80': 'D-Link',
    'F0:7D:68': 'D-Link',
    'F8:E9:03': 'D-Link',
    '00:1F:33': 'Netgear',
    '00:22:3F': 'Netgear',
    '00:24:B2': 'Netgear',
    '00:26:F2': 'Netgear',
    'A4:2B:8C': 'Netgear',
    '20:E5:2A': 'Netgear',
    'E0:46:9A': 'Netgear',
    '28:C6:8E': 'Netgear',
    '30:46:9A': 'Netgear',
    '44:94:FC': 'Netgear',
    '4C:60:DE': 'Netgear',
    '6C:B0:CE': 'Netgear',
    '84:1B:5E': 'Netgear',
    'C0:3F:0E': 'Netgear',
    'C4:04:15': 'Netgear',
    'DC:EF:09': 'Netgear',
    'E4:F4:C6': 'Netgear',
    'E8:FC:AF': 'Netgear',
    'F8:4F:57': 'Netgear',
    '00:04:4B': 'Nvidia',
    '48:B0:2D': 'Nvidia',
    '00:80:41': 'VoIP/Cisco',
    '00:1F:CA': 'Cisco',
    '00:22:55': 'Cisco',
    '00:23:04': 'Cisco',
    '00:24:97': 'Cisco',
    'F4:4D:30': 'Xiaomi',
    '0C:1D:AF': 'Xiaomi',
    '14:F6:5A': 'Xiaomi',
    '18:59:36': 'Xiaomi',
    '20:F4:1B': 'Xiaomi',
    '28:6C:07': 'Xiaomi',
    '34:CE:00': 'Xiaomi',
    '38:A4:ED': 'Xiaomi',
    '3C:BD:D8': 'Xiaomi',
    '58:44:98': 'Xiaomi',
    '64:09:80': 'Xiaomi',
    '64:B4:73': 'Xiaomi',
    '68:DF:DD': 'Xiaomi',
    '74:23:44': 'Xiaomi',
    '7C:1D:D9': 'Xiaomi',
    '7C:CB:E2': 'Xiaomi',
    '84:F3:EB': 'Xiaomi',
    '8C:BE:BE': 'Xiaomi',
    '98:FA:E3': 'Xiaomi',
    '9C:99:A0': 'Xiaomi',
    'A0:86:C6': 'Xiaomi',
    'AC:C1:EE': 'Xiaomi',
    'B0:E2:35': 'Xiaomi',
    'C4:0B:CB': 'Xiaomi',
    'C4:6A:B7': 'Xiaomi',
    'D4:97:0B': 'Xiaomi',
    'E8:AB:FA': 'Xiaomi',
    'F0:B4:29': 'Xiaomi',
    'F4:8B:32': 'Xiaomi',
    'F8:A4:5F': 'Xiaomi',
    'FC:64:BA': 'Xiaomi',
    '00:26:BB': 'Samsung',
    '00:26:37': 'Samsung',
    '5C:0A:5B': 'Samsung',
    '78:40:E4': 'Samsung',
    '88:32:9B': 'Samsung',
    '94:35:0A': 'Samsung',
    'A8:06:00': 'Samsung',
    'AC:5F:3E': 'Samsung',
    'CC:07:AB': 'Samsung',
    'F4:09:D8': 'Samsung',
    "00:1E:75": "LG Electronics",
    '10:68:3F': 'LG Electronics',
    '34:FC:EF': 'LG Electronics',
    '00:21:FB': 'LG Electronics',
    '00:22:A9': 'LG Electronics',
    '00:24:83': 'LG Electronics',
    '00:25:E5': 'LG Electronics',
    '00:26:E2': 'LG Electronics',
    '10:F1:F2': 'LG Electronics',
}


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to XX:XX:XX format (first 3 octets)"""
    # Remove common separators and convert to uppercase
    mac = mac.upper().replace('-', ':').replace('.', ':')
    
    # Extract first 3 octets
    parts = mac.split(':')
    if len(parts) >= 3:
        return f"{parts[0]}:{parts[1]}:{parts[2]}"
    
    # Handle no separator format
    mac_clean = mac.replace(':', '')
    if len(mac_clean) >= 6:
        return f"{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}"
    
    return mac


def lookup_vendor_offline(mac: str) -> Optional[str]:
    """
    Lookup vendor from offline database
    
    Args:
        mac: MAC address
        
    Returns:
        Vendor name or None
    """
    prefix = normalize_mac(mac)
    return MAC_VENDORS.get(prefix)


def lookup_vendor_online(mac: str) -> dict:
    """
    Lookup vendor using online API
    
    Args:
        mac: MAC address
        
    Returns:
        dict with vendor info
    """
    result = {
        'mac': mac,
        'vendor': None,
        'error': None,
        'source': None
    }
    
    try:
        # Try macvendors.com API (free, no key needed)
        mac_clean = mac.replace(':', '').replace('-', '').replace('.', '')[:6]
        url = f"https://api.macvendors.com/{mac_clean}"
        
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'PyNetScanner/1.0')
        
        response = urllib.request.urlopen(request, timeout=5)
        vendor = response.read().decode('utf-8').strip()
        
        result['vendor'] = vendor
        result['source'] = 'online'
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result['error'] = 'Vendor not found'
        else:
            result['error'] = f'API error: {e.code}'
    except Exception as e:
        result['error'] = str(e)
    
    # Fallback to offline
    if result['vendor'] is None and result['error']:
        offline = lookup_vendor_offline(mac)
        if offline:
            result['vendor'] = offline
            result['source'] = 'offline'
            result['error'] = None
    
    return result


def lookup_vendor(mac: str, use_online: bool = True) -> dict:
    """
    Lookup MAC vendor with fallback
    
    Args:
        mac: MAC address
        use_online: Try online API first
        
    Returns:
        dict with vendor info
    """
    result = {
        'mac': mac,
        'mac_normalized': normalize_mac(mac) + ':XX:XX:XX',
        'vendor': None,
        'source': None,
        'error': None
    }
    
    if use_online:
        online = lookup_vendor_online(mac)
        if online['vendor']:
            result['vendor'] = online['vendor']
            result['source'] = online['source']
            return result
    
    # Try offline
    vendor = lookup_vendor_offline(mac)
    if vendor:
        result['vendor'] = vendor
        result['source'] = 'offline'
    else:
        result['error'] = 'Vendor not found'
    
    return result
