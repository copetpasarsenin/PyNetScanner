"""
WHOIS Lookup Module
Provides domain and IP WHOIS information
"""
import socket
import re
from typing import Optional


# WHOIS servers for different TLDs
WHOIS_SERVERS = {
    'com': 'whois.verisign-grs.com',
    'net': 'whois.verisign-grs.com',
    'org': 'whois.pir.org',
    'info': 'whois.afilias.net',
    'io': 'whois.nic.io',
    'co': 'whois.nic.co',
    'id': 'whois.pandi.or.id',
    'default': 'whois.iana.org'
}

# IP WHOIS servers
IP_WHOIS_SERVERS = [
    'whois.arin.net',      # Americas
    'whois.ripe.net',      # Europe
    'whois.apnic.net',     # Asia Pacific
    'whois.lacnic.net',    # Latin America
    'whois.afrinic.net'    # Africa
]


def query_whois_server(server: str, query: str, port: int = 43) -> str:
    """
    Query a WHOIS server directly using socket
    
    Args:
        server: WHOIS server address
        query: Query string (domain or IP)
        port: WHOIS port (default 43)
        
    Returns:
        Raw WHOIS response
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, port))
        sock.send((query + '\r\n').encode())
        
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        sock.close()
        return response.decode('utf-8', errors='ignore')
        
    except Exception as e:
        return f"Error: {str(e)}"


def lookup_domain(domain: str) -> dict:
    """
    Perform WHOIS lookup for a domain
    
    Args:
        domain: Domain name to lookup
        
    Returns:
        dict with WHOIS information
    """
    result = {
        'domain': domain,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'name_servers': [],
        'status': [],
        'raw': None,
        'error': None
    }
    
    try:
        # Try using python-whois library first
        try:
            import whois
            w = whois.whois(domain)
            
            result['registrar'] = w.registrar if hasattr(w, 'registrar') else None
            result['creation_date'] = str(w.creation_date) if hasattr(w, 'creation_date') and w.creation_date else None
            result['expiration_date'] = str(w.expiration_date) if hasattr(w, 'expiration_date') and w.expiration_date else None
            
            if hasattr(w, 'name_servers') and w.name_servers:
                if isinstance(w.name_servers, list):
                    result['name_servers'] = [ns.lower() for ns in w.name_servers]
                else:
                    result['name_servers'] = [w.name_servers.lower()]
            
            if hasattr(w, 'status') and w.status:
                if isinstance(w.status, list):
                    result['status'] = w.status
                else:
                    result['status'] = [w.status]
            
            result['raw'] = w.text if hasattr(w, 'text') else str(w)
            return result
            
        except ImportError:
            pass
        
        # Fallback to direct socket query
        tld = domain.split('.')[-1].lower()
        server = WHOIS_SERVERS.get(tld, WHOIS_SERVERS['default'])
        
        response = query_whois_server(server, domain)
        result['raw'] = response
        
        # Parse common fields
        registrar_match = re.search(r'Registrar:\s*(.+)', response, re.IGNORECASE)
        if registrar_match:
            result['registrar'] = registrar_match.group(1).strip()
        
        creation_match = re.search(r'Creation Date:\s*(.+)', response, re.IGNORECASE)
        if creation_match:
            result['creation_date'] = creation_match.group(1).strip()
        
        expiry_match = re.search(r'(?:Registry Expiry Date|Expiration Date):\s*(.+)', response, re.IGNORECASE)
        if expiry_match:
            result['expiration_date'] = expiry_match.group(1).strip()
        
        ns_matches = re.findall(r'Name Server:\s*(.+)', response, re.IGNORECASE)
        result['name_servers'] = [ns.strip().lower() for ns in ns_matches]
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def lookup_ip(ip_address: str) -> dict:
    """
    Perform WHOIS lookup for an IP address
    
    Args:
        ip_address: IP address to lookup
        
    Returns:
        dict with IP ownership information
    """
    result = {
        'ip': ip_address,
        'network': None,
        'organization': None,
        'country': None,
        'cidr': None,
        'raw': None,
        'error': None
    }
    
    try:
        # Try using python-whois library first
        try:
            import whois
            # whois library doesn't support IP directly, skip to socket
            raise ImportError
        except ImportError:
            pass
        
        # Query ARIN first (most common for global IPs)
        response = query_whois_server('whois.arin.net', f'n {ip_address}')
        result['raw'] = response
        
        # If it refers to another RIR, follow it
        if 'RIPE' in response:
            response = query_whois_server('whois.ripe.net', ip_address)
            result['raw'] = response
        elif 'APNIC' in response:
            response = query_whois_server('whois.apnic.net', ip_address)
            result['raw'] = response
        
        # Parse fields
        org_match = re.search(r'(?:OrgName|org-name|Organization):\s*(.+)', response, re.IGNORECASE)
        if org_match:
            result['organization'] = org_match.group(1).strip()
        
        net_match = re.search(r'(?:NetName|netname):\s*(.+)', response, re.IGNORECASE)
        if net_match:
            result['network'] = net_match.group(1).strip()
        
        country_match = re.search(r'(?:Country|country):\s*(\w+)', response, re.IGNORECASE)
        if country_match:
            result['country'] = country_match.group(1).strip().upper()
        
        cidr_match = re.search(r'(?:CIDR|inetnum):\s*(.+)', response, re.IGNORECASE)
        if cidr_match:
            result['cidr'] = cidr_match.group(1).strip()
        
    except Exception as e:
        result['error'] = str(e)
    
    return result
