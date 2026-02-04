"""
PyNetScanner - Network Utilities Module
Modul untuk fungsi-fungsi jaringan seperti ping dan port scanning.

Nama: Richard Firmansyah
Kelas: 2C-D4-TI
NPM: 714240047
"""

import socket
import threading
from datetime import datetime
from typing import Callable, Optional, Tuple, List

# Common port services
COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}


def get_local_ip() -> str:
    """
    Mendapatkan alamat IP lokal dari perangkat.
    Returns:
        str: Alamat IP lokal atau 'Unknown' jika gagal
    """
    try:
        # Membuat koneksi dummy untuk mendapatkan IP lokal
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "Unknown"


def get_hostname() -> str:
    """
    Mendapatkan nama hostname dari perangkat.
    Returns:
        str: Nama hostname atau 'Unknown' jika gagal
    """
    try:
        return socket.gethostname()
    except Exception:
        return "Unknown"


def ping_host(ip: str, timeout: float = 2.0) -> Tuple[bool, Optional[float], str]:
    """
    Melakukan ping ke target IP menggunakan ICMP.
    
    Args:
        ip: Alamat IP target
        timeout: Waktu timeout dalam detik
        
    Returns:
        Tuple[bool, Optional[float], str]: (success, latency_ms, message)
    """
    try:
        from ping3 import ping
        latency = ping(ip, timeout=timeout)
        
        if latency is None:
            return (False, None, f"Request timeout untuk {ip}")
        elif latency is False:
            return (False, None, f"Host {ip} tidak dapat dijangkau")
        else:
            latency_ms = latency * 1000
            return (True, latency_ms, f"Reply dari {ip}: time={latency_ms:.2f}ms")
    except PermissionError:
        # Fallback ke TCP ping jika tidak ada admin privilege
        return tcp_ping(ip, timeout)
    except Exception as e:
        return (False, None, f"Error: {str(e)}")


def tcp_ping(ip: str, timeout: float = 2.0) -> Tuple[bool, Optional[float], str]:
    """
    Fallback ping menggunakan TCP connection ke port 80/443.
    Digunakan jika ICMP ping tidak tersedia (butuh admin privilege).
    """
    ports_to_try = [80, 443, 22]
    
    for port in ports_to_try:
        try:
            start_time = datetime.now()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            end_time = datetime.now()
            sock.close()
            
            latency_ms = (end_time - start_time).total_seconds() * 1000
            
            if result == 0:
                return (True, latency_ms, f"Reply dari {ip} (TCP port {port}): time={latency_ms:.2f}ms")
        except Exception:
            continue
    
    return (False, None, f"Host {ip} tidak merespons pada port umum")


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Tuple[int, bool, str]:
    """
    Scan satu port pada IP target.
    
    Args:
        ip: Alamat IP target
        port: Nomor port yang akan di-scan
        timeout: Waktu timeout dalam detik
        
    Returns:
        Tuple[int, bool, str]: (port, is_open, service_name)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        is_open = result == 0
        service = COMMON_PORTS.get(port, "Unknown")
        
        return (port, is_open, service)
    except Exception:
        return (port, False, "Error")


def scan_port_range(
    ip: str,
    start_port: int,
    end_port: int,
    callback: Optional[Callable[[int, int, bool, str], None]] = None,
    max_threads: int = 100
) -> List[Tuple[int, str]]:
    """
    Scan rentang port menggunakan threading untuk performa.
    
    Args:
        ip: Alamat IP target
        start_port: Port awal
        end_port: Port akhir
        callback: Fungsi callback untuk update progress (current, total, is_open, service)
        max_threads: Jumlah maksimum thread
        
    Returns:
        List[Tuple[int, str]]: List port yang terbuka dengan nama service
    """
    open_ports = []
    lock = threading.Lock()
    scanned_count = [0]  # Mutable container untuk counter
    total_ports = end_port - start_port + 1
    
    def scan_worker(port: int):
        port_num, is_open, service = scan_port(ip, port)
        
        with lock:
            scanned_count[0] += 1
            if is_open:
                open_ports.append((port_num, service))
            
            if callback:
                callback(scanned_count[0], total_ports, is_open, service if is_open else "")
    
    threads = []
    for port in range(start_port, end_port + 1):
        while threading.active_count() > max_threads:
            pass  # Tunggu jika thread terlalu banyak
        
        t = threading.Thread(target=scan_worker, args=(port,))
        t.start()
        threads.append(t)
    
    # Tunggu semua thread selesai
    for t in threads:
        t.join()
    
    # Sort berdasarkan nomor port
    open_ports.sort(key=lambda x: x[0])
    
    return open_ports


def validate_ip(ip: str) -> bool:
    """
    Validasi format alamat IP atau hostname.
    
    Args:
        ip: Alamat IP atau hostname
        
    Returns:
        bool: True jika valid
    """
    if not ip or ip.strip() == "":
        return False
    
    try:
        socket.gethostbyname(ip)
        return True
    except socket.error:
        return False


def get_timestamp() -> str:
    """
    Mendapatkan timestamp saat ini dalam format yang readable.
    
    Returns:
        str: Timestamp format [HH:MM:SS]
    """
    return datetime.now().strftime("[%H:%M:%S]")
