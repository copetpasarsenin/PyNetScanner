"""
Logger Module
Provides logging functionality for the application
"""
import os
import datetime
from typing import Callable, Optional, List


class Logger:
    """
    Logger class for recording and exporting activity logs
    """
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize logger
        
        Args:
            callback: Optional callback function(log_entry) for real-time updates
        """
        self.logs: List[dict] = []
        self.callback = callback
        self.session_start = datetime.datetime.now()
    
    def log(self, action: str, result: str, details: str = "") -> dict:
        """
        Add a log entry
        
        Args:
            action: Action performed (e.g., "Ping", "Port Scan")
            result: Result status (e.g., "Success", "Failed")
            details: Additional details
            
        Returns:
            The log entry dict
        """
        entry = {
            'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'action': action,
            'result': result,
            'details': details
        }
        
        self.logs.append(entry)
        
        if self.callback:
            self.callback(entry)
        
        return entry
    
    def log_ping(self, host: str, success: bool, latency: Optional[float] = None):
        """Log a ping result"""
        if success:
            details = f"Host: {host} | Latency: {latency:.2f}ms" if latency else f"Host: {host}"
            self.log("Ping", "Success", details)
        else:
            self.log("Ping", "Failed", f"Host: {host} - No response")
    
    def log_port_scan(self, host: str, port: int, status: str, service: str = ""):
        """Log a port scan result"""
        if status == "open":
            self.log("Port Scan", "Open", f"Host: {host} | Port: {port} ({service})")
        else:
            self.log("Port Scan", status.capitalize(), f"Host: {host} | Port: {port}")
    
    def log_dns(self, query: str, result_type: str, result: str):
        """Log a DNS lookup result"""
        self.log("DNS Lookup", result_type, f"Query: {query} | Result: {result}")
    
    def log_traceroute(self, target: str, hops: int):
        """Log traceroute completion"""
        self.log("Traceroute", "Complete", f"Target: {target} | Hops: {hops}")
    
    def log_whois(self, query: str, success: bool):
        """Log WHOIS lookup"""
        status = "Success" if success else "Failed"
        self.log("WHOIS", status, f"Query: {query}")
    
    def log_speed_test(self, speed_mbps: float):
        """Log speed test result"""
        self.log("Speed Test", "Complete", f"Download Speed: {speed_mbps:.2f} Mbps")
    
    def get_logs(self) -> List[dict]:
        """Get all logs"""
        return self.logs
    
    def get_logs_as_text(self) -> str:
        """Get logs formatted as text"""
        lines = [
            "=" * 60,
            "PyNetScanner Activity Log",
            f"Session started: {self.session_start.strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
            ""
        ]
        
        for entry in self.logs:
            lines.append(
                f"[{entry['timestamp']}] {entry['action']} - {entry['result']}"
            )
            if entry['details']:
                lines.append(f"   {entry['details']}")
            lines.append("")
        
        lines.append("=" * 60)
        lines.append(f"Total entries: {len(self.logs)}")
        lines.append(f"Log exported: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def export_to_file(self, filepath: str = None) -> str:
        """
        Export logs to a text file
        
        Args:
            filepath: Path to save the file (auto-generated if None)
            
        Returns:
            Path to the saved file
        """
        if filepath is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = f"PyNetScanner_Log_{timestamp}.txt"
        
        content = self.get_logs_as_text()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return os.path.abspath(filepath)
    
    def clear(self):
        """Clear all logs"""
        self.logs = []
        self.session_start = datetime.datetime.now()
    
    def set_callback(self, callback: Callable):
        """Set the callback function for real-time updates"""
        self.callback = callback
