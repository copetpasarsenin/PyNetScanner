"""
PyNetScanner GUI Application
Modern network scanning tool with CustomTkinter interface
"""
import customtkinter as ctk
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from network import ping_tester, port_scanner, dns_lookup, network_info
from network import service_detector, whois_lookup, speed_test
from network import host_discovery, mac_lookup, geoip
from network.traceroute import traceroute as do_traceroute
from utils.logger import Logger


# Configure CustomTkinter
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class PyNetScannerApp(ctk.CTk):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        
        # Window configuration
        self.title("🔍 PyNetScanner - Network Monitoring Tool")
        self.geometry("1100x750")
        self.minsize(900, 600)
        
        # Initialize logger
        self.logger = Logger(callback=self.on_log_entry)
        
        # Track running operations
        self.is_scanning = False
        
        # Build UI
        self._create_header()
        self._create_tabview()
        self._create_status_bar()
        
        # Load initial network info
        self.after(100, self._load_network_info)
    
    def _create_header(self):
        """Create header section with local info"""
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=20, pady=(15, 5))
        
        # Title
        title_label = ctk.CTkLabel(
            self.header_frame,
            text="🔍 PyNetScanner",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title_label.pack(side="left")
        
        # Local info frame (right side)
        self.info_frame = ctk.CTkFrame(self.header_frame, fg_color=("gray90", "gray17"))
        self.info_frame.pack(side="right", padx=10)
        
        self.hostname_label = ctk.CTkLabel(
            self.info_frame,
            text="💻 Loading...",
            font=ctk.CTkFont(size=13)
        )
        self.hostname_label.pack(side="left", padx=15, pady=8)
        
        self.local_ip_label = ctk.CTkLabel(
            self.info_frame,
            text="🌐 Loading...",
            font=ctk.CTkFont(size=13)
        )
        self.local_ip_label.pack(side="left", padx=15, pady=8)
        
        # Theme toggle
        self.theme_switch = ctk.CTkSwitch(
            self.header_frame,
            text="🌙 Dark",
            command=self._toggle_theme,
            onvalue=1,
            offvalue=0
        )
        self.theme_switch.select()
        self.theme_switch.pack(side="right", padx=20)
    
    def _create_tabview(self):
        """Create tabbed interface"""
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Create tabs
        self.tab_ping = self.tabview.add("🏓 Ping & Scan")
        self.tab_dns = self.tabview.add("🌐 DNS Tools")
        self.tab_network = self.tabview.add("📊 Network Info")
        self.tab_discovery = self.tabview.add("🔎 Discovery")
        self.tab_advanced = self.tabview.add("⚙️ Advanced")
        self.tab_logs = self.tabview.add("📋 Logs")
        
        # Build each tab
        self._build_ping_tab()
        self._build_dns_tab()
        self._build_network_tab()
        self._build_discovery_tab()
        self._build_advanced_tab()
        self._build_logs_tab()
    
    def _build_ping_tab(self):
        """Build Ping & Port Scan tab"""
        # Main container with two columns
        container = ctk.CTkFrame(self.tab_ping, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)
        container.grid_rowconfigure(1, weight=1)
        
        # === PING SECTION ===
        ping_frame = ctk.CTkFrame(container)
        ping_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
        
        ctk.CTkLabel(ping_frame, text="🏓 Ping Tester", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        input_frame = ctk.CTkFrame(ping_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(input_frame, text="Target IP/Host:").pack(side="left", padx=5)
        self.ping_target = ctk.CTkEntry(input_frame, width=200, placeholder_text="e.g., 8.8.8.8 or google.com")
        self.ping_target.pack(side="left", padx=5)
        
        ctk.CTkLabel(input_frame, text="Count:").pack(side="left", padx=(15, 5))
        self.ping_count = ctk.CTkEntry(input_frame, width=60, placeholder_text="4")
        self.ping_count.insert(0, "4")
        self.ping_count.pack(side="left", padx=5)
        
        self.ping_btn = ctk.CTkButton(ping_frame, text="🚀 Start Ping", command=self._run_ping)
        self.ping_btn.pack(pady=10)
        
        # === PORT SCAN SECTION ===
        scan_frame = ctk.CTkFrame(container)
        scan_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=(0, 10))
        
        ctk.CTkLabel(scan_frame, text="🔌 Port Scanner", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        scan_input = ctk.CTkFrame(scan_frame, fg_color="transparent")
        scan_input.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(scan_input, text="Target IP:").pack(side="left", padx=5)
        self.scan_target = ctk.CTkEntry(scan_input, width=150, placeholder_text="e.g., 192.168.1.1")
        self.scan_target.pack(side="left", padx=5)
        
        range_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        range_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(range_frame, text="Port Range:").pack(side="left", padx=5)
        self.port_start = ctk.CTkEntry(range_frame, width=70, placeholder_text="1")
        self.port_start.insert(0, "1")
        self.port_start.pack(side="left", padx=5)
        ctk.CTkLabel(range_frame, text="to").pack(side="left", padx=5)
        self.port_end = ctk.CTkEntry(range_frame, width=70, placeholder_text="1024")
        self.port_end.insert(0, "1024")
        self.port_end.pack(side="left", padx=5)
        
        btn_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        btn_frame.pack(pady=10)
        
        self.scan_btn = ctk.CTkButton(btn_frame, text="🔍 Scan Range", command=self._run_port_scan)
        self.scan_btn.pack(side="left", padx=5)
        
        self.scan_common_btn = ctk.CTkButton(btn_frame, text="⚡ Common Ports", command=self._run_common_scan)
        self.scan_common_btn.pack(side="left", padx=5)
        
        # Progress bar
        self.scan_progress = ctk.CTkProgressBar(scan_frame)
        self.scan_progress.pack(fill="x", padx=15, pady=5)
        self.scan_progress.set(0)
        
        # === RESULTS SECTION ===
        result_frame = ctk.CTkFrame(container)
        result_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 0))
        
        ctk.CTkLabel(result_frame, text="📊 Results", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        self.ping_result = ctk.CTkTextbox(result_frame, height=200, font=ctk.CTkFont(family="Consolas", size=12))
        self.ping_result.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_dns_tab(self):
        """Build DNS Tools tab"""
        container = ctk.CTkFrame(self.tab_dns, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # DNS Lookup section
        dns_frame = ctk.CTkFrame(container)
        dns_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(dns_frame, text="🔎 DNS Lookup", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        input_frame = ctk.CTkFrame(dns_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(input_frame, text="Hostname:").pack(side="left", padx=5)
        self.dns_hostname = ctk.CTkEntry(input_frame, width=300, placeholder_text="e.g., google.com")
        self.dns_hostname.pack(side="left", padx=5)
        
        self.dns_btn = ctk.CTkButton(input_frame, text="🔍 Resolve", command=self._run_dns_lookup)
        self.dns_btn.pack(side="left", padx=10)
        
        # Reverse DNS section
        rdns_frame = ctk.CTkFrame(container)
        rdns_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(rdns_frame, text="🔄 Reverse DNS", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        rinput_frame = ctk.CTkFrame(rdns_frame, fg_color="transparent")
        rinput_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(rinput_frame, text="IP Address:").pack(side="left", padx=5)
        self.rdns_ip = ctk.CTkEntry(rinput_frame, width=200, placeholder_text="e.g., 8.8.8.8")
        self.rdns_ip.pack(side="left", padx=5)
        
        self.rdns_btn = ctk.CTkButton(rinput_frame, text="🔍 Lookup", command=self._run_reverse_dns)
        self.rdns_btn.pack(side="left", padx=10)
        
        # Results
        result_frame = ctk.CTkFrame(container)
        result_frame.pack(fill="both", expand=True)
        
        ctk.CTkLabel(result_frame, text="📊 Results", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        self.dns_result = ctk.CTkTextbox(result_frame, height=250, font=ctk.CTkFont(family="Consolas", size=12))
        self.dns_result.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_network_tab(self):
        """Build Network Info tab"""
        container = ctk.CTkFrame(self.tab_network, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Refresh button
        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(fill="x", pady=10)
        
        self.refresh_net_btn = ctk.CTkButton(btn_frame, text="🔄 Refresh Network Info", command=self._load_network_info)
        self.refresh_net_btn.pack(side="left", padx=10)
        
        # Network info display
        self.network_result = ctk.CTkTextbox(container, font=ctk.CTkFont(family="Consolas", size=12))
        self.network_result.pack(fill="both", expand=True, padx=10, pady=10)
    
    def _build_discovery_tab(self):
        """Build Discovery tab with Host Discovery, MAC Lookup, and GeoIP"""
        container = ctk.CTkFrame(self.tab_discovery, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)
        container.grid_rowconfigure(1, weight=1)
        
        # === HOST DISCOVERY SECTION ===
        discover_frame = ctk.CTkFrame(container)
        discover_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
        
        ctk.CTkLabel(discover_frame, text="🔎 Host Discovery", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        disc_input = ctk.CTkFrame(discover_frame, fg_color="transparent")
        disc_input.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(disc_input, text="Network:").pack(side="left", padx=5)
        self.network_range = ctk.CTkEntry(disc_input, width=150, placeholder_text="e.g., 192.168.1.0/24")
        self.network_range.pack(side="left", padx=5)
        
        self.discover_btn = ctk.CTkButton(discover_frame, text="🔍 Discover Hosts", command=self._run_host_discovery)
        self.discover_btn.pack(pady=5)
        
        self.discover_progress = ctk.CTkProgressBar(discover_frame)
        self.discover_progress.pack(fill="x", padx=15, pady=5)
        self.discover_progress.set(0)
        
        self.discover_label = ctk.CTkLabel(discover_frame, text="Leave empty for auto-detect")
        self.discover_label.pack(pady=2)
        
        # === MAC VENDOR LOOKUP SECTION ===
        mac_frame = ctk.CTkFrame(container)
        mac_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=(0, 10))
        
        ctk.CTkLabel(mac_frame, text="🏭 MAC Vendor Lookup", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        mac_input = ctk.CTkFrame(mac_frame, fg_color="transparent")
        mac_input.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(mac_input, text="MAC:").pack(side="left", padx=5)
        self.mac_address = ctk.CTkEntry(mac_input, width=180, placeholder_text="e.g., 00:1A:2B:3C:4D:5E")
        self.mac_address.pack(side="left", padx=5)
        
        self.mac_btn = ctk.CTkButton(mac_frame, text="🔍 Lookup Vendor", command=self._run_mac_lookup)
        self.mac_btn.pack(pady=10)
        
        # === GEOIP SECTION ===
        geo_frame = ctk.CTkFrame(container)
        geo_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5), pady=(0, 0))
        
        ctk.CTkLabel(geo_frame, text="🌍 GeoIP Location", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        geo_input = ctk.CTkFrame(geo_frame, fg_color="transparent")
        geo_input.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(geo_input, text="IP:").pack(side="left", padx=5)
        self.geo_ip = ctk.CTkEntry(geo_input, width=150, placeholder_text="e.g., 8.8.8.8")
        self.geo_ip.pack(side="left", padx=5)
        
        geo_btn_frame = ctk.CTkFrame(geo_frame, fg_color="transparent")
        geo_btn_frame.pack(pady=10)
        
        self.geo_btn = ctk.CTkButton(geo_btn_frame, text="🔍 Locate IP", command=self._run_geoip)
        self.geo_btn.pack(side="left", padx=5)
        
        self.myip_btn = ctk.CTkButton(geo_btn_frame, text="🌐 My Public IP", command=self._run_my_ip)
        self.myip_btn.pack(side="left", padx=5)
        
        # === DISCOVERY RESULTS ===
        result_frame = ctk.CTkFrame(container)
        result_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0), pady=(0, 0))
        
        ctk.CTkLabel(result_frame, text="📊 Discovery Results", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        self.discovery_result = ctk.CTkTextbox(result_frame, font=ctk.CTkFont(family="Consolas", size=12))
        self.discovery_result.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_advanced_tab(self):
        """Build Advanced Tools tab"""
        container = ctk.CTkFrame(self.tab_advanced, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        container.grid_columnconfigure(0, weight=1)
        container.grid_columnconfigure(1, weight=1)
        
        # Traceroute section
        trace_frame = ctk.CTkFrame(container)
        trace_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
        
        ctk.CTkLabel(trace_frame, text="🛤️ Traceroute", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        trace_input = ctk.CTkFrame(trace_frame, fg_color="transparent")
        trace_input.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(trace_input, text="Target:").pack(side="left", padx=5)
        self.trace_target = ctk.CTkEntry(trace_input, width=150, placeholder_text="e.g., google.com")
        self.trace_target.pack(side="left", padx=5)
        
        self.trace_btn = ctk.CTkButton(trace_frame, text="🚀 Trace", command=self._run_traceroute)
        self.trace_btn.pack(pady=10)
        
        # WHOIS section
        whois_frame = ctk.CTkFrame(container)
        whois_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0), pady=(0, 10))
        
        ctk.CTkLabel(whois_frame, text="📋 WHOIS Lookup", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        whois_input = ctk.CTkFrame(whois_frame, fg_color="transparent")
        whois_input.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(whois_input, text="Domain/IP:").pack(side="left", padx=5)
        self.whois_target = ctk.CTkEntry(whois_input, width=150, placeholder_text="e.g., google.com")
        self.whois_target.pack(side="left", padx=5)
        
        self.whois_btn = ctk.CTkButton(whois_frame, text="🔍 Lookup", command=self._run_whois)
        self.whois_btn.pack(pady=10)
        
        # Service Detection section
        service_frame = ctk.CTkFrame(container)
        service_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
        
        ctk.CTkLabel(service_frame, text="🔧 Service Detection", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        svc_input = ctk.CTkFrame(service_frame, fg_color="transparent")
        svc_input.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(svc_input, text="Host:").pack(side="left", padx=5)
        self.svc_host = ctk.CTkEntry(svc_input, width=120, placeholder_text="IP/Host")
        self.svc_host.pack(side="left", padx=5)
        ctk.CTkLabel(svc_input, text="Port:").pack(side="left", padx=5)
        self.svc_port = ctk.CTkEntry(svc_input, width=60, placeholder_text="80")
        self.svc_port.pack(side="left", padx=5)
        
        self.svc_btn = ctk.CTkButton(service_frame, text="🔍 Detect", command=self._run_service_detect)
        self.svc_btn.pack(pady=10)
        
        # Speed Test section
        speed_frame = ctk.CTkFrame(container)
        speed_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 0), pady=(0, 10))
        
        ctk.CTkLabel(speed_frame, text="⚡ Speed Test", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        self.speed_btn = ctk.CTkButton(speed_frame, text="🚀 Start Test", command=self._run_speed_test)
        self.speed_btn.pack(pady=10)
        
        self.speed_progress = ctk.CTkProgressBar(speed_frame)
        self.speed_progress.pack(fill="x", padx=15, pady=5)
        self.speed_progress.set(0)
        
        self.speed_label = ctk.CTkLabel(speed_frame, text="Click to test download speed")
        self.speed_label.pack(pady=5)
        
        # Advanced Results
        adv_result_frame = ctk.CTkFrame(container)
        adv_result_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(0, 0))
        container.grid_rowconfigure(2, weight=1)
        
        ctk.CTkLabel(adv_result_frame, text="📊 Results", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        self.adv_result = ctk.CTkTextbox(adv_result_frame, height=150, font=ctk.CTkFont(family="Consolas", size=12))
        self.adv_result.pack(fill="both", expand=True, padx=10, pady=(0, 10))
    
    def _build_logs_tab(self):
        """Build Logs tab"""
        container = ctk.CTkFrame(self.tab_logs, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Buttons
        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.pack(fill="x", pady=10)
        
        self.export_btn = ctk.CTkButton(btn_frame, text="💾 Export Logs", command=self._export_logs)
        self.export_btn.pack(side="left", padx=10)
        
        self.clear_btn = ctk.CTkButton(btn_frame, text="🗑️ Clear Logs", command=self._clear_logs, fg_color="red", hover_color="darkred")
        self.clear_btn.pack(side="left", padx=10)
        
        # Log display
        self.log_display = ctk.CTkTextbox(container, font=ctk.CTkFont(family="Consolas", size=11))
        self.log_display.pack(fill="both", expand=True, padx=10, pady=10)
    
    def _create_status_bar(self):
        """Create status bar"""
        self.status_frame = ctk.CTkFrame(self, height=30, corner_radius=0)
        self.status_frame.pack(fill="x", side="bottom")
        
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Ready",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(side="left", padx=15, pady=5)
        
        # Credits
        credit_label = ctk.CTkLabel(
            self.status_frame,
            text="Richard Firmansyah | 2C-D4-TI | NPM: 714240047",
            font=ctk.CTkFont(size=11)
        )
        credit_label.pack(side="right", padx=15, pady=5)
    
    # === HELPER METHODS ===
    
    def _set_status(self, text: str):
        """Update status bar"""
        self.status_label.configure(text=text)
        self.update_idletasks()
    
    def _toggle_theme(self):
        """Toggle dark/light theme"""
        if ctk.get_appearance_mode() == "Dark":
            ctk.set_appearance_mode("light")
            self.theme_switch.configure(text="☀️ Light")
        else:
            ctk.set_appearance_mode("dark")
            self.theme_switch.configure(text="🌙 Dark")
    
    def _load_network_info(self):
        """Load and display network information"""
        def task():
            info = network_info.get_network_summary()
            
            # Update header
            self.hostname_label.configure(text=f"💻 {info['hostname']}")
            self.local_ip_label.configure(text=f"🌐 {info['local_ip']}")
            
            # Format for display
            lines = [
                "=" * 50,
                "       🖥️  NETWORK INFORMATION",
                "=" * 50,
                "",
                f"  Hostname:      {info['hostname']}",
                f"  FQDN:          {info['fqdn']}",
                f"  Local IP:      {info['local_ip']}",
                f"  Gateway:       {info['gateway'] or 'N/A'}",
                "",
                "-" * 50,
                "  📡 NETWORK INTERFACES",
                "-" * 50,
                ""
            ]
            
            for iface in info['interfaces']:
                if 'error' in iface:
                    continue
                lines.append(f"  [{iface['name']}]")
                if iface.get('ipv4'):
                    lines.append(f"    IPv4:    {iface['ipv4']}")
                if iface.get('netmask'):
                    lines.append(f"    Netmask: {iface['netmask']}")
                if iface.get('mac'):
                    lines.append(f"    MAC:     {iface['mac']}")
                if iface.get('speed'):
                    lines.append(f"    Speed:   {iface['speed']} Mbps")
                status = "🟢 UP" if iface.get('is_up') else "🔴 DOWN"
                lines.append(f"    Status:  {status}")
                lines.append("")
            
            self.network_result.delete("1.0", "end")
            self.network_result.insert("1.0", "\n".join(lines))
            self._set_status("Network info loaded")
        
        threading.Thread(target=task, daemon=True).start()
    
    def on_log_entry(self, entry: dict):
        """Callback for new log entries"""
        log_line = f"[{entry['timestamp']}] {entry['action']} - {entry['result']}\n"
        if entry['details']:
            log_line += f"   {entry['details']}\n"
        
        self.log_display.insert("end", log_line)
        self.log_display.see("end")
    
    # === ACTION METHODS ===
    
    def _run_ping(self):
        """Execute ping test"""
        target = self.ping_target.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target IP or hostname")
            return
        
        try:
            count = int(self.ping_count.get().strip() or "4")
        except ValueError:
            count = 4
        
        self._set_status(f"Pinging {target}...")
        self.ping_btn.configure(state="disabled")
        
        def task():
            result = ping_tester.ping_host(target, count)
            
            lines = [
                f"Ping results for {target}",
                "=" * 40,
                ""
            ]
            
            if result['success']:
                lines.extend([
                    f"✅ Status: SUCCESS",
                    f"📦 Packets: {result['packets_sent']} sent, {result['packets_received']} received",
                    f"📉 Packet Loss: {result['packet_loss']}%",
                    "",
                    f"⏱️ Latency:",
                    f"   Min: {result['min_ms']} ms",
                    f"   Avg: {result['avg_ms']} ms",
                    f"   Max: {result['max_ms']} ms"
                ])
                self.logger.log_ping(target, True, result['avg_ms'])
            else:
                lines.extend([
                    f"❌ Status: FAILED",
                    f"Error: {result['error'] or 'No response'}"
                ])
                self.logger.log_ping(target, False)
            
            self.ping_result.delete("1.0", "end")
            self.ping_result.insert("1.0", "\n".join(lines))
            self._set_status("Ping complete")
            self.ping_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_port_scan(self):
        """Execute port range scan"""
        target = self.scan_target.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target IP")
            return
        
        try:
            start = int(self.port_start.get().strip() or "1")
            end = int(self.port_end.get().strip() or "1024")
        except ValueError:
            messagebox.showerror("Invalid Input", "Port numbers must be integers")
            return
        
        if start > end or start < 1 or end > 65535:
            messagebox.showerror("Invalid Range", "Invalid port range")
            return
        
        self._set_status(f"Scanning ports {start}-{end} on {target}...")
        self.scan_btn.configure(state="disabled")
        self.scan_common_btn.configure(state="disabled")
        self.scan_progress.set(0)
        
        def progress_callback(current, total, result):
            progress = current / total
            self.scan_progress.set(progress)
            self._set_status(f"Scanning port {result['port']}... ({current}/{total})")
        
        def task():
            results = port_scanner.scan_port_range(target, start, end, progress_callback)
            open_ports = port_scanner.get_open_ports(results)
            
            lines = [
                f"Port Scan Results for {target}",
                f"Range: {start}-{end}",
                "=" * 50,
                ""
            ]
            
            if open_ports:
                lines.append(f"🟢 Found {len(open_ports)} open port(s):")
                lines.append("")
                for p in open_ports:
                    lines.append(f"  Port {p['port']:5d}  |  {p['service']}")
                    self.logger.log_port_scan(target, p['port'], 'open', p['service'])
            else:
                lines.append("❌ No open ports found in the specified range")
            
            self.ping_result.delete("1.0", "end")
            self.ping_result.insert("1.0", "\n".join(lines))
            self._set_status(f"Scan complete - {len(open_ports)} open ports")
            self.scan_btn.configure(state="normal")
            self.scan_common_btn.configure(state="normal")
            self.scan_progress.set(1)
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_common_scan(self):
        """Scan common ports"""
        target = self.scan_target.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target IP")
            return
        
        self._set_status(f"Scanning common ports on {target}...")
        self.scan_btn.configure(state="disabled")
        self.scan_common_btn.configure(state="disabled")
        
        def progress_callback(current, total, result):
            self.scan_progress.set(current / total)
        
        def task():
            results = port_scanner.scan_common_ports(target, progress_callback)
            open_ports = port_scanner.get_open_ports(results)
            
            lines = [
                f"Common Port Scan for {target}",
                "=" * 50,
                ""
            ]
            
            if open_ports:
                lines.append(f"🟢 Found {len(open_ports)} open port(s):")
                lines.append("")
                for p in open_ports:
                    lines.append(f"  Port {p['port']:5d}  |  {p['service']}")
                    self.logger.log_port_scan(target, p['port'], 'open', p['service'])
            else:
                lines.append("❌ No common ports are open")
            
            self.ping_result.delete("1.0", "end")
            self.ping_result.insert("1.0", "\n".join(lines))
            self._set_status("Common port scan complete")
            self.scan_btn.configure(state="normal")
            self.scan_common_btn.configure(state="normal")
            self.scan_progress.set(1)
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_dns_lookup(self):
        """Execute DNS lookup"""
        hostname = self.dns_hostname.get().strip()
        if not hostname:
            messagebox.showwarning("Input Required", "Please enter a hostname")
            return
        
        self._set_status(f"Resolving {hostname}...")
        self.dns_btn.configure(state="disabled")
        
        def task():
            result = dns_lookup.resolve_hostname(hostname)
            
            lines = [
                f"DNS Lookup: {hostname}",
                "=" * 50,
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ Error: {result['error']}")
                self.logger.log_dns(hostname, "Failed", result['error'])
            else:
                if result['ipv4']:
                    lines.append("📍 IPv4 Addresses:")
                    for ip in result['ipv4']:
                        lines.append(f"   {ip}")
                
                if result['ipv6']:
                    lines.append("\n📍 IPv6 Addresses:")
                    for ip in result['ipv6']:
                        lines.append(f"   {ip}")
                
                self.logger.log_dns(hostname, "Success", ", ".join(result['ip_addresses'][:3]))
            
            self.dns_result.delete("1.0", "end")
            self.dns_result.insert("1.0", "\n".join(lines))
            self._set_status("DNS lookup complete")
            self.dns_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_reverse_dns(self):
        """Execute reverse DNS lookup"""
        ip = self.rdns_ip.get().strip()
        if not ip:
            messagebox.showwarning("Input Required", "Please enter an IP address")
            return
        
        self._set_status(f"Reverse lookup for {ip}...")
        self.rdns_btn.configure(state="disabled")
        
        def task():
            result = dns_lookup.reverse_lookup(ip)
            
            lines = [
                f"Reverse DNS: {ip}",
                "=" * 50,
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ Error: {result['error']}")
            else:
                lines.append(f"🏷️ Hostname: {result['hostname']}")
                if result['aliases']:
                    lines.append(f"📋 Aliases: {', '.join(result['aliases'])}")
            
            self.dns_result.delete("1.0", "end")
            self.dns_result.insert("1.0", "\n".join(lines))
            self._set_status("Reverse lookup complete")
            self.rdns_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_traceroute(self):
        """Execute traceroute"""
        target = self.trace_target.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a target")
            return
        
        self._set_status(f"Tracing route to {target}...")
        self.trace_btn.configure(state="disabled")
        
        def task():
            result = do_traceroute(target)
            
            lines = [
                f"Traceroute to {target}",
                "=" * 50,
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ Error: {result['error']}")
            else:
                lines.append(f"{'Hop':<5} {'IP Address':<20} {'Avg Latency':<15}")
                lines.append("-" * 45)
                
                for hop in result['hops']:
                    ip = hop['ip'] if hop['ip'] != '*' else 'Request timed out'
                    latency = f"{hop['avg_ms']:.1f} ms" if hop['avg_ms'] else "*"
                    lines.append(f"{hop['hop']:<5} {ip:<20} {latency:<15}")
                
                status = "✅ Complete" if result['complete'] else "⚠️ Incomplete"
                lines.append("")
                lines.append(f"Status: {status} ({len(result['hops'])} hops)")
                
                self.logger.log_traceroute(target, len(result['hops']))
            
            self.adv_result.delete("1.0", "end")
            self.adv_result.insert("1.0", "\n".join(lines))
            self._set_status("Traceroute complete")
            self.trace_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_whois(self):
        """Execute WHOIS lookup"""
        target = self.whois_target.get().strip()
        if not target:
            messagebox.showwarning("Input Required", "Please enter a domain or IP")
            return
        
        self._set_status(f"WHOIS lookup for {target}...")
        self.whois_btn.configure(state="disabled")
        
        def task():
            # Check if IP or domain
            ip_check = dns_lookup.validate_ip(target)
            
            if ip_check['valid']:
                result = whois_lookup.lookup_ip(target)
                lines = [
                    f"WHOIS Lookup: {target} (IP)",
                    "=" * 50,
                    ""
                ]
                if result['error']:
                    lines.append(f"❌ Error: {result['error']}")
                else:
                    if result['organization']:
                        lines.append(f"🏢 Organization: {result['organization']}")
                    if result['network']:
                        lines.append(f"🌐 Network: {result['network']}")
                    if result['country']:
                        lines.append(f"🌍 Country: {result['country']}")
                    if result['cidr']:
                        lines.append(f"📊 CIDR: {result['cidr']}")
            else:
                result = whois_lookup.lookup_domain(target)
                lines = [
                    f"WHOIS Lookup: {target} (Domain)",
                    "=" * 50,
                    ""
                ]
                if result['error']:
                    lines.append(f"❌ Error: {result['error']}")
                else:
                    if result['registrar']:
                        lines.append(f"🏢 Registrar: {result['registrar']}")
                    if result['creation_date']:
                        lines.append(f"📅 Created: {result['creation_date']}")
                    if result['expiration_date']:
                        lines.append(f"⏰ Expires: {result['expiration_date']}")
                    if result['name_servers']:
                        lines.append(f"🌐 Name Servers:")
                        for ns in result['name_servers'][:5]:
                            lines.append(f"   - {ns}")
            
            self.logger.log_whois(target, result.get('error') is None)
            
            self.adv_result.delete("1.0", "end")
            self.adv_result.insert("1.0", "\n".join(lines))
            self._set_status("WHOIS lookup complete")
            self.whois_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_service_detect(self):
        """Execute service detection"""
        host = self.svc_host.get().strip()
        port_str = self.svc_port.get().strip()
        
        if not host or not port_str:
            messagebox.showwarning("Input Required", "Please enter host and port")
            return
        
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Invalid Input", "Port must be a number")
            return
        
        self._set_status(f"Detecting service on {host}:{port}...")
        self.svc_btn.configure(state="disabled")
        
        def task():
            result = service_detector.detect_service(host, port)
            
            lines = [
                f"Service Detection: {host}:{port}",
                "=" * 50,
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ Error: {result['error']}")
            else:
                lines.append(f"🔧 Service: {result['service'] or 'Unknown'}")
                if result['banner']:
                    lines.append(f"\n📋 Banner:")
                    lines.append("-" * 40)
                    # Truncate long banners
                    banner = result['banner'][:500]
                    lines.append(banner)
            
            self.adv_result.delete("1.0", "end")
            self.adv_result.insert("1.0", "\n".join(lines))
            self._set_status("Service detection complete")
            self.svc_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_speed_test(self):
        """Execute speed test"""
        self._set_status("Running speed test...")
        self.speed_btn.configure(state="disabled")
        self.speed_progress.set(0)
        self.speed_label.configure(text="Testing download speed...")
        
        def progress_callback(downloaded, total, current_speed):
            progress = downloaded / total if total > 0 else 0
            self.speed_progress.set(progress)
            self.speed_label.configure(text=f"Speed: {current_speed:.2f} Mbps")
        
        def task():
            result = speed_test.test_download_speed(callback=progress_callback)
            
            lines = [
                "Speed Test Results",
                "=" * 50,
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ Error: {result['error']}")
                self.speed_label.configure(text="Test failed")
            else:
                lines.extend([
                    f"📥 Download Speed: {result['speed_mbps_formatted']}",
                    f"📦 File Size: {result['file_size_mb']} MB",
                    f"⏱️ Download Time: {result['download_time_sec']} seconds"
                ])
                
                self.speed_label.configure(text=f"✅ {result['speed_mbps_formatted']}")
                self.logger.log_speed_test(result['speed_mbps'])
            
            self.adv_result.delete("1.0", "end")
            self.adv_result.insert("1.0", "\n".join(lines))
            self._set_status("Speed test complete")
            self.speed_btn.configure(state="normal")
            self.speed_progress.set(1)
        
        threading.Thread(target=task, daemon=True).start()
    
    def _export_logs(self):
        """Export logs to file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"PyNetScanner_Log_{self.logger.session_start.strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filepath:
            try:
                saved_path = self.logger.export_to_file(filepath)
                messagebox.showinfo("Success", f"Logs exported to:\n{saved_path}")
                self._set_status("Logs exported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def _clear_logs(self):
        """Clear all logs"""
        if messagebox.askyesno("Confirm", "Clear all logs?"):
            self.logger.clear()
            self.log_display.delete("1.0", "end")
            self._set_status("Logs cleared")
    
    # === DISCOVERY TAB METHODS ===
    
    def _run_host_discovery(self):
        """Run network host discovery"""
        network = self.network_range.get().strip() or None
        
        self._set_status("Discovering hosts on network...")
        self.discover_btn.configure(state="disabled")
        self.discover_progress.set(0)
        self.discover_label.configure(text="Scanning...")
        
        def progress_callback(current, total, host_info):
            progress = current / total if total > 0 else 0
            self.discover_progress.set(progress)
            self.discover_label.configure(text=f"Scanned {current}/{total}")
        
        def task():
            result = host_discovery.discover_hosts(network, progress_callback)
            
            lines = [
                f"Host Discovery Results",
                f"Network: {result['network']}",
                "=" * 50,
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ Error: {result['error']}")
            else:
                lines.append(f"🔍 Scanned {result['total_scanned']} addresses")
                lines.append(f"✅ Found {result['total_found']} active host(s)")
                lines.append("")
                lines.append(f"{'IP Address':<18} {'Hostname':<25} {'MAC':<20}")
                lines.append("-" * 65)
                
                for host in result['hosts']:
                    ip = host['ip']
                    hostname = host.get('hostname') or 'N/A'
                    mac = host.get('mac') or 'N/A'
                    
                    # Truncate long hostnames
                    if len(hostname) > 23:
                        hostname = hostname[:20] + "..."
                    
                    lines.append(f"{ip:<18} {hostname:<25} {mac:<20}")
                
                self.logger.log("Host Discovery", "Complete", f"Found {result['total_found']} hosts")
            
            self.discovery_result.delete("1.0", "end")
            self.discovery_result.insert("1.0", "\n".join(lines))
            self._set_status(f"Discovery complete - {result['total_found']} hosts found")
            self.discover_btn.configure(state="normal")
            self.discover_progress.set(1)
            self.discover_label.configure(text=f"Found {result['total_found']} hosts")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_mac_lookup(self):
        """Lookup MAC address vendor"""
        mac = self.mac_address.get().strip()
        if not mac:
            messagebox.showwarning("Input Required", "Please enter a MAC address")
            return
        
        self._set_status(f"Looking up vendor for {mac}...")
        self.mac_btn.configure(state="disabled")
        
        def task():
            result = mac_lookup.lookup_vendor(mac)
            
            lines = [
                f"MAC Vendor Lookup",
                "=" * 50,
                "",
                f"🔍 MAC Address: {mac}",
                f"📊 Normalized:  {result['mac_normalized']}",
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ {result['error']}")
            else:
                lines.append(f"🏭 Vendor: {result['vendor']}")
                lines.append(f"📡 Source: {result['source']}")
                self.logger.log("MAC Lookup", "Success", f"{mac} = {result['vendor']}")
            
            self.discovery_result.delete("1.0", "end")
            self.discovery_result.insert("1.0", "\n".join(lines))
            self._set_status("MAC lookup complete")
            self.mac_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_geoip(self):
        """Lookup IP geolocation"""
        ip = self.geo_ip.get().strip()
        if not ip:
            messagebox.showwarning("Input Required", "Please enter an IP address")
            return
        
        self._set_status(f"Locating {ip}...")
        self.geo_btn.configure(state="disabled")
        
        def task():
            result = geoip.get_ip_location(ip)
            
            lines = [
                f"GeoIP Location",
                "=" * 50,
                "",
                f"🔍 IP Address: {ip}",
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ {result['error']}")
            else:
                if result['city']:
                    lines.append(f"🏙️ City: {result['city']}")
                if result['region']:
                    lines.append(f"📍 Region: {result['region']}")
                if result['country']:
                    lines.append(f"🌍 Country: {result['country']} ({result.get('country_code', '')})")
                if result['timezone']:
                    lines.append(f"🕐 Timezone: {result['timezone']}")
                if result['isp']:
                    lines.append(f"🌐 ISP: {result['isp']}")
                if result['org']:
                    lines.append(f"🏢 Org: {result['org']}")
                if result['latitude'] and result['longitude']:
                    lines.append(f"📌 Coords: {result['latitude']}, {result['longitude']}")
                
                self.logger.log("GeoIP", "Success", geoip.format_location(result))
            
            self.discovery_result.delete("1.0", "end")
            self.discovery_result.insert("1.0", "\n".join(lines))
            self._set_status("GeoIP lookup complete")
            self.geo_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()
    
    def _run_my_ip(self):
        """Get my public IP and location"""
        self._set_status("Getting public IP...")
        self.myip_btn.configure(state="disabled")
        
        def task():
            result = geoip.get_my_public_ip()
            
            lines = [
                "My Public IP & Location",
                "=" * 50,
                ""
            ]
            
            if result['error']:
                lines.append(f"❌ Error: {result['error']}")
            else:
                lines.append(f"🌐 Public IP: {result['ip']}")
                lines.append("")
                
                if result['location']:
                    loc = result['location']
                    if loc.get('city'):
                        lines.append(f"🏙️ City: {loc['city']}")
                    if loc.get('region'):
                        lines.append(f"📍 Region: {loc['region']}")
                    if loc.get('country'):
                        lines.append(f"🌍 Country: {loc['country']}")
                    if loc.get('isp'):
                        lines.append(f"🌐 ISP: {loc['isp']}")
                    if loc.get('timezone'):
                        lines.append(f"🕐 Timezone: {loc['timezone']}")
                
                self.logger.log("My IP", "Success", f"{result['ip']}")
            
            self.discovery_result.delete("1.0", "end")
            self.discovery_result.insert("1.0", "\n".join(lines))
            self._set_status("Public IP lookup complete")
            self.myip_btn.configure(state="normal")
        
        threading.Thread(target=task, daemon=True).start()


def run_app():
    """Entry point to run the application"""
    app = PyNetScannerApp()
    app.mainloop()


if __name__ == "__main__":
    run_app()
