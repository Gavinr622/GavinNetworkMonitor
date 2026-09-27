import csv
import socket
import threading
import queue
import time
import subprocess
import re
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from html.parser import HTMLParser
from pathlib import Path

from scapy.all import (
    sniff,
    get_if_list,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    ARP,
    Ether,
)

from cmd.cmd import AdminCommandRunner, ADMIN_COMMANDS

try:
    from loading_screen import (
        MIN_LOADING_SECONDS,
        LOADING_LINES as CUSTOM_LOADING_LINES,
        LOADING_BG,
        LOADING_ACCENT,
        LOADING_TITLE,
        LOADING_SUBTITLE,
        SPINNER_INTERVAL_MS,
    )
except Exception:
    MIN_LOADING_SECONDS = 3.0
    CUSTOM_LOADING_LINES = []
    LOADING_BG = "#171a21"
    LOADING_ACCENT = "#66c0f4"
    LOADING_TITLE = "GAVIN"
    LOADING_SUBTITLE = "NETWORK MONITOR"
    SPINNER_INTERVAL_MS = 80

APP_NAME = "Gavin Network Monitor"
VERSION = "7.3"

# Built-in application admin credentials.
# NOTE: This is an app-level gate, not a secure system authentication system.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "Admin"

BG = "#090d12"
PANEL = "#101720"
PANEL2 = "#151e29"
INPUT = "#1a2531"
BORDER = "#2a3949"
TEXT = "#eaf1f8"
MUTED = "#8fa0b2"
BLUE = "#3aa7ff"
BLUE2 = "#176eaf"
GREEN = "#32d583"
RED = "#ff5b6e"
ORANGE = "#ffad4d"
PURPLE = "#b58cff"
WATCH_BG = "#30270e"

capture_running = False
capture_thread = None
packet_counter = 0
byte_counter = 0

captured_packets = []
domain_matches = []

watch_domains = {}
ip_to_domains = {}

packet_queue = queue.Queue()
console_queue = queue.Queue()


PROTOCOL_INFO = {
    "TCP": ("Transmission Control Protocol",
            "Reliable connection-oriented transport protocol."),
    "UDP": ("User Datagram Protocol",
            "Fast connectionless transport protocol."),
    "ICMP": ("Internet Control Message Protocol",
             "Used for diagnostics such as ping."),
    "ARP": ("Address Resolution Protocol",
            "Maps IPv4 addresses to MAC addresses on a local network."),
    "IPv4": ("Internet Protocol version 4",
             "Provides IPv4 addressing and routing."),
    "IPv6": ("Internet Protocol version 6",
             "Modern IP protocol with a much larger address space."),
    "ETHERNET": ("Ethernet",
                 "Layer-2 network framing."),
    "DNS": ("Domain Name System",
            "Translates domain names into IP addresses."),
    "HTTP": ("Hypertext Transfer Protocol",
             "Web protocol commonly associated with TCP port 80."),
    "HTTPS/TLS": ("HTTPS / TLS",
                  "Encrypted web traffic. Metadata remains visible."),
    "DHCP": ("Dynamic Host Configuration Protocol",
             "Provides devices with network configuration."),
    "mDNS": ("Multicast DNS",
             "Local-network name discovery."),
}


def safe_text(value):
    try:
        return str(value)
    except Exception:
        return "?"


def get_protocol(packet):
    if packet.haslayer(TCP):
        sport, dport = packet[TCP].sport, packet[TCP].dport
        if sport == 80 or dport == 80:
            return "HTTP"
        if sport == 443 or dport == 443:
            return "HTTPS/TLS"
        return "TCP"

    if packet.haslayer(UDP):
        sport, dport = packet[UDP].sport, packet[UDP].dport
        if sport == 53 or dport == 53:
            return "DNS"
        if sport in (67, 68) or dport in (67, 68):
            return "DHCP"
        if sport == 5353 or dport == 5353:
            return "mDNS"
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return "IPv4"
    if packet.haslayer(Ether):
        return "ETHERNET"
    return "OTHER"


def get_addresses(packet):
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    if packet.haslayer(ARP):
        return packet[ARP].psrc, packet[ARP].pdst
    if packet.haslayer(Ether):
        return packet[Ether].src, packet[Ether].dst
    return "?", "?"


def get_ports(packet):
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport
    return "", ""


def resolve_domain(domain):
    domain = domain.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    if not domain:
        return []

    try:
        results = socket.getaddrinfo(
            domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
        return sorted(set(result[4][0] for result in results))
    except Exception:
        return []


def rebuild_ip_map():
    global ip_to_domains
    ip_to_domains = {}
    for domain, ips in watch_domains.items():
        for ip in ips:
            ip_to_domains.setdefault(ip, []).append(domain)


def add_watch_target(target):
    target = target.strip().lower()
    if not target:
        return False, "No domain or IP supplied."

    # Direct IP watch target.
    try:
        socket.inet_pton(socket.AF_INET, target)
        watch_domains[target] = {target}
        rebuild_ip_map()
        return True, f"Watching IP {target}"
    except OSError:
        pass

    try:
        socket.inet_pton(socket.AF_INET6, target)
        watch_domains[target] = {target}
        rebuild_ip_map()
        return True, f"Watching IP {target}"
    except OSError:
        pass

    ips = resolve_domain(target)
    if not ips:
        return False, f"Could not resolve {target}"

    watch_domains[target] = set(ips)
    rebuild_ip_map()
    return True, f"{target} -> {', '.join(ips)}"


def remove_watch_target(target):
    target = target.strip().lower()
    if target in watch_domains:
        del watch_domains[target]
        rebuild_ip_map()
        return True
    return False


def get_watch_matches(src, dst):
    matches = set()
    if src in ip_to_domains:
        matches.update(ip_to_domains[src])
    if dst in ip_to_domains:
        matches.update(ip_to_domains[dst])
    return sorted(matches)


def build_header_text(packet):
    lines = ["========== PACKET HEADERS =========="]

    if packet.haslayer(Ether):
        eth = packet[Ether]
        lines += [
            "",
            "[ Ethernet ]",
            f"Source MAC:       {safe_text(eth.src)}",
            f"Destination MAC:  {safe_text(eth.dst)}",
            f"EtherType:        {safe_text(eth.type)}",
        ]

    if packet.haslayer(IP):
        ip = packet[IP]
        lines += [
            "",
            "[ IPv4 ]",
            f"Version:          {safe_text(ip.version)}",
            f"Header Length:    {safe_text(ip.ihl)}",
            f"TTL:              {safe_text(ip.ttl)}",
            f"Protocol:         {safe_text(ip.proto)}",
            f"Source:           {safe_text(ip.src)}",
            f"Destination:      {safe_text(ip.dst)}",
            f"Identification:   {safe_text(ip.id)}",
            f"Flags:            {safe_text(ip.flags)}",
            f"Fragment Offset:  {safe_text(ip.frag)}",
            f"Total Length:     {safe_text(ip.len)}",
        ]

    if packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        lines += [
            "",
            "[ IPv6 ]",
            f"Version:          {safe_text(ip6.version)}",
            f"Traffic Class:    {safe_text(ip6.tc)}",
            f"Flow Label:       {safe_text(ip6.fl)}",
            f"Hop Limit:        {safe_text(ip6.hlim)}",
            f"Next Header:      {safe_text(ip6.nh)}",
            f"Source:           {safe_text(ip6.src)}",
            f"Destination:      {safe_text(ip6.dst)}",
        ]

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        lines += [
            "",
            "[ TCP ]",
            f"Source Port:      {safe_text(tcp.sport)}",
            f"Destination Port: {safe_text(tcp.dport)}",
            f"Sequence:         {safe_text(tcp.seq)}",
            f"Acknowledgment:   {safe_text(tcp.ack)}",
            f"Data Offset:      {safe_text(tcp.dataofs)}",
            f"Flags:            {safe_text(tcp.flags)}",
            f"Window:           {safe_text(tcp.window)}",
            f"Urgent Pointer:   {safe_text(tcp.urgptr)}",
        ]

    if packet.haslayer(UDP):
        udp = packet[UDP]
        lines += [
            "",
            "[ UDP ]",
            f"Source Port:      {safe_text(udp.sport)}",
            f"Destination Port: {safe_text(udp.dport)}",
            f"Length:           {safe_text(udp.len)}",
            f"Checksum:         {safe_text(udp.chksum)}",
        ]

    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        lines += [
            "",
            "[ ICMP ]",
            f"Type:             {safe_text(icmp.type)}",
            f"Code:             {safe_text(icmp.code)}",
            f"Checksum:         {safe_text(icmp.chksum)}",
        ]

    if packet.haslayer(ARP):
        arp = packet[ARP]
        lines += [
            "",
            "[ ARP ]",
            f"Operation:        {safe_text(arp.op)}",
            f"Sender MAC:       {safe_text(arp.hwsrc)}",
            f"Sender IP:        {safe_text(arp.psrc)}",
            f"Target MAC:       {safe_text(arp.hwdst)}",
            f"Target IP:        {safe_text(arp.pdst)}",
        ]

    lines += [
        "",
        "[ Capture ]",
        f"Packet Length:    {len(packet)} bytes",
        "Payload:          [not displayed]",
    ]
    return "\n".join(lines)


def packet_callback(packet):
    if not capture_running:
        return

    try:
        src, dst = get_addresses(packet)
        sport, dport = get_ports(packet)
        matches = get_watch_matches(src, dst)

        item = {
            "time": time.strftime("%H:%M:%S"),
            "protocol": get_protocol(packet),
            "src": src,
            "sport": sport,
            "dst": dst,
            "dport": dport,
            "bytes": len(packet),
            "watch": ", ".join(matches),
            "headers": build_header_text(packet),
        }

        packet_queue.put(item)
    except Exception:
        pass


def capture_worker(interface):
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            stop_filter=lambda p: not capture_running,
        )
    except Exception as e:
        console_queue.put(f"Capture error: {e}")


def get_windows_adapters():
    adapters = []
    try:
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            (
                "Get-NetAdapter | "
                "Select-Object Name,InterfaceDescription,"
                "InterfaceGuid,Status,MacAddress | "
                "ConvertTo-Csv -NoTypeInformation"
            ),
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        lines = result.stdout.strip().splitlines()
        if len(lines) > 1:
            for row in csv.DictReader(lines):
                adapters.append(row)
    except Exception:
        pass
    return adapters


def get_interfaces():
    scapy_interfaces = get_if_list()
    windows_adapters = get_windows_adapters()
    result = []

    for iface in scapy_interfaces:
        friendly = iface
        match = re.search(r"\{([0-9A-Fa-f-]{36})\}", iface)

        if match:
            guid = match.group(1).lower()
            for adapter in windows_adapters:
                adapter_guid = safe_text(
                    adapter.get("InterfaceGuid", "")
                ).strip("{}").lower()

                if adapter_guid == guid:
                    name = adapter.get("Name", "")
                    status = adapter.get("Status", "")
                    if name:
                        friendly = f"{name} ({status})"
                    break
        elif "Loopback" in iface:
            friendly = "Npcap Loopback"

        result.append((friendly, iface))

    return result


class GavinNetworkMonitor(tk.Tk):
    def __init__(self):
        super().__init__()

        # Bundled decorative application icon.
        self.app_icon_path = Path(__file__).resolve().parent / "gavin_network_monitor.ico"
        try:
            if self.app_icon_path.exists():
                self.iconbitmap(default=str(self.app_icon_path))
        except Exception:
            pass
        self.workspace_frame = None
        self.workspace_back = None

        # Keep the real application window completely hidden while the
        # separate splash window is shown. This prevents the main GUI from
        # ever appearing underneath or mixing with the loading screen.
        self.title(f"{APP_NAME} {VERSION}")
        self.configure(bg=BG)
        self.fullscreen = True
        self.admin_authenticated = False
        self.admin_command_runner = None
        self.interface_data = []
        self.selected_packet = None
        self.startup_ready = False
        self.loading_started = time.monotonic()
        self.loading_finished = False
        self.loading_splash = None
        self.loading_lines = []
        self.loading_line_index = 0
        self.loading_screen_enabled = True
        self.loading_screen_seconds = float(MIN_LOADING_SECONDS)
        self.loading_cfg = {
            "title": LOADING_TITLE, "subtitle": LOADING_SUBTITLE,
            "bg": LOADING_BG, "accent": LOADING_ACCENT,
            "spinner_interval": SPINNER_INTERVAL_MS,
        }
        self.load_startup_loading_settings()

        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.bind("<F11>", lambda e: self.toggle_fullscreen())
        self.bind("<Escape>", lambda e: self.toggle_fullscreen())

        self.withdraw()
        if self.loading_screen_enabled:
            self.show_loading_screen()
        else:
            self.loading_started = time.monotonic()
        self.after(120, self.start_application)

    def load_startup_loading_settings(self):
        """Read loading-screen preferences before the main UI exists."""
        path = Path(__file__).resolve().parent / "config" / "settings.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
            self.loading_screen_enabled = bool(data.get("loading_screen_enabled", True))
            self.loading_screen_seconds = max(3.0, float(data.get("loading_screen_seconds", MIN_LOADING_SECONDS)))
            self.loading_cfg.update({
                "title": str(data.get("loading_title", LOADING_TITLE)),
                "subtitle": str(data.get("loading_subtitle", LOADING_SUBTITLE)),
                "bg": str(data.get("loading_bg", LOADING_BG)),
                "accent": str(data.get("loading_accent", LOADING_ACCENT)),
                "spinner_interval": max(30, int(data.get("loading_spinner_interval", SPINNER_INTERVAL_MS))),
            })
        except Exception:
            self.loading_screen_enabled = True
            self.loading_screen_seconds = 3.0

    def show_loading_screen(self):
        """Create a completely separate splash before any main widgets are shown."""
        splash = tk.Toplevel(self)
        self.loading_splash = splash
        bg = self.loading_cfg["bg"]; accent = self.loading_cfg["accent"]
        splash.title(f"{APP_NAME} - Loading")
        try:
            if self.app_icon_path.exists(): splash.iconbitmap(default=str(self.app_icon_path))
        except Exception: pass
        splash.configure(bg=bg)
        splash.overrideredirect(True)
        splash.protocol("WM_DELETE_WINDOW", self.close_app)
        sw, sh = splash.winfo_screenwidth(), splash.winfo_screenheight()
        width, height = 780, 440
        splash.geometry(f"{width}x{height}+{(sw-width)//2}+{(sh-height)//2}")
        splash.lift(); splash.attributes("-topmost", True)
        splash.update_idletasks(); splash.focus_force()

        tk.Frame(splash, bg=accent, height=4).pack(fill="x", side="top")
        center = tk.Frame(splash, bg=bg); center.pack(fill="both", expand=True)
        tk.Label(center, text=self.loading_cfg["title"], bg=bg, fg=accent,
                 font=("Segoe UI", 34, "bold")).pack(pady=(60, 0))
        tk.Label(center, text=self.loading_cfg["subtitle"], bg=bg, fg="#d6d7d8",
                 font=("Segoe UI", 15, "bold")).pack(pady=(0, 24))
        self.loading_canvas = tk.Canvas(center, width=74, height=74, bg=bg, highlightthickness=0); self.loading_canvas.pack()
        self.loading_status = tk.Label(center, text="Starting...", bg=bg, fg="#d6d7d8", font=("Segoe UI", 11)); self.loading_status.pack(pady=(18,5))
        self.loading_detail = tk.Label(center, text="Preparing application", bg=bg, fg="#8f98a0", font=("Segoe UI", 9)); self.loading_detail.pack()
        self.loading_percent = tk.Label(center, text="0%", bg=bg, fg=accent, font=("Segoe UI", 9, "bold")); self.loading_percent.pack(pady=(7,0))
        self.loading_lines = list(CUSTOM_LOADING_LINES) if CUSTOM_LOADING_LINES else [
            ("Starting Gavin Network Monitor", "Initializing", 10),
            ("Loading saved configuration", "Reading settings", 25),
            ("Loading admin command system", "Preparing commands", 40),
            ("Building application interface", "Creating interface", 58),
            ("Detecting Npcap network interfaces", "Scanning adapters", 78),
            ("Finalizing startup", "Almost ready", 92),
            ("Ready", "Launching monitor", 100),
        ]
        self.loading_spinner_angle = 0; self.loading_spinner_running = True
        splash.update_idletasks(); self.animate_loading_spinner(); self.animate_loading_stream()

    def animate_loading_spinner(self):
        if not self.loading_splash or not self.loading_splash.winfo_exists() or not self.loading_spinner_running:
            return

        c = self.loading_canvas
        c.delete("spinner")
        cx, cy = 37, 37
        import math
        for i in range(12):
            angle = math.radians(self.loading_spinner_angle + i * 30)
            x = cx + math.cos(angle) * 25
            y = cy + math.sin(angle) * 25
            # Bright head fading into the trail.
            intensity = int(70 + (185 * i / 11))
            color = f"#{intensity:02x}{min(255, intensity + 35):02x}ff"
            r = 3 if i < 3 else 2
            c.create_oval(x-r, y-r, x+r, y+r, fill=color, outline="", tags="spinner")

        self.loading_spinner_angle = (self.loading_spinner_angle + 30) % 360
        self.after(int(self.loading_cfg.get("spinner_interval", SPINNER_INTERVAL_MS)), self.animate_loading_spinner)

    def animate_loading_stream(self):
        if not self.loading_splash or not self.loading_splash.winfo_exists():
            return
        if self.loading_line_index < len(self.loading_lines):
            message, detail, progress = self.loading_lines[self.loading_line_index]
            self.loading_status.config(text=message)
            self.loading_detail.config(text=detail)
            self.loading_percent.config(text=f"{progress}%")
            self.loading_line_index += 1
            self.after(420, self.animate_loading_stream)
        else:
            self.loading_finished = True
            self.loading_status.config(text="Ready")
            self.loading_detail.config(text="Launching monitor...")
            self.loading_percent.config(text="100%")
            self.after(150, self.finish_startup)

    def loading_step(self, status, detail, progress):
        # Update only widgets that belong to the splash.  v7.3 intentionally
        # uses a spinner instead of a ttk progress bar, so never reference a
        # non-existent loading_bar widget.
        if self.loading_splash and self.loading_splash.winfo_exists():
            try:
                self.loading_status.config(text=status)
                self.loading_detail.config(text=detail)
                self.loading_percent.config(text=f"{int(progress)}%")
                self.loading_splash.update_idletasks()
            except tk.TclError:
                pass

    def start_application(self):
        self.loading_step("Loading configuration...", "Reading saved settings", 20)
        self.admin_command_runner = AdminCommandRunner(
            output=self.console_write,
            clear_console=self.clear_admin_console,
        )
        self.after(30, self.build_application_ui)

    def build_application_ui(self):
        self.loading_step("Building interface...", "Creating menus and panels", 45)
        self.create_styles()
        self.create_menu()
        self.create_header()
        self.create_main()
        self.create_statusbar()

        self.loading_step("Applying settings...", "Restoring your saved preferences", 65)
        self.apply_saved_settings()

        self.loading_step("Detecting network interfaces...", "Scanning Npcap adapters in the background", 78)
        self.after(20, self.start_interface_scan)

    def start_interface_scan(self):
        def worker():
            try:
                data = get_interfaces()
                self.after(0, lambda d=data: self.finish_interface_scan(d))
            except Exception as exc:
                self.after(0, lambda e=exc: self.finish_interface_scan([], e))

        threading.Thread(target=worker, daemon=True).start()

    def finish_interface_scan(self, data, error=None):
        self.interface_data = data or []
        names = [x[0] for x in self.interface_data]
        self.interface_box["values"] = names

        if names:
            saved = self.admin_command_runner.settings.get("selected_interface", "")
            if saved in names:
                self.interface_box.current(names.index(saved))
            else:
                self.interface_box.current(0)

        if error:
            self.console_write(f"Interface detection error: {error}")
        else:
            self.console_write(f"Detected {len(names)} capture interface(s).")

        self.loading_step("Finalizing startup...", f"Detected {len(names)} capture interface(s)", 92)

    def finish_startup(self):
        # Enforce a real minimum three-second splash duration. Even if all
        # initialization finishes instantly, the loading screen stays visible
        # for the full three seconds.
        elapsed = time.monotonic() - self.loading_started
        remaining = max(0, float(self.loading_screen_seconds) - elapsed)
        if not self.loading_finished or remaining > 0:
            if self.loading_splash and self.loading_splash.winfo_exists():
                self.after(100, self.finish_startup)
            return

        self.startup_ready = True
        if self.loading_splash and self.loading_splash.winfo_exists():
            try:
                self.loading_splash.grab_release()
            except Exception:
                pass
            self.loading_splash.destroy()
        self.loading_splash = None
        self.deiconify()
        self.attributes("-fullscreen", self.fullscreen)
        self.after(100, self.process_queues)
        self.after(1000, self.update_stats)
        self.after(60000, self.refresh_watch_dns)

    def create_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Dark.TCombobox",
            fieldbackground=INPUT,
            background=INPUT,
            foreground=TEXT,
            arrowcolor=TEXT,
            bordercolor=BORDER,
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", INPUT)],
            foreground=[("readonly", TEXT)],
        )

        style.configure(
            "TNotebook",
            background=BG,
            borderwidth=0,
        )
        style.configure(
            "TNotebook.Tab",
            background=PANEL2,
            foreground=MUTED,
            padding=(18, 10),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", BLUE2)],
            foreground=[("selected", "white")],
        )

        style.configure(
            "Treeview",
            background="#0f151c",
            foreground=TEXT,
            fieldbackground="#0f151c",
            rowheight=29,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#1c2936",
            foreground=TEXT,
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Treeview",
            background=[("selected", BLUE2)],
            foreground=[("selected", "white")],
        )

    def create_menu(self):
        menubar = tk.Menu(
            self,
            bg=PANEL,
            fg=TEXT,
            activebackground=BLUE2,
            activeforeground="white",
            tearoff=False,
        )

        file_menu = tk.Menu(menubar, tearoff=False, bg=PANEL, fg=TEXT)
        file_menu.add_command(
            label="Export Live Traffic CSV",
            command=self.export_csv,
        )
        file_menu.add_command(
            label="Export Domain Matches CSV",
            command=self.export_domain_csv,
        )
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.close_app)
        menubar.add_cascade(label="File", menu=file_menu)

        view_menu = tk.Menu(menubar, tearoff=False, bg=PANEL, fg=TEXT)
        view_menu.add_command(
            label="Live Traffic",
            command=lambda: self.notebook.select(self.traffic_tab),
        )
        view_menu.add_command(
            label="Domain Matches",
            command=lambda: self.notebook.select(self.domain_tab),
        )
        view_menu.add_command(
            label="Packet Headers",
            command=lambda: self.notebook.select(self.headers_tab),
        )
        view_menu.add_command(
            label="Command Console",
            command=lambda: self.notebook.select(self.console_tab),
        )
        view_menu.add_separator()
        view_menu.add_command(
            label="Toggle Fullscreen (F11)",
            command=self.toggle_fullscreen,
        )
        menubar.add_cascade(label="View", menu=view_menu)

        tools_menu = tk.Menu(menubar, tearoff=False, bg=PANEL, fg=TEXT)
        tools_menu.add_command(
            label="Domain Watch List",
            command=self.open_watch_window,
        )
        tools_menu.add_command(
            label="Protocol Information",
            command=self.open_protocol_window,
        )
        tools_menu.add_command(
            label="Refresh Interfaces",
            command=self.refresh_interfaces,
        )
        tools_menu.add_separator()
        tools_menu.add_command(
            label="Clear Live Traffic",
            command=self.clear_packets,
        )
        tools_menu.add_command(
            label="Clear Domain Matches",
            command=self.clear_domain_matches,
        )
        menubar.add_cascade(label="Tools", menu=tools_menu)

        admin_menu = tk.Menu(menubar, tearoff=False, bg=PANEL, fg=TEXT)
        admin_menu.add_command(
            label="🔐 Admin Login",
            command=self.admin_login,
        )
        admin_menu.add_command(
            label="🔓 Admin Logout",
            command=self.admin_logout,
        )
        admin_menu.add_command(
            label="ℹ Admin Status",
            command=self.show_admin_status,
        )
        admin_menu.add_separator()
        admin_menu.add_command(
            label="🖥 Admin Command Center",
            command=self.open_admin_command_center,
        )
        admin_menu.add_command(
            label="⚙ Admin Settings",
            command=self.open_admin_settings,
        )
        admin_menu.add_command(
            label="⌘ Custom Commands",
            command=self.open_custom_commands,
        )
        admin_menu.add_command(
            label="🚀 App Shortcuts",
            command=self.open_app_shortcuts,
        )
        menubar.add_cascade(label="Admin", menu=admin_menu)

        help_menu = tk.Menu(menubar, tearoff=False, bg=PANEL, fg=TEXT)
        help_menu.add_command(
            label="📚 Documentation",
            command=self.open_docs,
        )
        help_menu.add_command(
            label="Command Reference",
            command=self.show_command_help,
        )
        help_menu.add_command(
            label="About",
            command=self.show_about,
        )
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def create_header(self):
        header = tk.Frame(self, bg=PANEL, height=82)
        header.pack(fill="x")

        left = tk.Frame(header, bg=PANEL)
        left.pack(side="left", padx=24, pady=12)

        tk.Label(
            left,
            text="◈",
            bg=PANEL,
            fg=BLUE,
            font=("Segoe UI", 30, "bold"),
        ).pack(side="left", padx=(0, 12))

        title_box = tk.Frame(left, bg=PANEL)
        title_box.pack(side="left")

        tk.Label(
            title_box,
            text="Gavin Network Monitor",
            bg=PANEL,
            fg=TEXT,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")

        tk.Label(
            title_box,
            text=f"Network diagnostics  •  v{VERSION}  •  F11 = fullscreen",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        self.capture_indicator = tk.Label(
            header,
            text="● STOPPED",
            bg=PANEL,
            fg=RED,
            font=("Segoe UI", 11, "bold"),
        )
        self.capture_indicator.pack(side="right", padx=25)

    def create_main(self):
        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=12, pady=10)

        sidebar = tk.Frame(container, bg=PANEL, width=190)
        sidebar.pack(side="left", fill="y", padx=(0,10)); sidebar.pack_propagate(False)
        tk.Label(sidebar, text="NAVIGATION", bg=PANEL, fg=MUTED, font=("Segoe UI",9,"bold")).pack(anchor="w", padx=16, pady=(18,8))

        content = tk.Frame(container, bg=BG)
        content.pack(side="left", fill="both", expand=True)
        self.main_content = content
        self.notebook = ttk.Notebook(content)
        self.notebook.pack(fill="both", expand=True)

        self.create_traffic_tab(); self.create_domain_tab(); self.create_headers_tab(); self.create_console_tab()
        self.side_buttons = []
        nav_items = [("📡  Live Traffic", self.traffic_tab), ("🌐  Domain Matches", self.domain_tab), ("📦  Packet Headers", self.headers_tab), ("⌘  Command Console", self.console_tab)]
        for label, tab in nav_items:
            b=tk.Button(sidebar,text=label,command=lambda t=tab:self.notebook.select(t),bg=PANEL,fg=TEXT,activebackground=BLUE2,activeforeground="white",relief="flat",anchor="w",padx=16,pady=10)
            b.pack(fill="x", padx=8, pady=2); self.side_buttons.append(b)
        tk.Frame(sidebar,bg=BORDER,height=1).pack(fill="x",padx=12,pady=12)
        tk.Button(sidebar,text="📚  Documentation",command=self.open_docs,bg=PANEL2,fg=TEXT,activebackground=BLUE2,relief="flat",anchor="w",padx=16,pady=10).pack(fill="x",padx=8,pady=2)
        tk.Button(sidebar,text="⚙  Settings",command=self.open_admin_settings,bg=PANEL2,fg=TEXT,activebackground=BLUE2,relief="flat",anchor="w",padx=16,pady=10).pack(fill="x",padx=8,pady=2)

    def create_traffic_tab(self):
        self.traffic_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.traffic_tab, text="📡  Live Traffic")

        top = tk.Frame(self.traffic_tab, bg=BG)
        top.pack(fill="x", pady=(0, 8))

        tk.Label(
            top, text="Capture interface",
            bg=BG, fg=MUTED,
        ).pack(side="left")

        self.interface_box = ttk.Combobox(
            top,
            state="readonly",
            width=45,
            style="Dark.TCombobox",
        )
        self.interface_box.pack(side="left", padx=8)

        tk.Button(
            top,
            text="▶  START",
            command=self.start_capture,
            bg="#157a48",
            fg="white",
            activebackground="#1b9a5c",
            relief="flat",
            padx=16,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="■  STOP",
            command=self.stop_capture,
            bg="#7d4e18",
            fg="white",
            activebackground="#a66b23",
            relief="flat",
            padx=16,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="↻ Refresh",
            command=self.refresh_interfaces,
            bg=INPUT,
            fg=TEXT,
            relief="flat",
            padx=12,
            pady=7,
        ).pack(side="left", padx=4)

        tk.Button(
            top,
            text="Clear",
            command=self.clear_packets,
            bg=INPUT,
            fg=TEXT,
            relief="flat",
            padx=12,
            pady=7,
        ).pack(side="left", padx=4)

        filters = tk.Frame(
            self.traffic_tab,
            bg=PANEL,
            padx=10,
            pady=9,
        )
        filters.pack(fill="x", pady=(0, 8))

        tk.Label(
            filters, text="🔍 Search",
            bg=PANEL, fg=MUTED,
        ).pack(side="left")

        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(
            filters,
            textvariable=self.search_var,
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            width=38,
        )
        self.search_entry.pack(side="left", padx=8, ipady=4)
        self.search_entry.bind(
            "<KeyRelease>", lambda e: self.refresh_traffic()
        )

        tk.Label(
            filters, text="Protocol",
            bg=PANEL, fg=MUTED,
        ).pack(side="left", padx=(15, 5))

        self.protocol_var = tk.StringVar(value="ALL")
        self.protocol_box = ttk.Combobox(
            filters,
            textvariable=self.protocol_var,
            values=[
                "ALL", "TCP", "UDP", "ICMP", "ARP",
                "IPv4", "IPv6", "DNS", "HTTP",
                "HTTPS/TLS", "DHCP", "mDNS",
            ],
            state="readonly",
            width=15,
            style="Dark.TCombobox",
        )
        self.protocol_box.pack(side="left")
        self.protocol_box.bind(
            "<<ComboboxSelected>>",
            lambda e: self.refresh_traffic(),
        )

        tk.Label(
            filters,
            text="  •  Right-click a row for actions",
            bg=PANEL,
            fg=MUTED,
        ).pack(side="left", padx=15)

        frame = tk.Frame(self.traffic_tab, bg=BG)
        frame.pack(fill="both", expand=True)

        columns = (
            "time", "protocol", "source", "sport",
            "destination", "dport", "bytes", "watch",
        )

        self.traffic_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = [
            ("time", "Time", 80),
            ("protocol", "Protocol", 105),
            ("source", "Source", 180),
            ("sport", "Src Port", 80),
            ("destination", "Destination", 180),
            ("dport", "Dst Port", 80),
            ("bytes", "Bytes", 85),
            ("watch", "Domain Match", 190),
        ]

        for col, heading, width in headings:
            self.traffic_tree.heading(col, text=heading)
            self.traffic_tree.column(
                col, width=width, anchor="center"
            )

        self.traffic_tree.pack(
            side="left", fill="both", expand=True
        )

        scroll = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.traffic_tree.yview,
        )
        scroll.pack(side="right", fill="y")
        self.traffic_tree.configure(
            yscrollcommand=scroll.set
        )

        self.traffic_tree.tag_configure(
            "watch", background=WATCH_BG
        )

        self.traffic_tree.bind(
            "<Double-1>", self.open_selected_headers
        )
        self.traffic_tree.bind(
            "<Button-3>", self.traffic_context_menu
        )

    def create_domain_tab(self):
        self.domain_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(
            self.domain_tab,
            text="🌐  Domain Matches",
        )

        top = tk.Frame(self.domain_tab, bg=BG)
        top.pack(fill="x", pady=(0, 8))

        tk.Label(
            top,
            text="Only traffic matching your watched domains/IPs appears here.",
            bg=BG,
            fg=MUTED,
        ).pack(side="left")

        tk.Button(
            top,
            text="🎯 Watch List",
            command=self.open_watch_window,
            bg=BLUE2,
            fg="white",
            relief="flat",
            padx=14,
            pady=7,
        ).pack(side="right", padx=4)

        tk.Button(
            top,
            text="Export",
            command=self.export_domain_csv,
            bg=INPUT,
            fg=TEXT,
            relief="flat",
            padx=14,
            pady=7,
        ).pack(side="right", padx=4)

        tk.Button(
            top,
            text="Clear",
            command=self.clear_domain_matches,
            bg=INPUT,
            fg=TEXT,
            relief="flat",
            padx=14,
            pady=7,
        ).pack(side="right", padx=4)

        frame = tk.Frame(self.domain_tab, bg=BG)
        frame.pack(fill="both", expand=True)

        columns = (
            "time", "domain", "protocol", "source",
            "sport", "destination", "dport", "bytes",
        )

        self.domain_tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        headings = [
            ("time", "Time", 80),
            ("domain", "Watched Domain", 210),
            ("protocol", "Protocol", 105),
            ("source", "Source", 180),
            ("sport", "Src Port", 80),
            ("destination", "Destination", 180),
            ("dport", "Dst Port", 80),
            ("bytes", "Bytes", 85),
        ]

        for col, heading, width in headings:
            self.domain_tree.heading(col, text=heading)
            self.domain_tree.column(
                col, width=width, anchor="center"
            )

        self.domain_tree.pack(
            side="left", fill="both", expand=True
        )

        scroll = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=self.domain_tree.yview,
        )
        scroll.pack(side="right", fill="y")
        self.domain_tree.configure(
            yscrollcommand=scroll.set
        )

        self.domain_tree.bind(
            "<Double-1>",
            self.open_selected_domain_headers,
        )
        self.domain_tree.bind(
            "<Button-3>",
            self.domain_context_menu,
        )

        self.domain_empty = tk.Label(
            self.domain_tab,
            text=(
                "🎯\n\n"
                "No domain matches yet.\n\n"
                "Add a domain to the watch list,\n"
                "then start capturing traffic."
            ),
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 12),
        )
        self.domain_empty.place(
            relx=0.5, rely=0.5, anchor="center"
        )

    def create_headers_tab(self):
        self.headers_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(
            self.headers_tab,
            text="📦  Packet Headers",
        )

        bar = tk.Frame(self.headers_tab, bg=BG)
        bar.pack(fill="x", pady=(0, 8))

        self.header_title = tk.Label(
            bar,
            text="No packet selected",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 11, "bold"),
        )
        self.header_title.pack(side="left")

        tk.Button(
            bar,
            text="📋 Copy Headers",
            command=self.copy_headers,
            bg=INPUT,
            fg=TEXT,
            relief="flat",
            padx=12,
            pady=6,
        ).pack(side="right")

        self.header_text = tk.Text(
            self.headers_tab,
            bg="#070a0e",
            fg="#dce7f2",
            insertbackground="white",
            font=("Consolas", 10),
            wrap="none",
            relief="flat",
        )
        self.header_text.pack(
            fill="both", expand=True
        )
        self.header_text.insert(
            "1.0",
            "Double-click a packet or use Right-click → View Headers."
        )
        self.header_text.config(state="disabled")

    def create_console_tab(self):
        self.console_tab = tk.Frame(
            self.notebook, bg="#070a0e"
        )
        self.notebook.add(
            self.console_tab,
            text="⌨  Command Console",
        )

        self.console_output = tk.Text(
            self.console_tab,
            bg="#070a0e",
            fg="#72f59a",
            insertbackground="white",
            font=("Consolas", 10),
            relief="flat",
            wrap="word",
        )
        self.console_output.pack(
            fill="both", expand=True,
            padx=10, pady=(10, 5)
        )

        bottom = tk.Frame(
            self.console_tab,
            bg="#070a0e"
        )
        bottom.pack(
            fill="x", padx=10, pady=10
        )

        tk.Label(
            bottom,
            text="GavinNet>",
            bg="#070a0e",
            fg="#72f59a",
            font=("Consolas", 10),
        ).pack(side="left")

        self.console_entry = tk.Entry(
            bottom,
            bg=INPUT,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Consolas", 10),
        )
        self.console_entry.pack(
            side="left",
            fill="x",
            expand=True,
            padx=8,
            ipady=6,
        )
        self.console_entry.bind(
            "<Return>",
            lambda e: self.run_command()
        )

        tk.Button(
            bottom,
            text="RUN",
            command=self.run_command,
            bg=BLUE2,
            fg="white",
            relief="flat",
            padx=16,
        ).pack(side="right")

        self.console_write(
            f"Gavin Network Monitor {VERSION}"
        )
        self.console_write(
            "Type 'help' for commands."
        )

    def create_statusbar(self):
        bar = tk.Frame(
            self, bg=PANEL, height=32
        )
        bar.pack(fill="x")

        self.status_label = tk.Label(
            bar, text="STOPPED",
            bg=PANEL, fg=RED,
            anchor="w",
        )
        self.status_label.pack(
            side="left", padx=12
        )

        self.stats_label = tk.Label(
            bar,
            text="Packets: 0  |  Data: 0 B  |  Domains: 0  |  Matches: 0",
            bg=PANEL,
            fg=MUTED,
        )
        self.stats_label.pack(
            side="right", padx=12
        )

    # -------------------- interface/capture -----------------

    def refresh_interfaces(self):
        if not self.startup_ready or not hasattr(self, "interface_box"):
            return

        self.console_write("Refreshing capture interfaces...")

        def worker():
            try:
                data = get_interfaces()
                self.after(0, lambda d=data: self.finish_interface_scan(d))
            except Exception as exc:
                self.after(0, lambda e=exc: self.finish_interface_scan([], e))

        threading.Thread(target=worker, daemon=True).start()

    def start_capture(self):
        global capture_running, capture_thread

        if capture_running:
            return

        index = self.interface_box.current()
        if index < 0:
            messagebox.showerror(
                "No Interface",
                "Select a capture interface first."
            )
            return

        name, interface = self.interface_data[index]
        self.admin_command_runner.settings["selected_interface"] = name

        capture_running = True
        capture_thread = threading.Thread(
            target=capture_worker,
            args=(interface,),
            daemon=True,
        )
        capture_thread.start()

        self.capture_indicator.config(
            text="● CAPTURING", fg=GREEN
        )
        self.status_label.config(
            text=f"CAPTURING  •  {name}"
        )
        self.console_write(
            f"Capture started: {name}"
        )

    def stop_capture(self):
        global capture_running
        capture_running = False

        self.capture_indicator.config(
            text="● STOPPED", fg=RED
        )
        self.status_label.config(
            text="STOPPED"
        )
        self.console_write(
            "Capture stopped."
        )

    # ----------------------- queues -------------------------

    def process_queues(self):
        global packet_counter, byte_counter

        changed = False

        for _ in range(500):
            try:
                item = packet_queue.get_nowait()
            except queue.Empty:
                break

            captured_packets.append(item)
            packet_counter += 1
            byte_counter += item["bytes"]

            if item["watch"]:
                domain_matches.append(item)

            changed = True

        while True:
            try:
                self.console_write(
                    console_queue.get_nowait()
                )
            except queue.Empty:
                break

        if changed:
            self.refresh_traffic()
            self.refresh_domain_matches()

        self.after(100, self.process_queues)

    # ------------------------ tables ------------------------

    def refresh_traffic(self):
        search = self.search_var.get().lower()
        protocol = self.protocol_var.get()

        for row in self.traffic_tree.get_children():
            self.traffic_tree.delete(row)

        for item in reversed(captured_packets[-3000:]):
            if protocol != "ALL" and item["protocol"] != protocol:
                continue

            searchable = (
                f"{item['time']} {item['protocol']} "
                f"{item['src']} {item['sport']} "
                f"{item['dst']} {item['dport']} "
                f"{item['watch']}"
            ).lower()

            if search and search not in searchable:
                continue

            values = (
                item["time"],
                item["protocol"],
                item["src"],
                item["sport"],
                item["dst"],
                item["dport"],
                item["bytes"],
                item["watch"],
            )

            self.traffic_tree.insert(
                "",
                "end",
                values=values,
                tags=("watch",) if item["watch"] else (),
            )

    def refresh_domain_matches(self):
        for row in self.domain_tree.get_children():
            self.domain_tree.delete(row)

        if domain_matches:
            self.domain_empty.place_forget()
        else:
            self.domain_empty.place(
                relx=0.5, rely=0.5, anchor="center"
            )

        for item in reversed(domain_matches[-3000:]):
            self.domain_tree.insert(
                "",
                "end",
                values=(
                    item["time"],
                    item["watch"],
                    item["protocol"],
                    item["src"],
                    item["sport"],
                    item["dst"],
                    item["dport"],
                    item["bytes"],
                ),
            )

    # -------------------- row lookup ------------------------

    def find_packet_from_traffic_row(self, values):
        if not values:
            return None

        for item in reversed(captured_packets):
            if (
                str(item["time"]) == str(values[0])
                and item["protocol"] == str(values[1])
                and item["src"] == str(values[2])
                and item["dst"] == str(values[4])
                and str(item["bytes"]) == str(values[6])
            ):
                return item
        return None

    def find_domain_packet(self, values):
        if not values:
            return None

        for item in reversed(domain_matches):
            if (
                str(item["time"]) == str(values[0])
                and item["watch"] == str(values[1])
                and item["src"] == str(values[3])
                and item["dst"] == str(values[5])
                and str(item["bytes"]) == str(values[7])
            ):
                return item
        return None

    # -------------------- headers ----------------------------

    def show_headers(self, item):
        if not item:
            return

        self.selected_packet = item
        self.notebook.select(self.headers_tab)

        self.header_title.config(
            text=(
                f"{item['protocol']}  •  "
                f"{item['src']}:{item['sport']}  →  "
                f"{item['dst']}:{item['dport']}"
            ),
            fg=BLUE,
        )

        self.header_text.config(state="normal")
        self.header_text.delete("1.0", "end")
        self.header_text.insert("1.0", item["headers"])
        self.header_text.config(state="disabled")

    def open_selected_headers(self, event=None):
        selected = self.traffic_tree.selection()
        if not selected:
            return

        values = self.traffic_tree.item(
            selected[0], "values"
        )
        self.show_headers(
            self.find_packet_from_traffic_row(values)
        )

    def open_selected_domain_headers(self, event=None):
        selected = self.domain_tree.selection()
        if not selected:
            return

        values = self.domain_tree.item(
            selected[0], "values"
        )
        self.show_headers(
            self.find_domain_packet(values)
        )

    def copy_headers(self):
        if not self.selected_packet:
            return

        self.clipboard_clear()
        self.clipboard_append(
            self.selected_packet["headers"]
        )
        self.console_write(
            "Packet headers copied to clipboard."
        )

    # ---------------------- admin auth ----------------------

    def require_admin(self, action="perform this admin command"):
        if self.admin_authenticated:
            return True

        messagebox.showwarning(
            "Admin Login Required",
            f"You must log in as admin to {action}.\n\nUse Admin → Admin Login first.",
            parent=self,
        )
        return False

    def admin_login(self):
        if self.admin_authenticated:
            messagebox.showinfo(
                "Admin",
                "You are already logged in as admin.",
                parent=self,
            )
            return

        dialog = tk.Toplevel(self)
        dialog.title("Admin Login")
        dialog.geometry("420x270")
        dialog.resizable(False, False)
        dialog.configure(bg=PANEL)
        dialog.transient(self)
        dialog.grab_set()

        tk.Label(
            dialog, text="🔐 Admin Login", bg=PANEL, fg=TEXT,
            font=("Segoe UI", 18, "bold")
        ).pack(pady=(22, 5))

        tk.Label(
            dialog, text="Admin commands require authentication.",
            bg=PANEL, fg=MUTED, font=("Segoe UI", 9)
        ).pack(pady=(0, 16))

        form = tk.Frame(dialog, bg=PANEL)
        form.pack(fill="x", padx=35)

        tk.Label(form, text="Username", bg=PANEL, fg=TEXT).grid(
            row=0, column=0, sticky="w", pady=7
        )
        username = tk.Entry(
            form, bg=INPUT, fg=TEXT, insertbackground=TEXT, relief="flat"
        )
        username.grid(row=0, column=1, sticky="ew", padx=(15, 0), ipady=5)

        tk.Label(form, text="Password", bg=PANEL, fg=TEXT).grid(
            row=1, column=0, sticky="w", pady=7
        )
        password = tk.Entry(
            form, bg=INPUT, fg=TEXT, insertbackground=TEXT,
            relief="flat", show="•"
        )
        password.grid(row=1, column=1, sticky="ew", padx=(15, 0), ipady=5)
        form.columnconfigure(1, weight=1)

        status = tk.Label(
            dialog, text="", bg=PANEL, fg=RED, font=("Segoe UI", 9)
        )
        status.pack(pady=6)

        def login():
            if (username.get() == ADMIN_USERNAME and
                    password.get() == ADMIN_PASSWORD):
                self.admin_authenticated = True
                self.capture_indicator.config(
                    text="● CAPTURING • ADMIN" if capture_running
                    else "● STOPPED • ADMIN",
                    fg=GREEN
                )
                self.console_write("Admin login successful.")
                dialog.destroy()
            else:
                status.config(text="Invalid username or password.")
                password.delete(0, "end")
                password.focus_set()

        buttons = tk.Frame(dialog, bg=PANEL)
        buttons.pack(pady=8)

        tk.Button(
            buttons, text="LOGIN", command=login, bg=BLUE2, fg="white",
            relief="flat", padx=20, pady=7
        ).pack(side="left", padx=5)

        tk.Button(
            buttons, text="Cancel", command=dialog.destroy, bg=INPUT,
            fg=TEXT, relief="flat", padx=20, pady=7
        ).pack(side="left", padx=5)

        username.focus_set()
        password.bind("<Return>", lambda e: login())
        username.bind("<Return>", lambda e: password.focus_set())

    def admin_logout(self):
        self.admin_authenticated = False
        self.capture_indicator.config(
            text="● CAPTURING" if capture_running else "● STOPPED",
            fg=GREEN if capture_running else RED
        )
        self.console_write("Admin logged out.")

    def show_admin_status(self):
        state = "LOGGED IN" if self.admin_authenticated else "NOT LOGGED IN"
        messagebox.showinfo(
            "Admin Status",
            f"Admin status: {state}\n\nAdmin commands are protected by the app login.",
            parent=self,
        )

    def run_admin_command(self, callback, action):
        if not self.require_admin(action):
            return
        callback()

    # -------------------- context menus ---------------------

    def get_selected_traffic_item(self):
        selected = self.traffic_tree.selection()
        if not selected:
            return None

        values = self.traffic_tree.item(
            selected[0], "values"
        )
        return self.find_packet_from_traffic_row(values)

    def get_selected_domain_item(self):
        selected = self.domain_tree.selection()
        if not selected:
            return None

        values = self.domain_tree.item(
            selected[0], "values"
        )
        return self.find_domain_packet(values)

    def traffic_context_menu(self, event):
        row = self.traffic_tree.identify_row(event.y)
        if not row:
            return

        self.traffic_tree.selection_set(row)
        item = self.get_selected_traffic_item()
        if not item:
            return

        menu = tk.Menu(
            self,
            tearoff=False,
            bg=PANEL,
            fg=TEXT,
            activebackground=BLUE2,
            activeforeground="white",
        )

        menu.add_command(
            label="📦 View Packet Headers",
            command=lambda: self.show_headers(item),
        )

        menu.add_command(
            label="🔎 Copy Source IP",
            command=lambda: self.copy_text(item["src"]),
        )

        menu.add_command(
            label="🔎 Copy Destination IP",
            command=lambda: self.copy_text(item["dst"]),
        )

        menu.add_separator()

        targets = []
        if item["watch"]:
            targets = [
                x.strip()
                for x in item["watch"].split(",")
                if x.strip()
            ]

        target = targets[0] if targets else item["dst"]

        menu.add_command(
            label=f"🎯 Add {target} to Watch List",
            command=lambda t=target: self.add_context_watch(t),
        )

        if targets:
            submenu = tk.Menu(
                menu,
                tearoff=False,
                bg=PANEL,
                fg=TEXT,
            )

            for domain in targets:
                submenu.add_command(
                    label=f"▶ Resolve {domain}",
                    command=lambda d=domain: self.run_domain_command(
                        "resolve", d
                    ),
                )
                submenu.add_command(
                    label=f"▶ Watch {domain}",
                    command=lambda d=domain: self.run_domain_command(
                        "watch", d
                    ),
                )
                submenu.add_command(
                    label=f"▶ Unwatch {domain}",
                    command=lambda d=domain: self.run_domain_command(
                        "unwatch", d
                    ),
                )
                submenu.add_command(
                    label=f"▶ Filter {domain}",
                    command=lambda d=domain: self.run_domain_command(
                        "filter", d
                    ),
                )

            menu.add_cascade(
                label="⌨ Run Command on Domain",
                menu=submenu,
            )

        menu.add_separator()

        menu.add_command(
            label="📋 Open Command Console",
            command=lambda: self.notebook.select(
                self.console_tab
            ),
        )

        menu.tk_popup(event.x_root, event.y_root)

    def domain_context_menu(self, event):
        row = self.domain_tree.identify_row(event.y)
        if not row:
            return

        self.domain_tree.selection_set(row)
        item = self.get_selected_domain_item()
        if not item:
            return

        domain = item["watch"].split(",")[0].strip()

        menu = tk.Menu(
            self,
            tearoff=False,
            bg=PANEL,
            fg=TEXT,
            activebackground=BLUE2,
            activeforeground="white",
        )

        menu.add_command(
            label="📦 View Packet Headers",
            command=lambda: self.show_headers(item),
        )

        menu.add_command(
            label="🎯 Add to Watch List",
            command=lambda: self.add_context_watch(domain),
        )

        menu.add_command(
            label="❌ Remove from Watch List",
            command=lambda: self.remove_context_watch(domain),
        )

        submenu = tk.Menu(
            menu,
            tearoff=False,
            bg=PANEL,
            fg=TEXT,
        )

        for command_name, label in [
            ("resolve", "Resolve"),
            ("watch", "Watch"),
            ("unwatch", "Unwatch"),
            ("filter", "Filter"),
        ]:
            submenu.add_command(
                label=f"▶ {label} {domain}",
                command=lambda c=command_name, d=domain:
                    self.run_domain_command(c, d),
            )

        menu.add_cascade(
            label="⌨ Run Command on Domain",
            menu=submenu,
        )

        menu.add_separator()

        menu.add_command(
            label="📋 Copy Domain",
            command=lambda: self.copy_text(domain),
        )

        menu.tk_popup(event.x_root, event.y_root)

    def add_context_watch(self, target):
        if not self.require_admin("add a target to the watch list"):
            return
        success, message = add_watch_target(target)
        self.console_write(message)
        self.refresh_domain_matches()

    def remove_context_watch(self, target):
        if not self.require_admin("remove a target from the watch list"):
            return
        if remove_watch_target(target):
            self.console_write(
                f"Removed {target} from watch list."
            )
        else:
            self.console_write(
                f"{target} is not currently watched."
            )

    def run_domain_command(self, command, domain):
        self.notebook.select(self.console_tab)
        self.console_write(
            f"GavinNet> {command} {domain}"
        )

        if command == "resolve":
            ips = resolve_domain(domain)
            self.console_write(
                f"{domain}: {', '.join(ips) if ips else 'resolution failed'}"
            )

        elif command == "watch":
            if not self.require_admin("run the watch command"):
                return
            success, message = add_watch_target(domain)
            self.console_write(message)

        elif command == "unwatch":
            self.remove_context_watch(domain)

        elif command == "filter":
            self.search_var.set(domain)
            self.protocol_var.set("ALL")
            self.refresh_traffic()
            self.notebook.select(self.traffic_tab)
            self.console_write(
                f"Live traffic filter set to: {domain}"
            )

    def copy_text(self, value):
        self.clipboard_clear()
        self.clipboard_append(str(value))
        self.console_write(
            f"Copied: {value}"
        )

    # -------------------- watch window ----------------------

    def open_watch_window(self):
        w=self.open_workspace("Domain Watch List","Watched domains")
        tk.Label(w,text="🌐 Domain Watch List",bg=BG,fg=BLUE,font=("Segoe UI",18,"bold")).pack(anchor="w",padx=20,pady=(18,5))
        tk.Label(w,text="Domains are resolved to IPs. Matching packets appear in Domain Matches.",bg=BG,fg=MUTED).pack(anchor="w",padx=20)
        ef=tk.Frame(w,bg=BG);ef.pack(fill="x",padx=20,pady=15)
        entry=tk.Entry(ef,bg=INPUT,fg=TEXT,insertbackground=TEXT,relief="flat");entry.pack(side="left",fill="x",expand=True,ipady=7)
        listbox=tk.Listbox(w,bg=INPUT,fg=TEXT,selectbackground=BLUE2,relief="flat",font=("Consolas",10));listbox.pack(fill="both",expand=True,padx=20)
        def refresh():
            listbox.delete(0,"end")
            for domain,ips in sorted(watch_domains.items()): listbox.insert("end",f"{domain:<30}  →  {', '.join(sorted(ips))}")
        def add():
            success,message=add_watch_target(entry.get());self.console_write(message)
            if success: entry.delete(0,"end");refresh()
        def remove():
            selected=listbox.curselection()
            if selected:
                domain=listbox.get(selected[0]).split("→",1)[0].strip()
                if remove_watch_target(domain): self.console_write(f"Removed {domain}")
                refresh()
        tk.Button(ef,text="ADD",command=add,bg=BLUE2,fg="white",relief="flat",padx=18,pady=7).pack(side="left",padx=7)
        b=tk.Frame(w,bg=BG);b.pack(fill="x",padx=20,pady=12)
        tk.Button(b,text="Remove Selected",command=remove,bg="#652933",fg="white",relief="flat",padx=14,pady=7).pack(side="right")
        refresh()

    def open_protocol_window(self):
        w=self.open_workspace("Protocol Information","Network protocol reference")
        tk.Label(w,text="📚 Protocol Information",bg=BG,fg=BLUE,font=("Segoe UI",18,"bold")).pack(anchor="w",padx=20,pady=15)
        tree=ttk.Treeview(w,columns=("protocol","name","description"),show="headings")
        tree.heading("protocol",text="Protocol");tree.heading("name",text="Name");tree.heading("description",text="Description")
        tree.column("protocol",width=120);tree.column("name",width=270);tree.column("description",width=450)
        for protocol,data in PROTOCOL_INFO.items(): tree.insert("","end",values=(protocol,data[0],data[1]))
        tree.pack(fill="both",expand=True,padx=20,pady=10)

    def open_admin_command_center(self):
        if not self.require_admin("open the Admin Command Center"):
            return
        window=self.open_workspace("Admin Command Center", "Admin-only tools")
        top=tk.Frame(window,bg=PANEL);top.pack(fill="x")
        tk.Label(top,text="🖥 ADMIN COMMAND CENTER",bg=PANEL,fg=GREEN,font=("Segoe UI",16,"bold")).pack(side="left",padx=18,pady=13)
        tk.Label(top,text="SETTINGS • CUSTOM COMMANDS • APPS",bg=PANEL,fg=MUTED).pack(side="left",padx=8)
        body=ttk.Notebook(window);body.pack(fill="both",expand=True,padx=10,pady=10)

        console_tab=tk.Frame(body,bg="#070b10"); custom_tab=tk.Frame(body,bg=PANEL); apps_tab=tk.Frame(body,bg=PANEL); settings_tab=tk.Frame(body,bg=PANEL)
        body.add(console_tab,text="⌨ Console");body.add(custom_tab,text="⌘ Custom Commands");body.add(apps_tab,text="🚀 Apps");body.add(settings_tab,text="⚙ Settings")

        # console
        output=tk.Text(console_tab,bg="#05080c",fg="#78f2a0",insertbackground="white",font=("Consolas",10),relief="flat",wrap="word");output.pack(fill="both",expand=True,padx=2,pady=2)
        bottom=tk.Frame(console_tab,bg=PANEL);bottom.pack(fill="x",pady=8)
        tk.Label(bottom,text="AdminCMD>",bg=PANEL,fg=GREEN,font=("Consolas",10,"bold")).pack(side="left",padx=(10,5),pady=9)
        entry=tk.Entry(bottom,bg=INPUT,fg=TEXT,insertbackground=TEXT,relief="flat",font=("Consolas",10));entry.pack(side="left",fill="x",expand=True,ipady=6)
        old_output=self.admin_command_runner.output;old_clear=self.admin_command_runner.clear_console
        def write_here(text):
            self.after(0,lambda:(output.insert("end",str(text)+"\n"),output.see("end")))
        def clear_here(): self.after(0,lambda:output.delete("1.0","end"))
        self.admin_command_runner.output=write_here;self.admin_command_runner.clear_console=clear_here
        write_here("Gavin Admin Command Center v7.3");write_here("Type 'help' for commands.");write_here("Config: "+str(self.admin_command_runner.settings.get("command_directory")))
        def run():
            c=entry.get().strip()
            if c: write_here("AdminCMD> "+c);entry.delete(0,"end");self.admin_command_runner.execute(c);refresh_lists()
        entry.bind("<Return>",lambda e:run())
        tk.Button(bottom,text="RUN",command=run,bg=BLUE2,fg="white",relief="flat",padx=16).pack(side="left",padx=8)
        tk.Button(bottom,text="CLEAR",command=clear_here,bg=INPUT,fg=TEXT,relief="flat",padx=12).pack(side="left",padx=(0,8))

        # helper list manager
        def refresh_lists():
            if 'custom_tree' in locals():
                for x in custom_tree.get_children():custom_tree.delete(x)
                for n,it in self.admin_command_runner.custom_commands.items():custom_tree.insert("","end",values=(n,it.get("command",""),it.get("description","")))
                for x in apps_tree.get_children():apps_tree.delete(x)
                for n,it in self.admin_command_runner.apps.items():apps_tree.insert("","end",values=(n,it.get("command","")))

        custom_tree=ttk.Treeview(custom_tab,columns=("name","command","description"),show="headings")
        for c,t,w in (("name","Name",160),("command","Command",430),("description","Description",280)):custom_tree.heading(c,text=t);custom_tree.column(c,width=w)
        custom_tree.pack(fill="both",expand=True,padx=12,pady=12)
        cb=tk.Frame(custom_tab,bg=PANEL);cb.pack(fill="x",padx=12,pady=8)
        def add_custom():self.open_custom_commands()
        tk.Button(cb,text="＋ Manage / Add",command=add_custom,bg=BLUE2,fg="white",relief="flat",padx=14).pack(side="left")
        tk.Button(cb,text="Save",command=lambda:(self.admin_command_runner.save_all(),refresh_lists()),bg=INPUT,fg=TEXT,relief="flat",padx=14).pack(side="left",padx=8)

        apps_tree=ttk.Treeview(apps_tab,columns=("name","command"),show="headings");apps_tree.heading("name",text="Name");apps_tree.heading("command",text="Launch Command");apps_tree.column("name",width=220);apps_tree.column("command",width=650);apps_tree.pack(fill="both",expand=True,padx=12,pady=12)
        ab=tk.Frame(apps_tab,bg=PANEL);ab.pack(fill="x",padx=12,pady=8)
        tk.Button(ab,text="＋ Manage / Add",command=self.open_app_shortcuts,bg=BLUE2,fg="white",relief="flat",padx=14).pack(side="left")
        def launch_selected():
            sel=apps_tree.selection()
            if sel:self.admin_command_runner.execute("app "+str(apps_tree.item(sel[0],"values")[0]))
        tk.Button(ab,text="▶ Launch Selected",command=launch_selected,bg="#167348",fg="white",relief="flat",padx=14).pack(side="left",padx=8)

        # settings
        tk.Label(settings_tab,text="Persistent Admin Settings",bg=PANEL,fg=TEXT,font=("Segoe UI",15,"bold")).pack(anchor="w",padx=18,pady=(18,5))
        tk.Label(settings_tab,text="Saved under config/settings.json",bg=PANEL,fg=MUTED).pack(anchor="w",padx=18)
        sf=tk.Frame(settings_tab,bg=PANEL);sf.pack(fill="x",padx=18,pady=18)
        auto=tk.BooleanVar(value=bool(self.admin_command_runner.settings.get("auto_save",True))); full=tk.BooleanVar(value=bool(self.admin_command_runner.settings.get("fullscreen",True)))
        dns=tk.StringVar(value=str(self.admin_command_runner.settings.get("dns_refresh_seconds",60)))
        tk.Checkbutton(sf,text="Auto-save when app closes",variable=auto,bg=PANEL,fg=TEXT,selectcolor=INPUT,activebackground=PANEL,activeforeground=TEXT).pack(anchor="w",pady=6)
        tk.Checkbutton(sf,text="Start fullscreen",variable=full,bg=PANEL,fg=TEXT,selectcolor=INPUT,activebackground=PANEL,activeforeground=TEXT).pack(anchor="w",pady=6)
        r=tk.Frame(sf,bg=PANEL);r.pack(fill="x",pady=8);tk.Label(r,text="DNS refresh seconds",bg=PANEL,fg=TEXT).pack(side="left");tk.Entry(r,textvariable=dns,bg=INPUT,fg=TEXT,insertbackground=TEXT,relief="flat",width=12).pack(side="left",padx=15)
        def save_settings_tab():
            try:sec=max(10,int(dns.get()))
            except ValueError:messagebox.showerror("Settings","DNS refresh must be a number.");return
            self.admin_command_runner.settings.update({"auto_save":auto.get(),"fullscreen":full.get(),"dns_refresh_seconds":sec});self.save_app_settings();write_here("Settings saved.")
        tk.Button(sf,text="SAVE ALL SETTINGS",command=save_settings_tab,bg=BLUE2,fg="white",relief="flat",padx=16,pady=8).pack(anchor="w",pady=12)

        refresh_lists();entry.focus_set()
        def close():
            self.admin_command_runner.output=old_output;self.admin_command_runner.clear_console=old_clear;self.close_workspace()

    # ----------------------- console ------------------------

    def run_command(self):
        command = self.console_entry.get().strip()
        if not command:
            return

        self.console_entry.delete(0, "end")
        self.console_write(f"GavinNet> {command}")

        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ("admincmd", "admin-console", "command-center"):
            self.open_admin_command_center()

        elif cmd == "admin":
            if args and args[0].lower() == "logout":
                self.admin_logout()
            elif args and args[0].lower() == "status":
                self.show_admin_status()
            else:
                self.admin_login()

        elif cmd == "help":
            self.show_command_help()

        elif cmd == "interfaces":
            for name, iface in self.interface_data:
                self.console_write(
                    f"{name}\n  {iface}"
                )

        elif cmd == "stats":
            self.console_write(
                f"Packets: {packet_counter:,}\n"
                f"Bytes: {byte_counter:,}\n"
                f"Watched domains: {len(watch_domains)}\n"
                f"Domain matches: {len(domain_matches):,}\n"
                f"Capture: {'RUNNING' if capture_running else 'STOPPED'}"
            )

        elif cmd == "targets":
            if not watch_domains:
                self.console_write("No watched domains.")
            for domain, ips in watch_domains.items():
                self.console_write(
                    f"{domain}: {', '.join(sorted(ips))}"
                )

        elif cmd == "resolve":
            if not args:
                self.console_write(
                    "Usage: resolve example.com"
                )
            else:
                ips = resolve_domain(args[0])
                self.console_write(
                    f"{args[0]}: "
                    f"{', '.join(ips) if ips else 'resolution failed'}"
                )

        elif cmd == "watch":
            if not self.require_admin("run the watch command"):
                return
            if not args:
                self.console_write(
                    "Usage: watch example.com"
                )
            else:
                success, message = add_watch_target(args[0])
                self.console_write(message)

        elif cmd == "unwatch":
            if not self.require_admin("run the unwatch command"):
                return
            if not args:
                self.console_write(
                    "Usage: unwatch example.com"
                )
            else:
                self.remove_context_watch(args[0])

        elif cmd == "filter":
            if not args:
                self.console_write(
                    "Usage: filter example.com"
                )
            else:
                self.search_var.set(" ".join(args))
                self.refresh_traffic()
                self.notebook.select(self.traffic_tab)

        elif cmd == "filter-off":
            self.search_var.set("")
            self.refresh_traffic()

        elif cmd == "clear":
            if not self.require_admin("clear live traffic"):
                return
            self.clear_packets()

        elif cmd == "domain-clear":
            if not self.require_admin("clear domain matches"):
                return
            self.clear_domain_matches()

        elif cmd == "protocols":
            self.open_protocol_window()

        elif cmd == "refresh":
            if not self.require_admin("refresh network interfaces"):
                return
            self.refresh_interfaces()

        else:
            self.console_write(
                f"Unknown command: {cmd}\n"
                "Type 'help' for commands."
            )

    def clear_admin_console(self):
        """Clear the main in-app admin command console safely."""
        widget = getattr(self, "console_output", None)
        if widget is None:
            return
        try:
            widget.delete("1.0", "end")
        except tk.TclError:
            pass

    def console_write(self, text):
        self.console_output.insert(
            "end", str(text) + "\n"
        )
        self.console_output.see("end")

    def show_command_help(self):
        self.notebook.select(self.console_tab)
        self.console_write(
            """
COMMANDS
──────────────────────────────
admin
admin status
admin logout
admincmd                  [ADMIN]

help
interfaces
stats
targets
resolve example.com
watch example.com        [ADMIN]
unwatch example.com     [ADMIN]
filter google
filter-off
clear                    [ADMIN]
domain-clear             [ADMIN]
protocols
refresh                  [ADMIN]

Right-click actions:
• View packet headers
• Add target to watch list
• Remove target from watch list
• Run safe commands on a domain
• Admin Command Center: cmd, python, runpy, networking tools, files, and more
"""
        )

    def close_workspace(self):
        """Return from an embedded app page to the normal main tabs."""
        if self.workspace_frame is not None and self.workspace_frame.winfo_exists():
            self.workspace_frame.destroy()
        self.workspace_frame = None
        self.workspace_back = None
        if hasattr(self, "notebook"):
            self.notebook.pack(fill="both", expand=True)

    def open_workspace(self, title, subtitle=""):
        """Create an in-app page instead of opening a separate Tk window."""
        if getattr(self, "workspace_frame", None) is not None and self.workspace_frame.winfo_exists():
            self.workspace_frame.destroy()
        if hasattr(self, "notebook"):
            self.notebook.pack_forget()
        w = tk.Frame(self.main_content, bg=BG)
        w.pack(fill="both", expand=True)
        self.workspace_frame = w
        bar = tk.Frame(w, bg="#0b1118", height=58)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)
        tk.Button(bar, text="← Back", command=self.close_workspace, bg=INPUT, fg=TEXT, activebackground=BLUE2, activeforeground="white", relief="flat", bd=0, padx=13, pady=7).pack(side="left", padx=12, pady=10)
        tk.Label(bar, text=title, bg="#0b1118", fg=TEXT, font=("Segoe UI", 15, "bold")).pack(side="left", padx=8)
        if subtitle:
            tk.Label(bar, text=subtitle, bg="#0b1118", fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=8)
        return w

    def open_docs(self):
        """Show bundled documentation inside the main application window."""
        path = Path(__file__).resolve().parent / "docs" / "index.html"
        if not path.exists():
            messagebox.showerror("Documentation", "docs/index.html was not found.")
            return
        try:
            html = path.read_text(encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("Documentation", f"Could not read docs: {exc}")
            return

        w = self.open_workspace("Documentation", "Docs 7.3")
        lower = tk.Frame(w, bg=BG)
        lower.pack(fill="both", expand=True)
        sidebar = tk.Frame(lower, bg="#0d141c", width=215)
        sidebar.pack(side="left", fill="y"); sidebar.pack_propagate(False)
        tk.Label(sidebar, text="DOCUMENTATION", bg="#0d141c", fg="#718499", font=("Segoe UI",9,"bold")).pack(anchor="w", padx=16, pady=(18,10))
        reader=tk.Frame(lower,bg=BG); reader.pack(side="left",fill="both",expand=True)
        text=tk.Text(reader,bg="#080c11",fg=TEXT,insertbackground=TEXT,wrap="word",relief="flat",padx=28,pady=24,font=("Segoe UI",10),spacing1=2,spacing3=5)
        scroll=ttk.Scrollbar(reader,orient="vertical",command=text.yview); scroll.pack(side="right",fill="y"); text.pack(side="left",fill="both",expand=True); text.configure(yscrollcommand=scroll.set)
        self.render_html_to_text(text, html)
        headings=re.findall(r"<h[1-3][^>]*>(.*?)</h[1-3]>",html,flags=re.I|re.S)
        nav=[]
        for raw in headings:
            title=re.sub(r"<[^>]+>","",raw); title=re.sub(r"&nbsp;"," ",title); title=re.sub(r"&amp;","&",title).strip()
            if title and title not in [x for x in nav]: nav.append(title)
        def jump(title):
            idx=text.search(title,"1.0",stopindex="end",nocase=True)
            if idx:
                text.see(idx); text.tag_remove("nav_active","1.0","end"); text.tag_add("nav_active",idx,f"{idx}+{len(title)}c")
        text.tag_configure("nav_active",background=BLUE2,foreground="white")
        for title in nav:
            tk.Button(sidebar,text=title,command=lambda t=title:jump(t),bg="#0d141c",fg="#b9c8d6",activebackground=BLUE2,activeforeground="white",relief="flat",bd=0,anchor="w",padx=14,pady=7,font=("Segoe UI",9)).pack(fill="x",padx=8,pady=2)
        tk.Button(sidebar,text="🌐 Open in Browser",command=lambda:self.open_docs_browser(path),bg=PANEL2,fg=TEXT,activebackground=BLUE2,relief="flat",bd=0,anchor="w",padx=14,pady=8).pack(fill="x",padx=8,pady=(12,2))
        text.configure(state="disabled")
        if nav: jump(nav[0])

    def open_docs_browser(self, path):

        import webbrowser
        webbrowser.open(path.as_uri())

    def render_html_to_text(self, widget, html):
        class Renderer(HTMLParser):
            def __init__(self, out):
                super().__init__()
                self.out = out
                self.in_code = False
                self.skip_depth = 0
                self.heading_tag = None
                self.heading_start = None

            def handle_starttag(self, tag, attrs):
                tag = tag.lower()
                # The in-app viewer renders the document as Tk text, so CSS/metadata
                # must never appear as visible documentation.
                if tag in ("style", "script", "head", "title"):
                    self.skip_depth += 1
                    return
                if tag in ("meta", "link"):
                    return
                if self.skip_depth:
                    return
                if tag in ("h1", "h2", "h3"):
                    self.out.insert("end", "\n")
                    self.heading_tag = tag
                    self.heading_start = self.out.index("end")
                elif tag in ("p", "div", "section", "article", "ul", "ol", "main"):
                    self.out.insert("end", "\n")
                elif tag == "li":
                    self.out.insert("end", "\n• ")
                elif tag == "br":
                    self.out.insert("end", "\n")
                elif tag == "code":
                    self.in_code = True

            def handle_endtag(self, tag):
                tag = tag.lower()
                if self.skip_depth:
                    if tag in ("style", "script", "head", "title"):
                        self.skip_depth -= 1
                    return
                if tag in ("meta", "link"):
                    return
                if self.skip_depth:
                    return
                if tag in ("h1", "h2", "h3"):
                    self.out.insert("end", "\n")
                    if self.heading_start:
                        self.out.tag_add(tag, self.heading_start, "end-1c")
                    self.heading_tag = None
                    self.heading_start = None
                elif tag in ("p", "div", "section", "article", "li", "main"):
                    self.out.insert("end", "\n")
                elif tag == "code":
                    self.in_code = False

            def handle_data(self, data):
                if self.skip_depth:
                    return
                if data.strip() or self.in_code:
                    self.out.insert("end", data)

        Renderer(widget).feed(html)
        widget.tag_configure("h1", font=("Segoe UI", 22, "bold"), foreground=BLUE, spacing3=10)
        widget.tag_configure("h2", font=("Segoe UI", 16, "bold"), foreground=BLUE, spacing1=10, spacing3=7)
        widget.tag_configure("h3", font=("Segoe UI", 13, "bold"), foreground="#9ed8ff", spacing1=8)

    def show_about(self):
        messagebox.showinfo(
            "About Gavin Network Monitor",
            (
                f"Gavin Network Monitor {VERSION}\n\n"
                "Scapy + Npcap network diagnostics GUI.\n\n"
                "This monitor displays packet metadata and "
                "protocol headers; payload contents are not displayed."
            ),
        )

    # ------------------------ clear --------------------------

    def clear_packets(self):
        global packet_counter, byte_counter

        captured_packets.clear()
        packet_counter = 0
        byte_counter = 0
        self.refresh_traffic()

        self.console_write(
            "Live traffic cleared."
        )

    def clear_domain_matches(self):
        domain_matches.clear()
        self.refresh_domain_matches()

        self.console_write(
            "Domain match log cleared."
        )

    # ------------------------ export -------------------------

    def export_csv(self):
        if not captured_packets:
            messagebox.showinfo(
                "Export",
                "There is no traffic to export."
            )
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="gavin_network_traffic.csv",
        )

        if not filename:
            return

        try:
            with open(
                filename,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:
                writer = csv.writer(file)
                writer.writerow([
                    "Time", "Protocol", "Source",
                    "Source Port", "Destination",
                    "Destination Port", "Bytes",
                    "Domain Match",
                ])

                for item in captured_packets:
                    writer.writerow([
                        item["time"],
                        item["protocol"],
                        item["src"],
                        item["sport"],
                        item["dst"],
                        item["dport"],
                        item["bytes"],
                        item["watch"],
                    ])

            self.console_write(
                f"Exported {len(captured_packets):,} packets."
            )
        except Exception as e:
            messagebox.showerror(
                "Export Error", str(e)
            )

    def export_domain_csv(self):
        if not domain_matches:
            messagebox.showinfo(
                "Export",
                "There are no domain matches."
            )
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="gavin_domain_matches.csv",
        )

        if not filename:
            return

        try:
            with open(
                filename,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:
                writer = csv.writer(file)
                writer.writerow([
                    "Time", "Domain", "Protocol",
                    "Source", "Source Port",
                    "Destination", "Destination Port",
                    "Bytes",
                ])

                for item in domain_matches:
                    writer.writerow([
                        item["time"],
                        item["watch"],
                        item["protocol"],
                        item["src"],
                        item["sport"],
                        item["dst"],
                        item["dport"],
                        item["bytes"],
                    ])

            self.console_write(
                f"Exported {len(domain_matches):,} domain matches."
            )
        except Exception as e:
            messagebox.showerror(
                "Export Error", str(e)
            )

    # --------------------- DNS refresh -----------------------

    def refresh_watch_dns(self):
        if watch_domains:
            changed = False
            for target in list(watch_domains):
                if "." in target and not re.match(
                    r"^[0-9a-fA-F:]+$", target
                ):
                    ips = resolve_domain(target)
                    if ips and set(ips) != watch_domains[target]:
                        watch_domains[target] = set(ips)
                        changed = True

            if changed:
                rebuild_ip_map()
                self.console_write(
                    "Watched domain IPs refreshed."
                )

        self.after(60000, self.refresh_watch_dns)

    # --------------------- fullscreen ------------------------

    # ---------------------- saved settings ------------------

    def apply_saved_settings(self):
        settings = self.admin_command_runner.settings
        self.fullscreen = bool(settings.get("fullscreen", True))
        self.attributes("-fullscreen", self.fullscreen)
        self.search_var.set(str(settings.get("default_filter", "")))
        saved_protocol = str(settings.get("default_protocol", "ALL"))
        if saved_protocol in self.protocol_box["values"]:
            self.protocol_var.set(saved_protocol)

    def save_app_settings(self):
        settings = self.admin_command_runner.settings
        settings["fullscreen"] = bool(self.fullscreen)
        settings["default_filter"] = self.search_var.get()
        settings["default_protocol"] = self.protocol_var.get()
        if self.interface_box.current() >= 0 and self.interface_data:
            settings["selected_interface"] = self.interface_data[self.interface_box.current()][0]
        self.admin_command_runner.save_all()

    def open_admin_settings(self):
        if not self.require_admin("open Admin Settings"):
            return
        w = self.open_workspace("Admin Settings", "Persistent configuration")

        tk.Label(w, text="⚙ Admin Settings", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=22, pady=(18, 4))
        tk.Label(w, text="Settings are stored in config/settings.json", bg=PANEL, fg=MUTED).pack(anchor="w", padx=22, pady=(0, 15))

        form = tk.Frame(w, bg=PANEL); form.pack(fill="x", padx=22)
        fullscreen_var = tk.BooleanVar(value=bool(self.admin_command_runner.settings.get("fullscreen", True)))
        autosave_var = tk.BooleanVar(value=bool(self.admin_command_runner.settings.get("auto_save", True)))
        dns_var = tk.StringVar(value=str(self.admin_command_runner.settings.get("dns_refresh_seconds", 60)))
        loading_enabled_var = tk.BooleanVar(value=bool(self.admin_command_runner.settings.get("loading_screen_enabled", True)))
        loading_seconds_var = tk.StringVar(value=str(self.admin_command_runner.settings.get("loading_screen_seconds", 3.0)))
        loading_title_var = tk.StringVar(value=str(self.admin_command_runner.settings.get("loading_title", LOADING_TITLE)))
        loading_subtitle_var = tk.StringVar(value=str(self.admin_command_runner.settings.get("loading_subtitle", LOADING_SUBTITLE)))
        loading_bg_var = tk.StringVar(value=str(self.admin_command_runner.settings.get("loading_bg", LOADING_BG)))
        loading_accent_var = tk.StringVar(value=str(self.admin_command_runner.settings.get("loading_accent", LOADING_ACCENT)))
        loading_spinner_var = tk.StringVar(value=str(self.admin_command_runner.settings.get("loading_spinner_interval", SPINNER_INTERVAL_MS)))

        tk.Checkbutton(form, text="Start in fullscreen", variable=fullscreen_var, bg=PANEL, fg=TEXT,
                       selectcolor=INPUT, activebackground=PANEL, activeforeground=TEXT).pack(anchor="w", pady=7)
        tk.Checkbutton(form, text="Automatically save settings on exit", variable=autosave_var, bg=PANEL, fg=TEXT,
                       selectcolor=INPUT, activebackground=PANEL, activeforeground=TEXT).pack(anchor="w", pady=7)

        row = tk.Frame(form, bg=PANEL); row.pack(fill="x", pady=10)
        tk.Label(row, text="DNS refresh seconds", bg=PANEL, fg=TEXT).pack(side="left")
        tk.Entry(row, textvariable=dns_var, bg=INPUT, fg=TEXT, insertbackground=TEXT, relief="flat", width=12).pack(side="right")

        tk.Label(form,text="Loading Screen",bg=PANEL,fg=LOADING_ACCENT,font=("Segoe UI",11,"bold")).pack(anchor="w",pady=(12,5))
        tk.Checkbutton(form,text="Show loading screen on startup",variable=loading_enabled_var,bg=PANEL,fg=TEXT,selectcolor=INPUT,activebackground=PANEL,activeforeground=TEXT).pack(anchor="w",pady=4)
        for label,var in (("Minimum seconds",loading_seconds_var),("Title",loading_title_var),("Subtitle",loading_subtitle_var),("Background",loading_bg_var),("Accent",loading_accent_var),("Spinner interval (ms)",loading_spinner_var)):
            r=tk.Frame(form,bg=PANEL); r.pack(fill="x",pady=3)
            tk.Label(r,text=label,bg=PANEL,fg=TEXT,width=22,anchor="w").pack(side="left")
            tk.Entry(r,textvariable=var,bg=INPUT,fg=TEXT,insertbackground=TEXT,relief="flat",width=32).pack(side="left")
        tk.Label(form,text="Changes to the splash are used on the next launch.",bg=PANEL,fg=MUTED).pack(anchor="w",pady=(5,0))

        def save():
            try: seconds = max(10, int(dns_var.get()))
            except ValueError: messagebox.showerror("Settings", "DNS refresh must be a number.", parent=w); return
            try: load_seconds = max(3.0, float(loading_seconds_var.get()))
            except ValueError: messagebox.showerror("Settings", "Loading screen seconds must be a number.", parent=w); return
            try: spinner_ms = max(30, int(loading_spinner_var.get()))
            except ValueError: messagebox.showerror("Settings", "Spinner interval must be a number.", parent=w); return
            self.admin_command_runner.settings["fullscreen"] = fullscreen_var.get()
            self.admin_command_runner.settings["auto_save"] = autosave_var.get()
            self.admin_command_runner.settings["dns_refresh_seconds"] = seconds
            self.admin_command_runner.settings["loading_screen_enabled"] = loading_enabled_var.get()
            self.admin_command_runner.settings["loading_screen_seconds"] = load_seconds
            self.admin_command_runner.settings["loading_title"] = loading_title_var.get().strip() or LOADING_TITLE
            self.admin_command_runner.settings["loading_subtitle"] = loading_subtitle_var.get().strip() or LOADING_SUBTITLE
            self.admin_command_runner.settings["loading_bg"] = loading_bg_var.get().strip() or LOADING_BG
            self.admin_command_runner.settings["loading_accent"] = loading_accent_var.get().strip() or LOADING_ACCENT
            self.admin_command_runner.settings["loading_spinner_interval"] = spinner_ms
            self.save_app_settings()
            messagebox.showinfo("Settings", "Settings saved.")
            self.close_workspace()

        def reset():
            if messagebox.askyesno("Reset", "Reset saved settings to defaults?", parent=w):
                from cmd.cmd import DEFAULT_SETTINGS
                self.admin_command_runner.settings = dict(DEFAULT_SETTINGS)
                self.apply_saved_settings()
                self.save_app_settings()
                dns_var.set(str(DEFAULT_SETTINGS["dns_refresh_seconds"]))
                fullscreen_var.set(True); autosave_var.set(True)
                loading_enabled_var.set(bool(DEFAULT_SETTINGS.get("loading_screen_enabled", True)))
                loading_seconds_var.set(str(DEFAULT_SETTINGS.get("loading_screen_seconds", 3.0)))
                loading_title_var.set(str(DEFAULT_SETTINGS.get("loading_title", LOADING_TITLE)))
                loading_subtitle_var.set(str(DEFAULT_SETTINGS.get("loading_subtitle", LOADING_SUBTITLE)))
                loading_bg_var.set(str(DEFAULT_SETTINGS.get("loading_bg", LOADING_BG)))
                loading_accent_var.set(str(DEFAULT_SETTINGS.get("loading_accent", LOADING_ACCENT)))
                loading_spinner_var.set(str(DEFAULT_SETTINGS.get("loading_spinner_interval", SPINNER_INTERVAL_MS)))

        buttons = tk.Frame(w, bg=PANEL); buttons.pack(side="bottom", fill="x", padx=22, pady=18)
        tk.Button(buttons, text="SAVE SETTINGS", command=save, bg=BLUE2, fg="white", relief="flat", padx=16, pady=8).pack(side="right")
        tk.Button(buttons, text="RESET", command=reset, bg=INPUT, fg=TEXT, relief="flat", padx=16, pady=8).pack(side="right", padx=8)

    def open_custom_commands(self):
        if not self.require_admin("manage custom admin commands"): return
        w=self.open_workspace("Custom Admin Commands","Saved in config/custom_commands.json")
        tk.Label(w,text="⌘ Custom Admin Commands",bg=PANEL,fg=TEXT,font=("Segoe UI",18,"bold")).pack(anchor="w",padx=18,pady=(18,6))
        tk.Label(w,text="Use {args} for arguments and {cwd} for the current command directory.",bg=PANEL,fg=MUTED).pack(anchor="w",padx=18)
        tree=ttk.Treeview(w,columns=("name","command","description"),show="headings")
        for c,t,wd in (("name","Name",160),("command","Command",420),("description","Description",250)): tree.heading(c,text=t);tree.column(c,width=wd)
        tree.pack(fill="both",expand=True,padx=18,pady=12)
        form=tk.Frame(w,bg=PANEL);form.pack(fill="x",padx=18,pady=8)
        vars={k:tk.StringVar() for k in ("name","command","description")}
        for label,key,width in (("Name","name",18),("Command","command",42),("Description","description",30)):
            tk.Label(form,text=label,bg=PANEL,fg=TEXT).pack(side="left",padx=(4,3));tk.Entry(form,textvariable=vars[key],bg=INPUT,fg=TEXT,insertbackground=TEXT,relief="flat",width=width).pack(side="left",padx=(0,8),ipady=4)
        def refresh():
            tree.delete(*tree.get_children())
            for name,item in self.admin_command_runner.custom_commands.items(): tree.insert("","end",values=(name,item.get("command",""),item.get("description","")))
        def add():
            name=vars["name"].get().strip(); command=vars["command"].get().strip()
            if not name or not command: messagebox.showerror("Custom Command","Name and command are required.");return
            self.admin_command_runner.custom_commands[name]={"command":command,"description":vars["description"].get().strip()};self.admin_command_runner.save_all()
            for v in vars.values(): v.set("")
            refresh()
        def remove():
            sel=tree.selection()
            if sel:
                self.admin_command_runner.custom_commands.pop(str(tree.item(sel[0],"values")[0]),None);self.admin_command_runner.save_all();refresh()
        b=tk.Frame(w,bg=PANEL);b.pack(fill="x",padx=18,pady=10)
        tk.Button(b,text="＋ Add",command=add,bg=BLUE2,fg="white",relief="flat",padx=14).pack(side="left")
        tk.Button(b,text="− Remove",command=remove,bg=INPUT,fg=TEXT,relief="flat",padx=14).pack(side="left",padx=8)
        refresh()

    def open_app_shortcuts(self):
        if not self.require_admin("manage app shortcuts"): return
        w=self.open_workspace("App Shortcuts","Saved in config/apps.json")
        tk.Label(w,text="🚀 App Shortcuts",bg=PANEL,fg=TEXT,font=("Segoe UI",18,"bold")).pack(anchor="w",padx=18,pady=15)
        tree=ttk.Treeview(w,columns=("name","command"),show="headings");tree.heading("name",text="Name");tree.heading("command",text="Launch Command");tree.column("name",width=220);tree.column("command",width=600);tree.pack(fill="both",expand=True,padx=18,pady=12)
        form=tk.Frame(w,bg=PANEL);form.pack(fill="x",padx=18,pady=8)
        name=tk.StringVar();command=tk.StringVar()
        tk.Label(form,text="Name",bg=PANEL,fg=TEXT).pack(side="left",padx=4);tk.Entry(form,textvariable=name,bg=INPUT,fg=TEXT,insertbackground=TEXT,relief="flat",width=20).pack(side="left",padx=5)
        tk.Label(form,text="Command",bg=PANEL,fg=TEXT).pack(side="left",padx=4);tk.Entry(form,textvariable=command,bg=INPUT,fg=TEXT,insertbackground=TEXT,relief="flat",width=45).pack(side="left",padx=5)
        def refresh():
            tree.delete(*tree.get_children())
            for n,item in self.admin_command_runner.apps.items(): tree.insert("","end",values=(n,item.get("command","")))
        def add():
            n=name.get().strip();c=command.get().strip()
            if not n or not c: messagebox.showerror("App Shortcut","Name and command are required.");return
            self.admin_command_runner.apps[n]={"command":c};self.admin_command_runner.save_all();name.set("");command.set("");refresh()
        def remove():
            sel=tree.selection()
            if sel:
                self.admin_command_runner.apps.pop(str(tree.item(sel[0],"values")[0]),None);self.admin_command_runner.save_all();refresh()
        def launch():
            sel=tree.selection()
            if sel: self.admin_command_runner.execute("app "+str(tree.item(sel[0],"values")[0]))
        b=tk.Frame(w,bg=PANEL);b.pack(fill="x",padx=18,pady=10)
        tk.Button(b,text="＋ Add",command=add,bg=BLUE2,fg="white",relief="flat",padx=14).pack(side="left")
        tk.Button(b,text="▶ Launch",command=launch,bg="#167348",fg="white",relief="flat",padx=14).pack(side="left",padx=8)
        tk.Button(b,text="− Remove",command=remove,bg=INPUT,fg=TEXT,relief="flat",padx=14).pack(side="left")
        refresh()

    def toggle_fullscreen(self):
        self.fullscreen = not self.fullscreen
        self.attributes(
            "-fullscreen",
            self.fullscreen
        )

    # ------------------------- stats -------------------------

    def update_stats(self):
        # Startup can finish its timers before the main status bar has been
        # constructed.  Do not touch normal-GUI widgets until they exist.
        if not hasattr(self, "stats_label") or not hasattr(self, "status_label"):
            if not self.winfo_exists():
                return
            self.after(100, self.update_stats)
            return

        state = (
            "CAPTURING"
            if capture_running
            else "STOPPED"
        )

        self.stats_label.config(
            text=(
                f"Packets: {packet_counter:,}"
                f"   |   Data: {byte_counter:,} B"
                f"   |   Domains: {len(watch_domains)}"
                f"   |   Matches: {len(domain_matches):,}"
            )
        )

        self.status_label.config(
            text=state
        )

        self.after(1000, self.update_stats)

    # ------------------------- close -------------------------

    def close_app(self):
        global capture_running
        capture_running = False
        runner = getattr(self, "admin_command_runner", None)
        if runner is not None and runner.settings.get("auto_save", True):
            try:
                self.save_app_settings()
            except Exception:
                pass
        self.destroy()


if __name__ == "__main__":
    app = GavinNetworkMonitor()
    app.mainloop()
