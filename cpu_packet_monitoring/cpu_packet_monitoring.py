#!/usr/bin/env python3
"""
CPU & Packet Monitoring - Real-time Network Interface Monitor
==============================================================

Prikazuje statistike svih mrežnih interfejsa u real-time sa htop-style output-om.

METRIKE:
--------
- RX/TX Mbps: Brzina primanja/slanja u megabitima po sekundi (delta/sekundi)
- RX/TX pps: Paketi po sekundi (delta/sekundi)
- RX/TX Drops: Dropovani paketi u poslednjoj sekundi (delta)
- RX/TX Errors: Greške u poslednjoj sekundi (delta)
- RX/TX FIFO: FIFO buffer greške u poslednjoj sekundi (delta)
- RX Frame: Frame greške u poslednjoj sekundi (delta)
- RX Multicast: Multicast paketi u poslednjoj sekundi (delta)
- TX Collisions: Kolizije u poslednjoj sekundi (delta)
- TX Carrier: Carrier greške u poslednjoj sekundi (delta)

IZVOR PODATAKA:
---------------
/proc/net/dev - Linux kernel virtualni fajl sistem koji sadrži mrežne statistike

PRINCIP RADA:
-------------
1. Čita kumulativne vrednosti iz /proc/net/dev (ukupno od boot-a)
2. Čuva prethodne vrednosti i vreme
3. Izračunava delta (razliku) između trenutnih i prethodnih vrednosti
4. Deli delta sa vremenskom razlikom da dobije rate (brzinu)

POKRETANJE:
-----------
python3 cpu_packet_monitoring.py
Pritisnite 'q' za izlaz

REFRESH RATE: 1 sekunda
"""
import time
import os
import sys
import select
import json
import subprocess
import re
from datetime import datetime, timezone
from collections import defaultdict, deque
from bcc import BPF

# ============== ANSI COLOR CODES ==============
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    CYAN = '\033[36m'
    
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_CYAN = '\033[96m'

# ============== LOGGING KONFIGURACIJA ==============
# Kreiraj log fajl sa timestamp-om u nazivu
LOG_FILE = f"network_metrics_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log.jsonl"

def write_log(entry):
    """
    Upisuje metriku u JSON log fajl
    - Svaki red je jedan JSON objekat (JSONL format)
    - Dodaje timestamp u UTC formatu
    """
    entry['timestamp'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(entry) + '\n')

def log_start():
    """Loguje početak monitoring sesije"""
    write_log({
        'event': 'monitoring_start',
        'hostname': get_hostname_cached()
    })

def log_metrics(interfaces_stats):
    """
    Loguje metrike svih interfejsa
    
    Args:
        interfaces_stats: dictionary {iface_name: stats_dict}
    """
    write_log({
        'event': 'metrics',
        'interfaces': interfaces_stats
    })

# ============== OVS NAMESPACE MONITORING (eBPF) ==============
OVS_NAMESPACES = ["ovs-1", "ovs-2"]
VETH_TO_NAMESPACE = {
    "veth-phy-ovs1": "ovs-1",
    "veth-phy-ovs2": "ovs-2",
}

bpf = None
cpu_map_total = None
prev_cpu_total = {}
num_cpus = os.cpu_count()
ifmap = {}
veth_ns_map = {}
CPU_SMOOTHING_WINDOW = 3
cpu_history = defaultdict(lambda: deque(maxlen=CPU_SMOOTHING_WINDOW))
prev_user_cpu = {}

def build_ifindex_map():
    m = {}
    veth_to_ns = {}
    out = subprocess.check_output(["ip", "-o", "link"], text=True)
    for line in out.splitlines():
        parts = line.split(":")
        ifindex = int(parts[0])
        iface_name = parts[1].strip().split("@")[0]
        m[ifindex] = "host"
        for ns, veth in VETH_TO_NAMESPACE.items():
            if iface_name == veth:
                veth_to_ns[ifindex] = ns
    return m, veth_to_ns

def init_ebpf():
    global bpf, cpu_map_total, ifmap, veth_ns_map
    bpf_src = "ovs_cpu_full.bpf.c"
    if not os.path.exists(bpf_src):
        print(f"{Colors.RED}ERROR: {bpf_src} not found!{Colors.RESET}")
        print(f"{Colors.YELLOW}OVS namespace CPU monitoring will be disabled.{Colors.RESET}")
        return False
    try:
        bpf = BPF(src_file=bpf_src)
        
        # Attach core OVS datapath probe (most important)
        bpf.attach_kprobe(event="ovs_dp_process_packet", fn_name="trace_ovs_entry")
        bpf.attach_kretprobe(event="ovs_dp_process_packet", fn_name="trace_ovs_return")
        
        # Try to attach optional probes (may not be available on all kernels)
        probes_attached = ["ovs_dp_process_packet"]
        
        try:
            bpf.attach_kprobe(event="veth_xmit", fn_name="trace_veth_entry")
            bpf.attach_kretprobe(event="veth_xmit", fn_name="trace_veth_return")
            probes_attached.append("veth_xmit")
        except:
            pass
        
        try:
            bpf.attach_kprobe(event="netif_receive_skb", fn_name="trace_netif_entry")
            bpf.attach_kretprobe(event="netif_receive_skb", fn_name="trace_netif_return")
            probes_attached.append("netif_receive_skb")
        except:
            pass
        
        # Skip dev_queue_xmit - often inlined or notrace
        
        cpu_map_total = bpf.get_table("cpu_time_total")
        ifmap, veth_ns_map = build_ifindex_map()
        print(f"{Colors.GREEN}✓ eBPF initialized - tracking OVS kernel datapath{Colors.RESET}")
        print(f"{Colors.DIM}  Probes attached: {', '.join(probes_attached)}{Colors.RESET}")
        print(f"{Colors.DIM}  Monitoring namespaces: {', '.join(OVS_NAMESPACES)}{Colors.RESET}")
        return True
    except Exception as e:
        print(f"{Colors.RED}ERROR initializing eBPF: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}OVS namespace CPU monitoring will be disabled.{Colors.RESET}")
        return False

def get_namespace_pids(namespace):
    try:
        result = subprocess.run(["ip", "netns", "pids", namespace], capture_output=True, text=True, timeout=1)
        if result.returncode == 0 and result.stdout.strip():
            return [int(pid) for pid in result.stdout.strip().split()]
    except:
        pass
    return []

def get_process_cpu_time(pid):
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            stat = f.read().split()
            return int(stat[13]) + int(stat[14])
    except:
        return 0

def get_ovs_userspace_cpu(namespace, interval=1.0):
    global prev_user_cpu
    pids = get_namespace_pids(namespace)
    if not pids:
        return 0.0
    total_cpu_time = sum(get_process_cpu_time(pid) for pid in pids)
    prev_time = prev_user_cpu.get(namespace, total_cpu_time)
    delta_ticks = total_cpu_time - prev_time
    prev_user_cpu[namespace] = total_cpu_time
    hz = os.sysconf("SC_CLK_TCK")
    return (delta_ticks / (interval * hz)) * 100

def collect_bpf_cpu_by_namespace(interval=1.0):
    global prev_cpu_total
    if cpu_map_total is None:
        return {ns: 0.0 for ns in OVS_NAMESPACES}
    raw_result = {ns: 0.0 for ns in OVS_NAMESPACES}
    for k, v in cpu_map_total.items():
        ifindex = k.ifindex
        ns = ifmap.get(ifindex)
        if ns == "host" and ifindex in veth_ns_map:
            ns = veth_ns_map[ifindex]
        if ns not in OVS_NAMESPACES:
            continue
        prev = prev_cpu_total.get(ifindex, v.value)
        delta = v.value - prev
        prev_cpu_total[ifindex] = v.value
        if delta > 0:
            cpu_pct = (delta / (interval * 1e9)) * 100 / num_cpus
            raw_result[ns] += cpu_pct
    result = {}
    for ns, raw_cpu in raw_result.items():
        cpu_history[ns].append(raw_cpu)
        result[ns] = sum(cpu_history[ns]) / len(cpu_history[ns])
    return result

def get_ovs_namespace_packet_counts(interface_stats):
    """
    Dobija packet count (RX + TX pps) za svaki OVS namespace.
    
    Koristi veth interfejse da odredi koliko paketa prolazi kroz svaki namespace.
    VAŽNO: Paketi se vide i kao RX i kao TX (zavisno od smera), uzimamo max.
    
    Args:
        interface_stats: Dictionary sa statistikama svih interfejsa
    
    Returns:
        Dictionary {namespace: total_pps}
    """
    result = {}
    
    # VETH_TO_NAMESPACE: {"veth-phy-ovs1": "ovs-1", ...}
    # key = veth interface, value = namespace
    for veth, ns in VETH_TO_NAMESPACE.items():
        if veth in interface_stats:
            stats = interface_stats[veth]
            rx_pps = stats.get('rx_pps', 0)
            tx_pps = stats.get('tx_pps', 0)
            
            # Paketi se vide i kao RX i kao TX zavisno od smera
            # Uzimamo max jer je to stvaran broj paketa kroz namespace
            # (RX = paketi iz namespace-a ka host-u, TX = paketi od host-a ka namespace-u)
            total_pps = max(rx_pps, tx_pps)
            
            # Alternativno: ako želimo oba smera, koristimo zbir
            # Ali to može duplirati count, pa koristimo max
            result[ns] = total_pps
        else:
            result[ns] = 0
    
    return result

def get_all_ovs_namespace_cpu(interval=1.0, system_cpu_stats=None, interface_stats=None):
    """
    Dobija CPU % za sve OVS namespace-ove.
    
    METODA: 
    1. Userspace CPU - meri direktno iz /proc/<pid>/stat
    2. Kernel CPU - proporcionalno deli softirq CPU baziran na packet count-u
    
    Kernel CPU se deli proporcionalno packet count-u jer:
    - Više paketa = više CPU za processing
    - softirq CPU je dominantno packet processing
    
    Args:
        interval: Vremenski interval
        system_cpu_stats: Overall CPU stats (za softirq)
        interface_stats: Interface statistike (za packet count)
    """
    global bpf
    if bpf is None:
        return None
    
    # Dobij packet count po namespace-u
    ns_packet_counts = {}
    if interface_stats:
        ns_packet_counts = get_ovs_namespace_packet_counts(interface_stats)
    
    # Ukupan packet count (za proporcionalno deljenje)
    total_pps = sum(ns_packet_counts.values())
    
    # Userspace CPU i kernel CPU (proporcionalno)
    result = {}
    for ns in OVS_NAMESPACES:
        user_cpu = get_ovs_userspace_cpu(ns, interval)
        pids = get_namespace_pids(ns)
        
        # Kernel CPU: podeli softirq proporcionalno packet count-u
        kern_cpu = 0.0
        if system_cpu_stats and 'softirq' in system_cpu_stats and total_pps > 0:
            # Procenat paketa ovog namespace-a
            ns_pps = ns_packet_counts.get(ns, 0)
            pps_ratio = ns_pps / total_pps if total_pps > 0 else 0
            
            # Podeli softirq CPU proporcionalno
            kern_cpu = system_cpu_stats['softirq'] * pps_ratio
        
        result[ns] = {
            'cpu_total': user_cpu + kern_cpu,
            'cpu_kernel': kern_cpu,
            'cpu_user': user_cpu,
            'process_count': len(pids),
            'pps': ns_packet_counts.get(ns, 0)  # Dodaj i packet count
        }
    
    return result

# Cache hostname da ne čitamo fajl svaki put
_hostname_cache = None

def get_hostname_cached():
    """Cached verzija get_hostname()"""
    global _hostname_cache
    if _hostname_cache is None:
        _hostname_cache = get_hostname()
    return _hostname_cache

# ============== FUNKCIJE ZA KOLORIZACIJU METRIKA ==============
def format_mbps(value):
    """
    Formatira Mbps vrednost u cyan boji
    - value: brzina u Mbps
    - :8.2f = 8 karaktera širine, 2 decimale (npr. "  123.45")
    """
    return f"{Colors.CYAN}{value:8.2f}{Colors.RESET}"

def format_pps(value):
    """
    Formatira pakete po sekundi u zelenoj boji
    - value: broj paketa/sekundi
    - :9 = 9 karaktera širine (npr. "    12345")
    """
    return f"{Colors.GREEN}{value:9}{Colors.RESET}"

def format_drops(value):
    """
    Formatira dropove/greške sa color coding-om
    - Zeleno ako je 0 (nema problema)
    - Crveno ako je > 0 (ima problema)
    """
    if value == 0:
        return f"{Colors.GREEN}{value:>8}{Colors.RESET}"
    else:
        return f"{Colors.RED}{value:>8}{Colors.RESET}"

# ============== FUNKCIJE ZA PRIKUPLJANJE PODATAKA ==============
def get_hostname():
    """
    Dobija hostname sistema iz /etc/hostname fajla
    - Koristi se za prikaz u header-u
    - Fallback na "localhost" ako fajl ne postoji
    """
    try:
        with open('/etc/hostname', 'r') as f:
            return f.read().strip()
    except:
        return "localhost"

def get_cpu_stats():
    """
    Čita CPU statistike iz /proc/stat
    
    Format /proc/stat prve linije:
    cpu  user nice system idle iowait irq softirq steal guest guest_nice
    
    Returns: dictionary sa CPU vremenima u jiffies
    """
    try:
        with open('/proc/stat', 'r') as f:
            line = f.readline()  # Prva linija je ukupan CPU
            fields = line.split()
            return {
                'user': int(fields[1]),
                'nice': int(fields[2]),
                'system': int(fields[3]),
                'idle': int(fields[4]),
                'iowait': int(fields[5]),
                'irq': int(fields[6]),
                'softirq': int(fields[7]),
                'steal': int(fields[8]) if len(fields) > 8 else 0,
                'guest': int(fields[9]) if len(fields) > 9 else 0,
                'guest_nice': int(fields[10]) if len(fields) > 10 else 0
            }
    except:
        return None

def get_network_interfaces():
    """
    Dobija listu svih mrežnih interfejsa iz /proc/net/dev
    
    Format /proc/net/dev:
    - Prva 2 linije su header (preskačemo ih)
    - Svaka linija: "interface_name: stats..."
    - Split po ':' da dobijemo ime interfejsa
    
    Returns: lista stringova (npr. ['lo', 'eno1', 'enp5s0np0', ...])
    """
    interfaces = []
    try:
        with open('/proc/net/dev', 'r') as f:
            lines = f.readlines()[2:]  # Preskoči header linije
            for line in lines:
                iface = line.split(':')[0].strip()  # Uzmi ime pre ':'
                if iface:
                    interfaces.append(iface)
    except:
        pass
    return interfaces

def get_interface_stats(iface):
    """
    Čita trenutne (kumulativne) statistike za dati interfejs iz /proc/net/dev
    
    VAŽNO: Ovo su UKUPNE vrednosti od boot-a sistema, ne rate!
    
    Format /proc/net/dev linije:
    iface: RX_bytes RX_pkts RX_errs RX_drop RX_fifo RX_frame RX_comp RX_mcast |
           TX_bytes TX_pkts TX_errs TX_drop TX_fifo TX_colls TX_carr TX_comp
    
    Indeksi nakon split():
    fields[0] = interface_name:
    fields[1-8] = RX metrike
    fields[9-16] = TX metrike
    
    Returns: dictionary sa svim metrikama (kumulativne vrednosti)
    """
    try:
        with open('/proc/net/dev', 'r') as f:
            for line in f:
                if iface in line:
                    fields = line.split()
                    return {
                        # RX (Receive) metrike - fields[1-8]
                        'rx_bytes': int(fields[1]),        # Ukupno primljenih bajtova
                        'rx_packets': int(fields[2]),      # Ukupno primljenih paketa
                        'rx_errs': int(fields[3]),         # RX greške
                        'rx_drops': int(fields[4]),        # RX dropovani paketi
                        'rx_fifo': int(fields[5]),         # RX FIFO buffer greške
                        'rx_frame': int(fields[6]),        # RX frame greške
                        'rx_compressed': int(fields[7]),   # RX kompresovani paketi
                        'rx_multicast': int(fields[8]),    # RX multicast paketi
                        # TX (Transmit) metrike - fields[9-16]
                        'tx_bytes': int(fields[9]),        # Ukupno poslato bajtova
                        'tx_packets': int(fields[10]),     # Ukupno poslato paketa
                        'tx_errs': int(fields[11]),        # TX greške
                        'tx_drops': int(fields[12]),       # TX dropovani paketi
                        'tx_fifo': int(fields[13]),        # TX FIFO buffer greške
                        'tx_colls': int(fields[14]),       # TX kolizije
                        'tx_carrier': int(fields[15]),     # TX carrier greške
                        'tx_compressed': int(fields[16])   # TX kompresovani paketi
                    }
    except:
        pass
    
    # Fallback ako interfejs ne postoji ili greška pri čitanju
    return {
        'rx_bytes': 0, 'rx_packets': 0, 'rx_errs': 0, 'rx_drops': 0,
        'rx_fifo': 0, 'rx_frame': 0, 'rx_compressed': 0, 'rx_multicast': 0,
        'tx_bytes': 0, 'tx_packets': 0, 'tx_errs': 0, 'tx_drops': 0,
        'tx_fifo': 0, 'tx_colls': 0, 'tx_carrier': 0, 'tx_compressed': 0
    }

def get_namespace_interfaces_with_drops():
    """
    Dobija interfejse iz svih network namespace-ova koji imaju dropove
    
    Koristi 'ip netns exec' i 'ip -s link' za čitanje statistika iz namespace-ova.
    Vraća samo interfejse koji imaju RX ili TX dropove > 0.
    
    Returns: dictionary {namespace: {interface: {rx_drops, tx_drops}}}
    """
    import subprocess
    
    ns_stats = {}
    
    try:
        # Dobij listu svih namespace-ova
        result = subprocess.run(['ip', 'netns', 'list'], 
                              capture_output=True, text=True, timeout=2)
        if result.returncode != 0:
            return ns_stats
        
        namespaces = [line.split()[0] for line in result.stdout.strip().split('\n') if line]
        
        for ns in namespaces:
            try:
                # Dobij statistike za sve interfejse u namespace-u
                result = subprocess.run(['ip', 'netns', 'exec', ns, 'ip', '-s', 'link'],
                                      capture_output=True, text=True, timeout=2)
                if result.returncode != 0:
                    continue
                
                lines = result.stdout.split('\n')
                i = 0
                while i < len(lines):
                    line = lines[i]
                    # Traži liniju sa interfejsom (format: "3: br0-1: <BROADCAST...")
                    if ':' in line and '<' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            iface = parts[1].strip().split('@')[0]  # Uzmi ime pre '@'
                            
                            # Sledeće 2 linije sadrže RX i TX statistike
                            if i + 2 < len(lines):
                                rx_line = lines[i + 1].strip()
                                tx_line = lines[i + 2].strip()
                                
                                # Parse RX line: "RX: bytes packets errors dropped missed mcast"
                                if 'RX:' in rx_line:
                                    rx_parts = rx_line.split()
                                    rx_drops = int(rx_parts[4]) if len(rx_parts) > 4 else 0
                                    
                                    # Parse TX line: "TX: bytes packets errors dropped carrier collsns"
                                    if 'TX:' in tx_line:
                                        tx_parts = tx_line.split()
                                        tx_drops = int(tx_parts[4]) if len(tx_parts) > 4 else 0
                                        
                                        # Dodaj samo ako ima dropova
                                        if rx_drops > 0 or tx_drops > 0:
                                            if ns not in ns_stats:
                                                ns_stats[ns] = {}
                                            ns_stats[ns][iface] = {
                                                'rx_drops': rx_drops,
                                                'tx_drops': tx_drops
                                            }
                    i += 1
                    
            except (subprocess.TimeoutExpired, subprocess.SubprocessError):
                continue
                
    except Exception:
        pass
    
    return ns_stats

# ============== KLASA ZA MONITORING INTERFEJSA ==============
class CPUMonitor:
    """
    Prati CPU potrošnju sistema
    
    Izračunava procenat CPU usage-a na osnovu delta vrednosti iz /proc/stat
    """
    def __init__(self):
        self.prev_stats = None
        self.prev_time = None
    
    def update(self):
        """
        Ažurira CPU statistike i vraća procenat korišćenja
        
        Returns:
            dictionary sa CPU metrikama ili None ako je prvi poziv
        """
        current_stats = get_cpu_stats()
        current_time = time.time()
        
        if current_stats is None:
            return None
        
        # Prvi poziv - samo sačuvaj trenutne vrednosti
        if self.prev_stats is None:
            self.prev_stats = current_stats
            self.prev_time = current_time
            return None
        
        # Izračunaj delta za sve CPU vremena
        prev = self.prev_stats
        
        # Total CPU time = suma svih vremena
        prev_total = sum(prev.values())
        curr_total = sum(current_stats.values())
        
        # Delta total
        total_delta = curr_total - prev_total
        
        if total_delta == 0:
            return None
        
        # Idle time delta
        idle_delta = current_stats['idle'] - prev['idle']
        
        # CPU usage = (total - idle) / total * 100
        cpu_usage = ((total_delta - idle_delta) / total_delta) * 100
        
        # Detaljnije metrike
        user_delta = current_stats['user'] - prev['user']
        system_delta = current_stats['system'] - prev['system']
        iowait_delta = current_stats['iowait'] - prev['iowait']
        irq_delta = current_stats['irq'] - prev['irq']
        softirq_delta = current_stats['softirq'] - prev['softirq']
        
        user_pct = (user_delta / total_delta) * 100
        system_pct = (system_delta / total_delta) * 100
        iowait_pct = (iowait_delta / total_delta) * 100
        irq_pct = (irq_delta / total_delta) * 100
        softirq_pct = (softirq_delta / total_delta) * 100
        
        # Sačuvaj trenutne vrednosti za sledeći poziv
        self.prev_stats = current_stats
        self.prev_time = current_time
        
        return {
            'total': cpu_usage,
            'user': user_pct,
            'system': system_pct,
            'iowait': iowait_pct,
            'irq': irq_pct,
            'softirq': softirq_pct,
            'idle': (idle_delta / total_delta) * 100
        }

class InterfaceMonitor:
    """
    Klasa koja prati statistike mrežnih interfejsa i izračunava rate-ove (brzine)
    
    Princip rada:
    1. Čuva prethodne vrednosti (prev_stats) i vreme (prev_time)
    2. Pri svakom update() pozivu:
       - Čita nove vrednosti iz /proc/net/dev
       - Izračunava razliku (delta) između novih i starih vrednosti
       - Deli delta sa vremenskom razlikom da dobije rate (Mbps, pps)
    3. Čuva nove vrednosti za sledeći poziv
    """
    def __init__(self):
        self.prev_stats = {}  # Dictionary: {iface_name: stats_dict}
        self.prev_time = {}   # Dictionary: {iface_name: timestamp}
        
    def update(self, iface):
        """
        Ažurira statistike za dati interfejs i izračunava rate-ove
        
        Args:
            iface: ime interfejsa (string, npr. 'eno1')
            
        Returns:
            dictionary sa metrikama:
            - rx_mbps, tx_mbps: brzina u Mbps (delta/sekundi)
            - rx_pps, tx_pps: paketi/sekundi (delta/sekundi)
            - rx_drops, tx_drops, errors, itd: delta vrednosti (promena u poslednjoj sekundi)
        """
        current_stats = get_interface_stats(iface)  # Čitaj trenutne vrednosti
        current_time = time.time()  # Trenutno vreme (Unix timestamp)
        
        # PRVI POZIV za ovaj interfejs - nema prethodnih podataka
        if iface not in self.prev_stats:
            # Sačuvaj trenutne vrednosti
            self.prev_stats[iface] = current_stats
            self.prev_time[iface] = current_time
            # Vrati sve metrike sa 0 (jer nemamo sa čim da uporedimo)
            return {
                'rx_mbps': 0.0,  # Nema prethodnih podataka za izračunavanje
                'tx_mbps': 0.0,
                'rx_pps': 0,
                'tx_pps': 0,
                # Delta vrednosti - sve 0 pri prvom pozivu
                'rx_drops': 0,
                'tx_drops': 0,
                'rx_errs': 0,
                'tx_errs': 0,
                'rx_fifo': 0,
                'tx_fifo': 0,
                'rx_frame': 0,
                'rx_multicast': 0,
                'tx_colls': 0,
                'tx_carrier': 0
            }
        
        # SLEDEĆI POZIVI - imamo prethodne podatke, možemo izračunati rate
        prev = self.prev_stats[iface]  # Prethodne vrednosti
        time_delta = current_time - self.prev_time[iface]  # Vremenska razlika u sekundama
        
        if time_delta > 0:
            # Izračunaj RX Mbps:
            # 1. (current_rx_bytes - prev_rx_bytes) = bajtova primljeno u ovom periodu
            # 2. * 8 = konvertuj bajtove u bite
            # 3. / time_delta = podeli sa sekundama da dobiješ bps (bits per second)
            # 4. / 1000000 = konvertuj u Mbps (megabits per second)
            rx_mbps = ((current_stats['rx_bytes'] - prev['rx_bytes']) * 8) / (time_delta * 1000000)
            tx_mbps = ((current_stats['tx_bytes'] - prev['tx_bytes']) * 8) / (time_delta * 1000000)
            
            # Izračunaj pakete po sekundi (pps):
            # (current_packets - prev_packets) / time_delta
            rx_pps = int((current_stats['rx_packets'] - prev['rx_packets']) / time_delta)
            tx_pps = int((current_stats['tx_packets'] - prev['tx_packets']) / time_delta)
        else:
            # Ako je time_delta 0 (ne bi trebalo), vrati 0
            rx_mbps = tx_mbps = 0.0
            rx_pps = tx_pps = 0
        
        # Sačuvaj trenutne vrednosti za sledeći poziv
        self.prev_stats[iface] = current_stats
        self.prev_time[iface] = current_time
        
        # Izračunaj delta (promenu) za sve metrike u ovom periodu
        # Delta = trenutna_vrednost - prethodna_vrednost
        return {
            'rx_mbps': rx_mbps,
            'tx_mbps': tx_mbps,
            'rx_pps': rx_pps,
            'tx_pps': tx_pps,
            # Delta vrednosti - koliko se promenilo u poslednjoj sekundi
            'rx_drops': current_stats['rx_drops'] - prev['rx_drops'],
            'tx_drops': current_stats['tx_drops'] - prev['tx_drops'],
            'rx_errs': current_stats['rx_errs'] - prev['rx_errs'],
            'tx_errs': current_stats['tx_errs'] - prev['tx_errs'],
            'rx_fifo': current_stats['rx_fifo'] - prev['rx_fifo'],
            'tx_fifo': current_stats['tx_fifo'] - prev['tx_fifo'],
            'rx_frame': current_stats['rx_frame'] - prev['rx_frame'],
            'rx_multicast': current_stats['rx_multicast'] - prev['rx_multicast'],
            'tx_colls': current_stats['tx_colls'] - prev['tx_colls'],
            'tx_carrier': current_stats['tx_carrier'] - prev['tx_carrier']
        }

# ============== FUNKCIJE ZA PRIKAZ ==============
def display_header(hostname, cpu_stats=None):
    """
    Prikazuje header sa nazivom, hostname-om i CPU statistikama
    - os.system('clear') briše ekran (kao 'clear' komanda u terminalu)
    - Crta box sa Unicode karakterima (╔═╗)
    
    Args:
        hostname: ime hosta
        cpu_stats: dictionary sa CPU metrikama ili None
    """
    os.system('clear')
    print("╔" + "═" * 158 + "╗")
    
    # Prva linija - naziv i hostname
    print(f"║ {Colors.BOLD}Network Interface Monitor - {hostname}{Colors.RESET}" + " " * (158 - 29 - len(hostname)) + "║")
    
    # Druga linija - CPU statistike
    if cpu_stats:
        total = cpu_stats['total']
        user = cpu_stats['user']
        system = cpu_stats['system']
        iowait = cpu_stats['iowait']
        softirq = cpu_stats['softirq']
        
        # Color coding za CPU usage
        if total < 50:
            cpu_color = Colors.GREEN
        elif total < 80:
            cpu_color = Colors.YELLOW
        else:
            cpu_color = Colors.RED
        
        cpu_line = (f"║ {Colors.BOLD}CPU:{Colors.RESET} {cpu_color}{total:5.1f}%{Colors.RESET} "
                   f"(user: {user:4.1f}% | system: {system:4.1f}% | iowait: {iowait:4.1f}% | softirq: {softirq:4.1f}%)")
        
        # Dopuni do 160 karaktera (158 + 2 za ║)
        padding_needed = 160 - len(cpu_line) + len(Colors.BOLD) + len(Colors.RESET) * 2 + len(cpu_color) + len(Colors.RESET)
        print(cpu_line + " " * padding_needed + "║")
    else:
        print(f"║ {Colors.BOLD}CPU:{Colors.RESET} Calculating..." + " " * (158 - 19) + "║")
    
    print("╚" + "═" * 158 + "╝")
    print()

def display_interfaces(monitor, interfaces, ovs_cpu_stats=None):
    """
    Prikazuje tabelu sa statistikama svih interfejsa i OVS namespace-ova
    
    Args:
        monitor: InterfaceMonitor objekat
        interfaces: lista imena interfejsa
        ovs_cpu_stats: dictionary {namespace: cpu_stats} (optional)
    
    Returns:
        dictionary sa metrikama svih interfejsa (za logging)
    """
    # Ispiši header tabele sa imenima kolona
    print(f"{Colors.BOLD}{'Interface':<16} │ {'RX Mbps':>8} │ {'TX Mbps':>8} │ {'RX pps':>9} │ {'TX pps':>9} │ "
          f"{'RX Drop':>8} │ {'TX Drop':>8} │ {'RX Err':>8} │ {'TX Err':>8} │ "
          f"{'RX FIFO':>8} │ {'TX FIFO':>8} │ {'RX Fram':>8} │ {'RX Mcast':>8} │ {'TX Coll':>8} │ {'TX Carr':>8}{Colors.RESET}")
    print("─" * 160)  # Separator linija
    
    # Dictionary za čuvanje svih metrika (za logging)
    all_stats = {}
    
    # Iteriraj kroz sve interfejse (sortirano alfabetski)
    for iface in sorted(interfaces):
        stats = monitor.update(iface)  # Dobij metrike za ovaj interfejs
        all_stats[iface] = stats  # Sačuvaj za logging
        
        # Proveri da li interfejs ima problema (bilo koji drop/error > 0)
        has_issues = (stats['rx_drops'] > 0 or stats['tx_drops'] > 0 or 
                     stats['rx_errs'] > 0 or stats['tx_errs'] > 0 or
                     stats['rx_fifo'] > 0 or stats['tx_fifo'] > 0 or
                     stats['rx_frame'] > 0 or stats['tx_colls'] > 0 or stats['tx_carrier'] > 0)
        
        # Ako ima problema, stavi crveni ✖ marker, inače prazan prostor
        prefix = f"{Colors.BRIGHT_RED}✖{Colors.RESET}" if has_issues else " "
        
        print(f"{prefix} {iface:<15} │ "
              f"{format_mbps(stats['rx_mbps'])} │ "
              f"{format_mbps(stats['tx_mbps'])} │ "
              f"{format_pps(stats['rx_pps'])} │ "
              f"{format_pps(stats['tx_pps'])} │ "
              f"{format_drops(stats['rx_drops'])} │ "
              f"{format_drops(stats['tx_drops'])} │ "
              f"{format_drops(stats['rx_errs'])} │ "
              f"{format_drops(stats['tx_errs'])} │ "
              f"{format_drops(stats['rx_fifo'])} │ "
              f"{format_drops(stats['tx_fifo'])} │ "
              f"{format_drops(stats['rx_frame'])} │ "
              f"{format_drops(stats['rx_multicast'])} │ "
              f"{format_drops(stats['tx_colls'])} │ "
              f"{format_drops(stats['tx_carrier'])}")
    
    # Prikaži OVS namespace CPU statistike (ako je eBPF enabled)
    if ovs_cpu_stats is not None:
        print()
        print(f"{Colors.CYAN}{Colors.BOLD}📊 OVS NAMESPACE CPU:{Colors.RESET}")
        print("─" * 120)
        print(f"{Colors.BOLD}{'Namespace':<15} │ {'CPU Total':>10} │ {'CPU User':>10} │ {'CPU Kernel':>10} │ {'PPS':>10} │ {'Processes':>10}{Colors.RESET}")
        print("─" * 120)
        for ns in sorted(ovs_cpu_stats.keys()):
            stats = ovs_cpu_stats[ns]
            cpu_total = stats['cpu_total']
            cpu_user = stats['cpu_user']
            cpu_kernel = stats['cpu_kernel']
            pps = stats.get('pps', 0)
            proc_count = stats['process_count']
            
            # Color coding za CPU usage
            if cpu_total < 5:
                total_color = Colors.GREEN
            elif cpu_total < 15:
                total_color = Colors.YELLOW
            else:
                total_color = Colors.RED
            
            print(f"{ns:<15} │ {total_color}{cpu_total:9.2f}%{Colors.RESET} │ "
                  f"{Colors.CYAN}{cpu_user:9.2f}%{Colors.RESET} │ "
                  f"{Colors.BRIGHT_CYAN}{cpu_kernel:9.2f}%{Colors.RESET} │ "
                  f"{Colors.GREEN}{pps:10d}{Colors.RESET} │ "
                  f"{proc_count:10d}")
        print("─" * 120)
    
    # Prikaži namespace dropove (ako postoje)
    ns_drops = get_namespace_interfaces_with_drops()
    if ns_drops:
        print()
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠️  NAMESPACE DROPS DETECTED:{Colors.RESET}")
        print("─" * 80)
        for ns, interfaces in sorted(ns_drops.items()):
            print(f"{Colors.BOLD}[{ns}]{Colors.RESET}")
            for iface, drops in sorted(interfaces.items()):
                rx_drops = drops['rx_drops']
                tx_drops = drops['tx_drops']
                rx_color = Colors.BRIGHT_RED if rx_drops > 1000 else Colors.YELLOW
                tx_color = Colors.BRIGHT_RED if tx_drops > 1000 else Colors.YELLOW
                print(f"  {iface:<20} RX drops: {rx_color}{rx_drops:>10,}{Colors.RESET}  "
                      f"TX drops: {tx_color}{tx_drops:>10,}{Colors.RESET}")
        print("─" * 80)
    
    print()
    print(f"{Colors.DIM}Press 'q' to quit | Logging to: {LOG_FILE}{Colors.RESET}")
    
    return all_stats

# ============== GLAVNA FUNKCIJA ==============
def main():
    """
    Glavna petlja programa
    
    Tok izvršavanja:
    1. Dobij hostname i kreiraj InterfaceMonitor i CPUMonitor objekte
    2. Postavi terminal u non-blocking mode (da bi mogli čitati tastere bez blokiranja)
    3. Beskonačna petlja:
       - Dobij listu interfejsa
       - Ažuriraj CPU statistike
       - Prikaži header sa CPU info i tabelu
       - Proveri da li je pritisnuto 'q' (quit)
       - Čekaj 1 sekundu
    4. Vrati terminal u normalan režim pri izlasku
    """
    hostname = get_hostname()
    monitor = InterfaceMonitor()
    cpu_monitor = CPUMonitor()
    
    # Inicijalizuj eBPF za OVS namespace CPU monitoring
    ebpf_enabled = init_ebpf()
    
    # Loguj početak monitoring sesije
    log_start()
    print(f"{Colors.GREEN}✓ Monitoring started - logging to {LOG_FILE}{Colors.RESET}")
    if ebpf_enabled:
        print(f"{Colors.GREEN}✓ eBPF OVS monitoring enabled{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}⚠ eBPF OVS monitoring disabled{Colors.RESET}")
    time.sleep(1)
    
    # Postavi terminal u non-blocking mode za čitanje tastera
    import termios
    import tty
    
    old_settings = termios.tcgetattr(sys.stdin)  # Sačuvaj stare postavke terminala
    
    try:
        # Postavi terminal u cbreak mode (čita tastere bez Enter-a)
        tty.setcbreak(sys.stdin.fileno())
        
        while True:
            # Dobij trenutnu listu interfejsa (može se menjati tokom rada)
            interfaces = get_network_interfaces()
            
            # Ažuriraj CPU statistike
            cpu_stats = cpu_monitor.update()
            
            # Ažuriraj interface statistike (potrebno za OVS CPU calculation)
            all_stats = {}
            for iface in interfaces:
                all_stats[iface] = monitor.update(iface)
            
            # Dobij OVS namespace CPU statistike (ako je eBPF enabled)
            # Koristi interface stats da proporcionalno podeli softirq CPU
            ovs_cpu_stats = None
            if ebpf_enabled:
                ovs_cpu_stats = get_all_ovs_namespace_cpu(
                    interval=0.5,  # Match LQR V2 controller sampling time
                    system_cpu_stats=cpu_stats,
                    interface_stats=all_stats
                )
            
            # Prikaži header sa CPU info i tabelu
            display_header(hostname, cpu_stats)
            display_interfaces(monitor, interfaces, ovs_cpu_stats)
            
            # Loguj metrike u fajl (uključujući CPU i OVS namespace-ove)
            log_entry = {
                'event': 'metrics',
                'interfaces': all_stats
            }
            if cpu_stats:
                log_entry['cpu'] = cpu_stats
            if ovs_cpu_stats:
                log_entry['ovs_namespaces'] = ovs_cpu_stats
            write_log(log_entry)
            
            # Proveri da li je pritisnut taster (non-blocking, timeout 0.0s)
            # select.select() sa timeout=0.0 je instant check bez čekanja
            if select.select([sys.stdin], [], [], 0.0)[0]:
                key = sys.stdin.read(1).lower()  # Čitaj jedan karakter
                if key == 'q':  # Ako je 'q', izađi
                    print(f"\n{Colors.YELLOW}Exiting...{Colors.RESET}")
                    break
            
            # Čekaj 0.5 sekundi pre sledećeg refresh-a
            # (ovo + select timeout = ~0.5s refresh rate, matches LQR V2)
            time.sleep(0.5)
    
    finally:
        # Vrati terminal u normalan režim (čak i ako dođe do greške)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Interrupted by user{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)
