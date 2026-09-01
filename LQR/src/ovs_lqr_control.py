#!/usr/bin/env python3
"""
OVS LQR Control Application

Glavna aplikacija koja:
1. Čita metrike iz cpu_packet_monitoring.py (JSONL log)
2. Koristi LQR kontroler za izračunavanje drop rate-a
3. Ažurira XDP program sa novim drop rate-om
4. Loguje sve akcije

Autor: Stefan
Datum: 2026-08-06
"""

import os
import sys
import time
import json
import signal
import logging
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict
from bcc import BPF
import struct

# Import LQR controller
from lqr_controller import LQRController, LQRConfig, PIDController

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/stefan/LQR/logs/lqr_control.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class ControlState:
    """Stanje kontrolnog sistema"""
    timestamp: str
    namespace: str
    cpu_total: float
    cpu_kernel: float
    cpu_user: float
    pps: int
    drop_rate: float
    target_cpu: float
    error: float
    control_mode: str  # 'lqr' ili 'pid'


class MetricsReader:
    """Čita metrike iz JSONL log fajla"""
    
    def __init__(self, log_dir: str = "/home/stefan/cpu_packet_monitoring"):
        self.log_dir = Path(log_dir)
        self.current_log_file = None
        self.file_handle = None
        self.last_position = 0
    
    def _find_latest_log(self) -> Optional[Path]:
        """Pronađi najnoviji log fajl"""
        log_files = list(self.log_dir.glob("network_metrics_*.log.jsonl"))
        if not log_files:
            return None
        return max(log_files, key=lambda p: p.stat().st_mtime)
    
    def _open_log_file(self):
        """Otvori log fajl"""
        latest_log = self._find_latest_log()
        
        if latest_log is None:
            logger.warning("No log file found")
            return False
        
        if self.current_log_file != latest_log:
            if self.file_handle:
                self.file_handle.close()
            
            self.current_log_file = latest_log
            self.file_handle = open(latest_log, 'r')
            self.last_position = 0
            logger.info(f"Opened log file: {latest_log}")
        
        return True
    
    def read_latest_metrics(self) -> Optional[Dict]:
        """
        Čita najnovije metrike iz log fajla
        
        Returns:
            Dictionary sa metrikama ili None
        """
        if not self._open_log_file():
            return None
        
        # Seek to last position
        self.file_handle.seek(self.last_position)
        
        # Čitaj sve nove linije
        lines = self.file_handle.readlines()
        self.last_position = self.file_handle.tell()
        
        if not lines:
            return None
        
        # Parse poslednju liniju
        try:
            last_line = lines[-1].strip()
            if not last_line:
                return None
            
            metrics = json.loads(last_line)
            return metrics
        
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return None
    
    def close(self):
        """Zatvori fajl"""
        if self.file_handle:
            self.file_handle.close()


class XDPController:
    """Kontroler za XDP program"""
    
    def __init__(self, interface: str = "enp5s0np0", 
                 xdp_program: str = "/home/stefan/LQR/xdp/ovs_rate_limiter.bpf.c"):
        self.interface = interface
        self.xdp_program = xdp_program
        self.bpf = None
        self.ns_control_map = None
        self.ip_to_ns_map = None
        self.mac_to_ns_map = None
        
        # Namespace mappings (hardcoded za sada, može se učitati iz config-a)
        self.namespace_config = {
            0: {  # ovs-1
                'name': 'ovs-1',
                'ip_ranges': ['192.168.1.0/24'],  # Client1 -> Service1
                'mac_addresses': []
            },
            1: {  # ovs-2
                'name': 'ovs-2',
                'ip_ranges': ['192.168.2.0/24'],  # Client2 -> Service2
                'mac_addresses': []
            }
        }
    
    def load_xdp_program(self) -> bool:
        """Učitaj i attach XDP program"""
        try:
            logger.info(f"Loading XDP program from {self.xdp_program}")
            
            # Step 1: Load BPF program (ali NE attach-uj još!)
            self.bpf = BPF(src_file=self.xdp_program)
            logger.info("BPF program compiled successfully")
            
            # Step 2: Get maps
            self.ns_control_map = self.bpf.get_table("ns_control_map")
            self.ip_to_ns_map = self.bpf.get_table("ip_to_ns_map")
            self.mac_to_ns_map = self.bpf.get_table("mac_to_ns_map")
            logger.info("BPF maps obtained")
            
            # Step 3: Initialize mappings BEFORE attaching XDP
            # Ovo je KRITIČNO - mappings moraju biti postavljeni pre nego što XDP počne da filtrira!
            self._initialize_mappings()
            logger.info("Mappings initialized")
            
            # Step 4: NOW attach XDP to interface
            # Use SKB mode (flags=2) instead of native mode for safety
            try:
                fn = self.bpf.load_func("xdp_ovs_rate_limiter", BPF.XDP)
                logger.info("XDP function loaded")
                
                self.bpf.attach_xdp(self.interface, fn, flags=2)  # 2 = SKB mode
                logger.info(f"✓ XDP program attached to {self.interface} (SKB mode)")
            except Exception as attach_error:
                logger.error(f"Failed to attach XDP: {attach_error}")
                logger.info("Trying without flags (default mode)...")
                try:
                    self.bpf.attach_xdp(self.interface, fn, 0)
                    logger.info(f"✓ XDP program attached to {self.interface} (default mode)")
                except Exception as e2:
                    logger.error(f"Failed to attach XDP (both modes): {e2}")
                    raise
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to load XDP program: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _initialize_mappings(self):
        """Inicijalizuj IP/MAC -> Namespace mappings"""
        logger.info("Initializing IP/MAC mappings...")
        
        for ns_id, config in self.namespace_config.items():
            # IP mappings
            for ip_range in config['ip_ranges']:
                # Parse IP range (simplified - samo /24 subnet)
                if '/' in ip_range:
                    import socket
                    import struct
                    
                    base_ip, prefix = ip_range.split('/')
                    parts = base_ip.split('.')
                    
                    # Add all IPs in range
                    for i in range(1, 255):
                        ip_str = f"{parts[0]}.{parts[1]}.{parts[2]}.{i}"
                        # Convert to host byte order (little endian on x86)
                        ip_int = struct.unpack('I', socket.inet_aton(ip_str))[0]
                        self.ip_to_ns_map[self.ip_to_ns_map.Key(ip_int)] = self.ip_to_ns_map.Leaf(ns_id)
                    
                    logger.info(f"  Mapped {ip_range} -> namespace {ns_id} ({config['name']})")
            
            # Initialize control structure
            self.set_drop_rate(ns_id, 0.0)
            
            # Initialize counters
            total_packets_map = self.bpf.get_table("total_packets")
            dropped_packets_map = self.bpf.get_table("dropped_packets")
            
            counter_key = total_packets_map.Key(ns_id)
            total_packets_map[counter_key] = total_packets_map.Leaf(0)
            dropped_packets_map[counter_key] = dropped_packets_map.Leaf(0)
        
        logger.info("Mappings initialized")
    
    def set_drop_rate(self, ns_id: int, drop_rate: float):
        """
        Postavi drop rate za namespace
        
        Args:
            ns_id: Namespace ID (0=ovs-1, 1=ovs-2)
            drop_rate: Drop rate (0.0 - 1.0)
        """
        if self.ns_control_map is None:
            logger.error("XDP program not loaded")
            return
        
        # Convert drop_rate (0.0-1.0) to integer (0-10000)
        drop_rate_int = int(drop_rate * 10000)
        drop_rate_int = max(0, min(10000, drop_rate_int))
        
        # Create control structure
        # struct ns_control { u32 drop_rate; u64 total_packets; u64 dropped_packets; u64 last_update; }
        control_struct = self.ns_control_map.Leaf()
        control_struct.drop_rate = drop_rate_int
        control_struct.total_packets = 0
        control_struct.dropped_packets = 0
        control_struct.last_update = int(time.time())
        
        # Update map
        key = self.ns_control_map.Key(ns_id)
        self.ns_control_map[key] = control_struct
        
        logger.debug(f"Set drop_rate for ns_id={ns_id}: {drop_rate:.3f} ({drop_rate_int}/10000)")
    
    def get_statistics(self, ns_id: int) -> Optional[Dict]:
        """Dobij statistike za namespace"""
        if self.bpf is None:
            return None
        
        try:
            # Get drop rate from control map
            ctrl_key = self.ns_control_map.Key(ns_id)
            ctrl = self.ns_control_map[ctrl_key]
            drop_rate = ctrl.drop_rate / 10000.0
            
            # Get counters from separate maps
            total_packets_map = self.bpf.get_table("total_packets")
            dropped_packets_map = self.bpf.get_table("dropped_packets")
            
            counter_key = total_packets_map.Key(ns_id)
            
            try:
                total = total_packets_map[counter_key].value
            except KeyError:
                total = 0
            
            try:
                dropped = dropped_packets_map[counter_key].value
            except KeyError:
                dropped = 0
            
            return {
                'drop_rate': drop_rate,
                'total_packets': total,
                'dropped_packets': dropped,
                'drop_percentage': (dropped / total * 100) if total > 0 else 0.0
            }
        except KeyError:
            return None
    
    def unload(self):
        """Unload XDP program"""
        if self.bpf:
            try:
                self.bpf.remove_xdp(self.interface, 0)
                logger.info(f"XDP program removed from {self.interface}")
            except Exception as e:
                logger.error(f"Failed to remove XDP program: {e}")


class OVSLQRControl:
    """Glavna kontrolna aplikacija"""
    
    def __init__(self, config: LQRConfig, target_namespace: str = "ovs-1",
                 control_mode: str = "lqr", interface: str = "enp5s0np0"):
        self.config = config
        self.target_namespace = target_namespace
        self.control_mode = control_mode
        self.interface = interface
        
        # Namespace ID mapping
        self.namespace_to_id = {
            'ovs-1': 0,
            'ovs-2': 1
        }
        
        # Components
        self.metrics_reader = MetricsReader()
        self.xdp_controller = XDPController(interface=interface)
        
        # Controller
        if control_mode == "lqr":
            self.controller = LQRController(config)
        else:
            self.controller = PIDController(
                Kp=0.1, Ki=0.01, Kd=0.05,
                target=config.target_cpu,
                max_output=config.max_drop_rate
            )
        
        # State
        self.running = False
        self.iteration = 0
        
        # Logging
        self.state_log_file = f"/home/stefan/LQR/logs/control_state_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.jsonl"
        
        logger.info(f"OVS LQR Control initialized")
        logger.info(f"  Target namespace: {target_namespace}")
        logger.info(f"  Target CPU: {config.target_cpu}%")
        logger.info(f"  Control mode: {control_mode}")
        logger.info(f"  Interface: {interface}")
    
    def start(self):
        """Pokreni kontrolni loop"""
        logger.info("Starting control loop...")
        
        # Load XDP program
        if not self.xdp_controller.load_xdp_program():
            logger.error("Failed to load XDP program, exiting")
            return
        
        self.running = True
        
        try:
            while self.running:
                self._control_iteration()
                time.sleep(self.config.dt)
        
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        
        finally:
            self.stop()
    
    def _control_iteration(self):
        """Jedna iteracija kontrolnog loop-a"""
        self.iteration += 1
        
        # Čitaj metrike
        metrics = self.metrics_reader.read_latest_metrics()
        
        if metrics is None:
            logger.warning(f"[{self.iteration}] No metrics available")
            return
        
        # Extract OVS namespace metrics
        ovs_metrics = metrics.get('ovs_namespaces', {})
        target_metrics = ovs_metrics.get(self.target_namespace)
        
        if target_metrics is None:
            logger.warning(f"[{self.iteration}] No metrics for {self.target_namespace}")
            return
        
        # Extract values
        cpu_total = target_metrics.get('cpu_total', 0.0)
        cpu_kernel = target_metrics.get('cpu_kernel', 0.0)
        cpu_user = target_metrics.get('cpu_user', 0.0)
        pps = target_metrics.get('pps', 0)
        
        # Compute control signal
        if self.control_mode == "lqr":
            drop_rate = self.controller.update(cpu_total, pps)
        else:
            drop_rate = self.controller.update(cpu_total, self.config.dt)
        
        # Apply control signal
        ns_id = self.namespace_to_id[self.target_namespace]
        self.xdp_controller.set_drop_rate(ns_id, drop_rate)
        
        # Get XDP statistics
        xdp_stats = self.xdp_controller.get_statistics(ns_id)
        
        # Log state
        state = ControlState(
            timestamp=metrics.get('timestamp', datetime.now().isoformat()),
            namespace=self.target_namespace,
            cpu_total=cpu_total,
            cpu_kernel=cpu_kernel,
            cpu_user=cpu_user,
            pps=pps,
            drop_rate=drop_rate,
            target_cpu=self.config.target_cpu,
            error=cpu_total - self.config.target_cpu,
            control_mode=self.control_mode
        )
        
        self._log_state(state, xdp_stats)
        
        # Console output
        if self.iteration % 10 == 0:
            logger.info(f"[{self.iteration}] CPU: {cpu_total:.2f}% | "
                       f"Target: {self.config.target_cpu:.2f}% | "
                       f"Error: {state.error:+.2f}% | "
                       f"Drop Rate: {drop_rate:.3f} | "
                       f"PPS: {pps}")
            
            if xdp_stats:
                logger.info(f"         XDP Stats: Total={xdp_stats['total_packets']}, "
                           f"Dropped={xdp_stats['dropped_packets']} "
                           f"({xdp_stats['drop_percentage']:.1f}%)")
    
    def _log_state(self, state: ControlState, xdp_stats: Optional[Dict]):
        """Loguj stanje u JSONL fajl"""
        log_entry = asdict(state)
        if xdp_stats:
            log_entry['xdp_stats'] = xdp_stats
        
        with open(self.state_log_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    def stop(self):
        """Zaustavi kontrolni loop"""
        logger.info("Stopping control loop...")
        self.running = False
        
        # Cleanup
        self.metrics_reader.close()
        self.xdp_controller.unload()
        
        logger.info("Control loop stopped")


def main():
    parser = argparse.ArgumentParser(description='OVS LQR CPU Control')
    parser.add_argument('--namespace', type=str, default='ovs-1',
                       help='Target OVS namespace (default: ovs-1)')
    parser.add_argument('--target-cpu', type=float, default=3.0,
                       help='Target CPU percentage (default: 3.0)')
    parser.add_argument('--max-cpu', type=float, default=10.0,
                       help='Maximum CPU percentage (default: 10.0)')
    parser.add_argument('--mode', type=str, choices=['lqr', 'pid'], default='lqr',
                       help='Control mode: lqr or pid (default: lqr)')
    parser.add_argument('--interface', type=str, default='enp5s0np0',
                       help='Network interface (default: enp5s0np0)')
    parser.add_argument('--dt', type=float, default=1.0,
                       help='Sampling time in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    # Create config
    config = LQRConfig(
        target_cpu=args.target_cpu,
        max_cpu=args.max_cpu,
        dt=args.dt
    )
    
    # Create and start controller
    controller = OVSLQRControl(
        config=config,
        target_namespace=args.namespace,
        control_mode=args.mode,
        interface=args.interface
    )
    
    # Signal handlers
    def signal_handler(sig, frame):
        logger.info("Received signal, stopping...")
        controller.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start
    controller.start()


if __name__ == "__main__":
    main()
