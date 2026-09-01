#!/usr/bin/env python3
"""
Enhanced Multi-Namespace OVS LQR Control (Version 2)

Integriše poboljšani LQR kontroler V2 sa:
- Manjim vremenskim korakom (dt=0.5s)
- Finijom granulacijom drop rate-a
- Mekšim hard limitom
- Adaptivnim K gain-om
- Prediktivnom kontrolom

Autor: Stefan
Datum: 2026-08-25
"""

import sys
import os
import time
import json
import logging
import argparse
import signal
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

# Dodaj src direktorijum u Python path
sys.path.insert(0, str(Path(__file__).parent))

from lqr_controller_v2 import LQRControllerV2, LQRConfigV2
from ovs_lqr_control import XDPController, MetricsReader

# Podešavanje logovanja
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class NamespaceConfig:
    """Konfiguracija za jedan OVS namespace"""
    name: str
    target_cpu: float
    ip_range: str  # e.g., "192.168.1.0/24"


class MultiNamespaceLQRControl:
    """
    Kontroler za više OVS namespace-a sa poboljšanim LQR algoritmom
    """
    
    def __init__(self, 
                 interface: str,
                 namespaces: List[NamespaceConfig],
                 xdp_program_path: str,
                 monitoring_log_path: str = "/home/stefan/cpu_packet_monitoring",
                 dt: float = 0.5,
                 soft_limit: bool = True,
                 prediction: bool = True):
        """
        Args:
            interface: Network interface (e.g., "enp5s0np0")
            namespaces: Lista namespace konfiguracija
            xdp_program_path: Path do XDP BPF programa
            monitoring_log_path: Path do CPU monitoring logova
            dt: Sampling time (seconds)
            soft_limit: Omogući soft limit kontrolu
            prediction: Omogući prediktivnu kontrolu
        """
        self.interface = interface
        self.namespaces = namespaces
        self.xdp_program_path = xdp_program_path
        self.monitoring_log_path = monitoring_log_path
        self.dt = dt
        
        # Kreiranje LQR kontrolera za svaki namespace
        self.controllers: Dict[str, LQRControllerV2] = {}
        for ns_config in namespaces:
            lqr_config = LQRConfigV2(
                target_cpu=ns_config.target_cpu,
                dt=dt,
                soft_limit_enabled=soft_limit,
                prediction_enabled=prediction
            )
            self.controllers[ns_config.name] = LQRControllerV2(lqr_config)
        
        # Metrics reader
        self.metrics_reader = MetricsReader()
        
        # XDP controller (use existing implementation)
        self.xdp_controller = XDPController(interface=interface)
        
        # Running flag
        self.running = False
        
        logger.info(f"Multi-Namespace LQR Control V2 initialized")
        logger.info(f"Interface: {interface}")
        logger.info(f"Sampling time: {dt}s")
        logger.info(f"Soft limit: {soft_limit}")
        logger.info(f"Prediction: {prediction}")
        for ns in namespaces:
            logger.info(f"  {ns.name}: target={ns.target_cpu}%")
    
    def load_xdp_program(self):
        """Load XDP program za packet dropping"""
        if not self.xdp_controller.load_xdp_program():
            raise Exception("Failed to load XDP program")
        logger.info(f"✓ XDP program loaded successfully")
    
    def unload_xdp_program(self):
        """Unload XDP program"""
        self.xdp_controller.unload()
        logger.info(f"✓ XDP program unloaded")
    
    def update_drop_rates(self, drop_rates: Dict[str, float]):
        """
        Update drop rates u XDP programu
        
        Args:
            drop_rates: Dictionary {namespace_name: drop_rate}
        """
        for idx, ns_config in enumerate(self.namespaces):
            drop_rate = drop_rates.get(ns_config.name, 0.0)
            self.xdp_controller.set_drop_rate(idx, drop_rate)
    
    def control_loop(self):
        """Glavna kontrolna petlja"""
        logger.info("Starting multi-namespace control loop...")
        logger.info("")
        
        iteration = 0
        self.running = True
        
        while self.running:
            iteration += 1
            start_time = time.time()
            
            try:
                # Get CPU metrics from monitor
                metrics = self.metrics_reader.read_latest_metrics()
                
                if not metrics:
                    logger.warning(f"[{iteration}] No metrics available")
                    time.sleep(self.dt)
                    continue
                
                ovs_metrics = metrics.get('ovs_namespaces', {})
                
                # Update kontrolera za svaki namespace
                drop_rates = {}
                
                for ns_config in self.namespaces:
                    ns_name = ns_config.name
                    controller = self.controllers[ns_name]
                    
                    # Get metrics for this namespace
                    if ns_name not in ovs_metrics:
                        logger.warning(f"[{iteration}] No metrics for {ns_name}")
                        drop_rates[ns_name] = 0.0
                        continue
                    
                    ns_metrics = ovs_metrics[ns_name]
                    cpu_total = ns_metrics.get('cpu_total', 0.0)
                    pps = ns_metrics.get('pps', 0)
                    
                    # Update controller
                    drop_rate = controller.update(cpu_total, pps)
                    drop_rates[ns_name] = drop_rate
                    
                    logger.info(f"[{iteration}] {ns_name}: CPU={cpu_total:.2f}%, "
                               f"PPS={pps:,}, DropRate={drop_rate:.3f}")
                
                # Update XDP drop rates
                self.update_drop_rates(drop_rates)
                
            except Exception as e:
                logger.error(f"Error in control loop: {e}", exc_info=True)
            
            # Sleep to maintain dt
            elapsed = time.time() - start_time
            sleep_time = max(0, self.dt - elapsed)
            time.sleep(sleep_time)
    
    def stop(self):
        """Zaustavi kontrolnu petlju"""
        logger.info("Stopping control loop...")
        self.running = False
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up...")
        self.unload_xdp_program()
        logger.info("Cleanup complete")


def signal_handler(signum, frame):
    """Handle SIGINT/SIGTERM"""
    logger.info(f"Received signal {signum}")
    if hasattr(signal_handler, 'controller'):
        signal_handler.controller.stop()


def main():
    parser = argparse.ArgumentParser(description='Enhanced Multi-Namespace OVS LQR Control V2')
    parser.add_argument('--config', type=str, 
                       default='/home/stefan/LQR/config/multi_lqr_config.yaml',
                       help='Path to YAML config file')
    parser.add_argument('--interface', type=str, default='enp5s0np0',
                       help='Network interface')
    parser.add_argument('--xdp-program', type=str, 
                       default='/home/stefan/LQR/xdp/ovs_rate_limiter.bpf.c',
                       help='Path to XDP BPF program')
    parser.add_argument('--monitoring-log', type=str,
                       default='/home/stefan/cpu_packet_monitoring',
                       help='Path to CPU monitoring logs')
    parser.add_argument('--dt', type=float, default=0.5,
                       help='Sampling time in seconds (default: 0.5)')
    parser.add_argument('--no-soft-limit', action='store_true',
                       help='Disable soft limit control')
    parser.add_argument('--no-prediction', action='store_true',
                       help='Disable predictive control')
    
    args = parser.parse_args()
    
    # Load config from YAML
    logger.info(f"Loading config from {args.config}")
    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)
    
    # Parse namespaces from config
    namespaces = []
    for ns_name, ns_config in config['namespaces'].items():
        namespaces.append(NamespaceConfig(
            name=ns_name,
            target_cpu=ns_config['target_cpu'],
            ip_range=ns_config['ip_range']
        ))
    
    # Print banner
    print("=" * 80)
    print("Enhanced OVS LQR Multi-Namespace Control V2")
    print("=" * 80)
    print(f"Config: {args.config}")
    print(f"Interface: {args.interface}")
    print(f"Sampling time: {args.dt}s")
    print(f"Soft limit: {not args.no_soft_limit}")
    print(f"Prediction: {not args.no_prediction}")
    print("Namespaces:")
    
    for ns in namespaces:
        print(f"  {ns.name}: target={ns.target_cpu}%")
    
    print("=" * 80)
    
    # Create controller
    controller = MultiNamespaceLQRControl(
        interface=args.interface,
        namespaces=namespaces,
        xdp_program_path=args.xdp_program,
        monitoring_log_path=args.monitoring_log,
        dt=args.dt,
        soft_limit=not args.no_soft_limit,
        prediction=not args.no_prediction
    )
    
    # Setup signal handlers
    signal_handler.controller = controller
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Load XDP program
        controller.load_xdp_program()
        
        # Start control loop
        controller.control_loop()
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        controller.cleanup()


if __name__ == "__main__":
    main()
