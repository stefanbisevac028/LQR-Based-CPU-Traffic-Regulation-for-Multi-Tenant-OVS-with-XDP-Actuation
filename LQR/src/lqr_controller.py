#!/usr/bin/env python3
"""
LQR-Based OVS CPU Controller

Implementira Linear Quadratic Regulator (LQR) za kontrolu CPU usage-a
OVS namespace-a kroz adaptivno dropovanje paketa.

Autor: Stefan
Datum: 2026-08-06
"""

import numpy as np
import time
import json
import logging
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from scipy import linalg
from collections import deque

# Podešavanje logovanja
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class LQRConfig:
    """Konfiguracija LQR kontrolera"""
    target_cpu: float = 3.0          # Target CPU % (setpoint)
    max_cpu: float = 10.0            # Maksimalan dozvoljeni CPU %
    min_cpu: float = 0.0             # Minimalan CPU %
    
    # LQR parametri
    Q: np.ndarray = None             # State cost matrix
    R: np.ndarray = None             # Control cost matrix
    
    # Parametri sistemskog modela
    dt: float = 1.0                  # Sampling time (seconds)
    tau: float = 2.0                 # System time constant
    
    # Ograničenja kontrole
    max_drop_rate: float = 0.95      # Maksimalan drop rate (95%)
    min_drop_rate: float = 0.0       # Minimalan drop rate (0%)
    
    # Smoothing
    state_history_len: int = 5       # Broj uzoraka za smoothing
    
    def __post_init__(self):
        """Inicijalizuj Q i R matrice ako nisu postavljene"""
        if self.Q is None:
            # Cena stanja: [cpu_error, cpu_error_derivative]
            # AGRESIVNA kontrola - mora brzo reagovati!
            self.Q = np.diag([100.0, 10.0])  # Mnogo veća težina na error
        
        if self.R is None:
            # Cena kontrole: mala penalizacija - dozvoljavamo velike promene
            self.R = np.array([[0.01]])  # Smanjena penalizacija


class LQRController:
    """
    LQR kontroler za OVS CPU regulaciju
    
    State-space model:
        x(k+1) = A*x(k) + B*u(k)
        y(k) = C*x(k)
    
    Gde:
        x = [cpu_error, cpu_error_derivative]  (state)
        u = drop_rate                           (control input)
        y = cpu_usage                           (output)
    """
    
    def __init__(self, config: LQRConfig):
        self.config = config
        
        # Vektor stanja: [greška, izvod greške]
        self.state = np.zeros(2)
        
        # History za smoothing
        self.cpu_history = deque(maxlen=config.state_history_len)
        self.error_history = deque(maxlen=config.state_history_len)
        
        # Previous values
        self.prev_cpu = 0.0
        self.prev_error = 0.0
        self.prev_drop_rate = 0.0
        
        # Compute LQR gain
        self.K = self._compute_lqr_gain()
        
        logger.info(f"LQR Controller initialized with target CPU: {config.target_cpu}%")
        logger.info(f"LQR Gain K: {self.K}")
    
    def _compute_lqr_gain(self) -> np.ndarray:
        """
        Izračunaj LQR gain matricu K koristeći Riccati jednačinu
        
        Returns:
            K: Control gain matrix
        """
        # Discrete-time state-space model
        # x(k+1) = A*x(k) + B*u(k)
        
        # A matrix: state transition
        # x1(k+1) = x1(k) + dt*x2(k)  (error integration)
        # x2(k+1) = -x1(k)/tau + u(k) (error derivative dynamics)
        dt = self.config.dt
        tau = self.config.tau
        
        A = np.array([
            [1.0, dt],
            [-dt/tau, 1.0 - dt/tau]
        ])
        
        # B matrix: control input
        # u(k) affects error derivative
        # Drop rate ima DIREKTAN i INVERZNI uticaj na CPU!
        # NEGATIVAN znak jer: veći drop_rate → manji CPU
        B = np.array([
            [0.0],
            [-dt * 10.0]  # Negativan zbog inverznog odnosa
        ])
        
        # Solve discrete-time algebraic Riccati equation
        try:
            P = linalg.solve_discrete_are(A, B, self.config.Q, self.config.R)
            
            # Compute LQR gain: K = (R + B'*P*B)^-1 * B'*P*A
            K = np.linalg.inv(self.config.R + B.T @ P @ B) @ (B.T @ P @ A)
            
            return K
        
        except Exception as e:
            logger.error(f"Failed to compute LQR gain: {e}")
            # Fallback: simple proportional gain
            return np.array([[0.1, 0.05]])
    
    def update(self, current_cpu: float, current_pps: int) -> float:
        """
        Update kontrolera sa novim merenjima i izračunaj control signal
        
        Args:
            current_cpu: Trenutni CPU usage (%)
            current_pps: Trenutni packets per second
        
        Returns:
            drop_rate: Drop rate (0.0 - 1.0)
        """
        # Smoothing: dodaj u history
        self.cpu_history.append(current_cpu)
        
        # Koristi smoothed vrednost
        if len(self.cpu_history) >= 3:
            smoothed_cpu = np.median(list(self.cpu_history))
        else:
            smoothed_cpu = current_cpu
        
        # Compute error
        error = smoothed_cpu - self.config.target_cpu
        self.error_history.append(error)
        
        # Compute error derivative
        if len(self.error_history) >= 2:
            error_derivative = (error - self.prev_error) / self.config.dt
        else:
            error_derivative = 0.0
        
        # Update state vector
        self.state = np.array([error, error_derivative])
        
        # Compute control signal: u = -K*x
        control_signal = -self.K @ self.state
        drop_rate_raw = control_signal[0]
        
        # Add feedforward term based on PPS
        # Ako je PPS visok, povećaj drop rate preventivno
        if current_pps > 50000:
            feedforward = 0.1 * (current_pps - 50000) / 50000
            drop_rate_raw += feedforward
        
        # HARD LIMIT MODE: CPU NE SME preći target!
        # Ako je CPU > target, ODMAH postavi agresivan drop rate
        if smoothed_cpu > self.config.target_cpu:
            # Direktna proporcionalna kontrola
            # CPU 3% -> drop 0%
            # CPU 4% -> drop ~14%
            # CPU 5% -> drop ~28%
            # CPU 6% -> drop ~43%
            # CPU 7% -> drop ~57%
            # CPU 8% -> drop ~71%
            # CPU 9% -> drop ~85%
            # CPU 10%+ -> drop 95%
            
            overshoot = smoothed_cpu - self.config.target_cpu
            max_overshoot = self.config.max_cpu - self.config.target_cpu
            
            # Agresivna proporcionalna kontrola
            proportional_drop = (overshoot / max_overshoot) ** 0.7  # Power < 1 za brži response
            drop_rate_hard = min(proportional_drop * 0.95, 0.95)
            
            # Uzmi maksimum između LQR i hard limit kontrole
            drop_rate = max(drop_rate_raw, drop_rate_hard)
            
            logger.info(f"HARD LIMIT: CPU {smoothed_cpu:.2f}% > target {self.config.target_cpu}%, "
                       f"overshoot={overshoot:.2f}%, drop_rate={drop_rate:.3f}")
        else:
            drop_rate = drop_rate_raw
        
        # Clamp
        drop_rate = np.clip(drop_rate, self.config.min_drop_rate, self.config.max_drop_rate)
        
        # Update previous values
        self.prev_cpu = smoothed_cpu
        self.prev_error = error
        self.prev_drop_rate = drop_rate
        
        # Logging
        logger.debug(f"CPU: {smoothed_cpu:.2f}% | Error: {error:.2f}% | "
                    f"dError: {error_derivative:.2f} | Drop Rate: {drop_rate:.3f}")
        
        return float(drop_rate)
    
    def get_state(self) -> Dict:
        """Vrati trenutno stanje kontrolera"""
        return {
            'state': self.state.tolist(),
            'cpu_history': list(self.cpu_history),
            'error_history': list(self.error_history),
            'prev_drop_rate': self.prev_drop_rate,
            'K': self.K.tolist()
        }
    
    def reset(self):
        """Reset kontrolera"""
        self.state = np.zeros(2)
        self.cpu_history.clear()
        self.error_history.clear()
        self.prev_cpu = 0.0
        self.prev_error = 0.0
        self.prev_drop_rate = 0.0
        logger.info("Controller reset")


class PIDController:
    """
    Alternativni PID kontroler (za poređenje sa LQR)
    """
    
    def __init__(self, Kp: float = 0.1, Ki: float = 0.01, Kd: float = 0.05,
                 target: float = 3.0, max_output: float = 0.95):
        self.Kp = Kp
        self.Ki = Ki
        self.Kd = Kd
        self.target = target
        self.max_output = max_output
        
        self.integral = 0.0
        self.prev_error = 0.0
        
        logger.info(f"PID Controller initialized: Kp={Kp}, Ki={Ki}, Kd={Kd}")
    
    def update(self, current_value: float, dt: float = 1.0) -> float:
        """
        PID update
        
        Args:
            current_value: Trenutna vrednost (CPU %)
            dt: Time step
        
        Returns:
            control_output: Drop rate (0.0 - 1.0)
        """
        error = current_value - self.target
        
        # Proportional
        P = self.Kp * error
        
        # Integral (sa anti-windup)
        self.integral += error * dt
        self.integral = np.clip(self.integral, -10.0, 10.0)
        I = self.Ki * self.integral
        
        # Derivative
        derivative = (error - self.prev_error) / dt
        D = self.Kd * derivative
        
        # Control output
        output = P + I + D
        output = np.clip(output, 0.0, self.max_output)
        
        self.prev_error = error
        
        logger.debug(f"PID: P={P:.3f}, I={I:.3f}, D={D:.3f}, Output={output:.3f}")
        
        return float(output)
    
    def reset(self):
        """Reset PID-a"""
        self.integral = 0.0
        self.prev_error = 0.0


def test_lqr_controller():
    """Test funkcija za LQR kontroler"""
    print("=" * 80)
    print("LQR Controller Test")
    print("=" * 80)
    
    # Kreiranje kontrolera
    config = LQRConfig(target_cpu=3.0, max_cpu=10.0)
    controller = LQRController(config)
    
    # Simulacija sistema
    print("\nSimulating system response...")
    print(f"{'Time':<6} {'CPU %':<8} {'Error':<8} {'Drop Rate':<10} {'PPS':<8}")
    print("-" * 50)
    
    # Simulirani CPU (sa noise-om)
    cpu_values = [0.5, 1.0, 2.5, 5.0, 8.0, 10.0, 12.0, 9.0, 6.0, 4.0, 3.5, 3.2, 3.0, 2.9]
    pps_values = [10000, 20000, 40000, 80000, 100000, 120000, 120000, 100000, 80000, 60000, 50000, 45000, 40000, 40000]
    
    for t, (cpu, pps) in enumerate(zip(cpu_values, pps_values)):
        drop_rate = controller.update(cpu, pps)
        error = cpu - config.target_cpu
        
        print(f"{t:<6} {cpu:<8.2f} {error:<8.2f} {drop_rate:<10.3f} {pps:<8}")
    
    print("\n" + "=" * 80)
    print("Test completed!")
    print("=" * 80)


if __name__ == "__main__":
    test_lqr_controller()
