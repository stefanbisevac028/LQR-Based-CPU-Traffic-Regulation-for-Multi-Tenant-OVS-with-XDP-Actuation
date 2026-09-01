#!/usr/bin/env python3
"""
Enhanced LQR-Based OVS CPU Controller (Version 2)

Poboljšanja:
1. Manji vremenski korak (dt = 0.5s)
2. Finija granulacija drop rate-a (više nivoa)
3. Mekši hard limit (postepeni prelaz)
4. Adaptivni K gain za različite target CPU nivoe
5. Prediktivna kontrola (trend prediction)

Autor: Stefan
Datum: 2026-08-25
"""

import numpy as np
import time
import json
import logging
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List
from scipy import linalg
from collections import deque

# Podešavanje logovanja
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class LQRConfigV2:
    """Poboljšana konfiguracija LQR kontrolera"""
    target_cpu: float = 3.0          # Target CPU % (setpoint)
    min_cpu: float = 0.0             # Minimalan CPU %
    
    # LQR parametri
    Q: np.ndarray = None             # State cost matrix
    R: np.ndarray = None             # Control cost matrix
    
    # Parametri sistemskog modela
    dt: float = 0.5                  # POBOLJŠANJE 1: Manji sampling time (0.5s umesto 1.0s)
    tau: float = 2.0                 # System time constant
    
    # POBOLJŠANJE 2: Finija granulacija drop rate-a
    drop_rate_levels: List[float] = None  # Diskretni nivoi drop rate-a
    max_drop_rate: float = 0.95      # Maksimalan drop rate (95%)
    min_drop_rate: float = 0.0       # Minimalan drop rate (0%)
    
    # POBOLJŠANJE 3: Mekši hard limit
    soft_limit_enabled: bool = True  # Koristi mekši prelaz umesto hard limit
    soft_limit_margin: float = 0.5   # Margina za soft limit (%)
    
    # POBOLJŠANJE 5: Prediktivna kontrola
    prediction_enabled: bool = True  # Omogući trend prediction
    prediction_weight: float = 0.3   # Težina predikcije (0-1)
    
    # Smoothing
    state_history_len: int = 5       # Broj uzoraka za smoothing
    
    def __post_init__(self):
        """Inicijalizuj Q i R matrice ako nisu postavljene"""
        if self.Q is None:
            # POBOLJŠANJE 4: Adaptivni Q gain za različite target CPU nivoe
            # Za niže target CPU (3%), treba agresivnija kontrola
            aggressiveness = 10.0 / max(self.target_cpu, 1.0)  # Obrnuto proporcionalno
            self.Q = np.diag([100.0 * aggressiveness, 10.0 * aggressiveness])
        
        if self.R is None:
            # Mala penalizacija kontrole - dozvoljavamo velike promene
            self.R = np.array([[0.01]])
        
        if self.drop_rate_levels is None:
            # POBOLJŠANJE 2: Kreiranje finih nivoa drop rate-a
            # 20 nivoa između 0% i 95%
            self.drop_rate_levels = [
                0.0, 0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45,
                0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95
            ]


class LQRControllerV2:
    """
    Poboljšani LQR kontroler za OVS CPU regulaciju
    
    State-space model:
        x(k+1) = A*x(k) + B*u(k)
        y(k) = C*x(k)
    
    Gde:
        x = [cpu_error, cpu_error_derivative]  (state)
        u = drop_rate                           (control input)
        y = cpu_usage                           (output)
    """
    
    def __init__(self, config: LQRConfigV2):
        self.config = config
        
        # Vektor stanja: [greška, izvod greške]
        self.state = np.zeros(2)
        
        # History za smoothing i predikciju
        self.cpu_history = deque(maxlen=config.state_history_len)
        self.error_history = deque(maxlen=config.state_history_len)
        self.drop_rate_history = deque(maxlen=config.state_history_len)
        
        # Previous values
        self.prev_cpu = 0.0
        self.prev_error = 0.0
        self.prev_drop_rate = 0.0
        
        # Compute LQR gain
        self.K = self._compute_lqr_gain()
        
        logger.info(f"LQR Controller V2 initialized with target CPU: {config.target_cpu}%")
        logger.info(f"Sampling time dt: {config.dt}s")
        logger.info(f"Drop rate levels: {len(config.drop_rate_levels)} levels")
        logger.info(f"LQR Gain K: {self.K}")
        logger.info(f"Soft limit: {'enabled' if config.soft_limit_enabled else 'disabled'}")
        logger.info(f"Prediction: {'enabled' if config.prediction_enabled else 'disabled'}")
    
    def _compute_lqr_gain(self) -> np.ndarray:
        """
        Izračunaj LQR gain matricu K koristeći Riccati jednačinu
        
        Returns:
            K: Control gain matrix
        """
        dt = self.config.dt
        tau = self.config.tau
        
        # Discrete-time state-space model
        A = np.array([
            [1.0, dt],
            [-dt/tau, 1.0 - dt/tau]
        ])
        
        # B matrix: control input
        # NEGATIVAN znak jer: veći drop_rate → manji CPU
        # Odražava inverzni odnos iz fizičkog modela: CPU = c·(1-u)·λ
        B = np.array([
            [0.0],
            [-dt * 10.0]
        ])
        
        # Solve discrete-time algebraic Riccati equation
        try:
            P = linalg.solve_discrete_are(A, B, self.config.Q, self.config.R)
            K = np.linalg.inv(self.config.R + B.T @ P @ B) @ (B.T @ P @ A)
            return K
        
        except Exception as e:
            logger.error(f"Failed to compute LQR gain: {e}")
            # Fallback: simple proportional gain
            return np.array([[0.1, 0.05]])
    
    def _predict_cpu(self) -> float:
        """
        POBOLJŠANJE 5: Predvidi sledeći CPU na osnovu trenda
        
        Returns:
            predicted_cpu: Predviđeni CPU za sledeći korak
        """
        if len(self.cpu_history) < 2:
            return self.prev_cpu
        
        # Linear trend prediction
        cpu_list = list(self.cpu_history)
        recent_trend = cpu_list[-1] - cpu_list[-2]
        predicted_cpu = cpu_list[-1] + recent_trend
        
        # Clamp prediction
        predicted_cpu = np.clip(predicted_cpu, self.config.min_cpu, 100.0)
        
        return predicted_cpu
    
    def _quantize_drop_rate(self, drop_rate: float) -> float:
        """
        POBOLJŠANJE 2: Kvantizuj drop rate na najbliži dozvoljeni nivo
        
        Args:
            drop_rate: Kontinualna vrednost drop rate-a
        
        Returns:
            quantized_drop_rate: Kvantizovana vrednost
        """
        # Nađi najbliži nivo
        levels = np.array(self.config.drop_rate_levels)
        idx = np.argmin(np.abs(levels - drop_rate))
        return self.config.drop_rate_levels[idx]
    
    def _soft_limit_control(self, cpu: float, base_drop_rate: float) -> float:
        """
        POBOLJŠANJE 3: Soft limit - postepeni prelaz između LQR i hard limita
        
        Kako je opisano u journal paperu:
        - Ispod targeta: čista LQR kontrola
        - U margini (target, target+margin): postepeni prelaz (blending)
        - Iznad margine: agresivan hard limit
        
        Args:
            cpu: Trenutni CPU
            base_drop_rate: Bazni drop rate iz LQR kontrole
        
        Returns:
            adjusted_drop_rate: Prilagođeni drop rate
        """
        if not self.config.soft_limit_enabled:
            # Soft limit disabled - koristi samo LQR
            return base_drop_rate
        
        target = self.config.target_cpu
        margin = self.config.soft_limit_margin
        
        if cpu <= target:
            # Ispod targeta - čista LQR kontrola
            return base_drop_rate
        
        elif cpu <= target + margin:
            # U margini - postepeni prelaz (blending)
            # blend_factor ide od 0 (na targetu) do 1 (na target+margin)
            blend_factor = (cpu - target) / margin
            
            # Hard limit komponenta
            overshoot = cpu - target
            # Pretpostavljamo razumnu max vrednost za overshoot
            max_overshoot = target * 2.0  # 2x target je maksimum
            hard_component = min((overshoot / max_overshoot) ** 0.5 * 0.95, 0.95)
            
            # Blend između LQR i hard limita
            blended = (1 - blend_factor) * base_drop_rate + blend_factor * hard_component
            
            logger.debug(f"SOFT LIMIT (blending): CPU={cpu:.2f}%, "
                        f"blend_factor={blend_factor:.2f}, "
                        f"LQR={base_drop_rate:.3f}, hard={hard_component:.3f}, "
                        f"result={blended:.3f}")
            
            return max(base_drop_rate, blended)
        
        else:
            # Iznad margine - agresivan hard limit
            overshoot = cpu - target
            max_overshoot = target * 2.0
            hard_drop = min((overshoot / max_overshoot) ** 0.7 * 0.95, 0.95)
            
            logger.info(f"SOFT LIMIT (hard): CPU {cpu:.2f}% > target+margin {target+margin:.2f}%, "
                       f"overshoot={overshoot:.2f}%, drop_rate={hard_drop:.3f}")
            
            return max(base_drop_rate, hard_drop)
    
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
        
        # POBOLJŠANJE 5: Prediktivna komponenta
        if self.config.prediction_enabled and len(self.cpu_history) >= 2:
            predicted_cpu = self._predict_cpu()
            # Blend trenutnog i predviđenog CPU-a
            w = self.config.prediction_weight
            effective_cpu = (1 - w) * smoothed_cpu + w * predicted_cpu
            
            logger.debug(f"Prediction: current={smoothed_cpu:.2f}%, "
                        f"predicted={predicted_cpu:.2f}%, "
                        f"effective={effective_cpu:.2f}%")
        else:
            effective_cpu = smoothed_cpu
        
        # Compute error
        error = effective_cpu - self.config.target_cpu
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
        drop_rate_lqr = control_signal[0]
        
        # Add feedforward term based on PPS (samo za visok saobraćaj)
        if current_pps > 50000:
            feedforward = 0.1 * (current_pps - 50000) / 50000
            drop_rate_lqr += feedforward
        
        # POBOLJŠANJE 3: Primeni soft limit kontrolu
        # Postepeni prelaz između LQR i hard limita kada CPU prelazi target
        drop_rate_adjusted = self._soft_limit_control(effective_cpu, drop_rate_lqr)
        
        # Clamp
        drop_rate_clamped = np.clip(drop_rate_adjusted, 
                                     self.config.min_drop_rate, 
                                     self.config.max_drop_rate)
        
        # POBOLJŠANJE 2: Kvantizuj na dozvoljene nivoe
        drop_rate_final = self._quantize_drop_rate(drop_rate_clamped)
        
        # Update previous values
        self.prev_cpu = smoothed_cpu
        self.prev_error = error
        self.prev_drop_rate = drop_rate_final
        self.drop_rate_history.append(drop_rate_final)
        
        # Logging
        logger.info(f"CPU: {smoothed_cpu:.2f}% | Error: {error:.2f}% | "
                    f"State: [{self.state[0]:.2f}, {self.state[1]:.2f}] | "
                    f"Control: {control_signal[0]:.3f} | "
                    f"Drop Rate: LQR={drop_rate_lqr:.3f} -> Adj={drop_rate_adjusted:.3f} -> Final={drop_rate_final:.3f}")
        
        return float(drop_rate_final)
    
    def get_state(self) -> Dict:
        """Vrati trenutno stanje kontrolera"""
        return {
            'state': self.state.tolist(),
            'cpu_history': list(self.cpu_history),
            'error_history': list(self.error_history),
            'drop_rate_history': list(self.drop_rate_history),
            'prev_drop_rate': self.prev_drop_rate,
            'K': self.K.tolist(),
            'config': {
                'target_cpu': self.config.target_cpu,
                'dt': self.config.dt,
                'soft_limit': self.config.soft_limit_enabled,
                'prediction': self.config.prediction_enabled
            }
        }
    
    def reset(self):
        """Reset kontrolera"""
        self.state = np.zeros(2)
        self.cpu_history.clear()
        self.error_history.clear()
        self.drop_rate_history.clear()
        self.prev_cpu = 0.0
        self.prev_error = 0.0
        self.prev_drop_rate = 0.0
        logger.info("Controller V2 reset")


def test_lqr_controller_v2():
    """Test funkcija za poboljšani LQR kontroler"""
    print("=" * 80)
    print("Enhanced LQR Controller V2 Test")
    print("=" * 80)
    
    # Kreiranje kontrolera sa 3% targetom
    config = LQRConfigV2(
        target_cpu=3.0,
        dt=0.5,
        soft_limit_enabled=True,
        prediction_enabled=True
    )
    controller = LQRControllerV2(config)
    
    # Simulacija sistema
    print("\nSimulating system response...")
    print(f"{'Time':<6} {'CPU %':<8} {'Error':<8} {'Drop Rate':<10} {'Level':<6} {'PPS':<8}")
    print("-" * 60)
    
    # Simulirani CPU (sa noise-om)
    cpu_values = [
        0.5, 1.0, 2.0, 2.8, 3.2, 3.5, 3.8, 4.2, 4.5, 4.0,
        3.7, 3.4, 3.2, 3.1, 3.0, 2.9, 2.95, 3.0, 3.05, 3.0
    ]
    pps_values = [
        10000, 20000, 35000, 50000, 60000, 70000, 75000, 80000, 85000, 75000,
        65000, 55000, 50000, 48000, 45000, 43000, 44000, 45000, 46000, 45000
    ]
    
    for t, (cpu, pps) in enumerate(zip(cpu_values, pps_values)):
        drop_rate = controller.update(cpu, pps)
        error = cpu - config.target_cpu
        
        # Nađi nivo drop rate-a
        level_idx = config.drop_rate_levels.index(drop_rate) if drop_rate in config.drop_rate_levels else -1
        
        print(f"{t*config.dt:<6.1f} {cpu:<8.2f} {error:<8.2f} {drop_rate:<10.3f} {level_idx:<6} {pps:<8}")
    
    print("\n" + "=" * 80)
    print("Test completed!")
    print("\nController State:")
    state = controller.get_state()
    print(f"  Final error: {state['state'][0]:.3f}%")
    print(f"  Error derivative: {state['state'][1]:.3f}")
    print(f"  Drop rate history: {[f'{d:.2f}' for d in list(state['drop_rate_history'])]}")
    print("=" * 80)


if __name__ == "__main__":
    test_lqr_controller_v2()
