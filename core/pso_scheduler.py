#!/usr/bin/env python3
"""
Zero-Hunter-Engine v3.0 - MOpt Particle Swarm Optimization (PSO) Operator Scheduler
Dynamically learns which mutation operators (`cmplog_i2s`, `dictionary`, `grammar`,
`checksum_patch`, `splice`, `structure`, `native_havoc`) are most effective at
unlocking new coverage edges & crashes on the active target, updating probability
distributions via Particle Swarm Optimization.

Educational & Authorized Defensive Research Only
"""

import random
import threading
from typing import Dict, List


DEFAULT_OPERATORS = [
    "cmplog_i2s",
    "dictionary",
    "grammar",
    "checksum_patch",
    "splice",
    "structure",
    "native_havoc",
]


class MOptPSOScheduler:
    """
    Lightweight thread-safe MOpt PSO scheduler over mutation operators.
    """

    def __init__(
        self,
        operators: List[str] = DEFAULT_OPERATORS,
        swarm_size: int = 4,
        epoch_budget: int = 120,
        min_prob: float = 0.04,
    ):
        self._lock = threading.Lock()
        self.operators = list(operators)
        self.num_ops = len(self.operators)
        self.swarm_size = max(2, swarm_size)
        self.epoch_budget = max(30, epoch_budget)
        self.min_prob = min_prob

        # Initialize swarm around sensible prior probabilities
        base_prior = self._normalize([0.22, 0.14, 0.10, 0.10, 0.12, 0.08, 0.24][: self.num_ops])
        self.particles: List[List[float]] = []
        self.velocities: List[List[float]] = []
        self.l_best: List[List[float]] = []
        self.l_best_score: List[float] = [0.0] * self.swarm_size

        for i in range(self.swarm_size):
            jittered = [max(min_prob, p + random.uniform(-0.04, 0.04)) for p in base_prior]
            normed = self._normalize(jittered)
            self.particles.append(list(normed))
            self.velocities.append([0.0] * self.num_ops)
            self.l_best.append(list(normed))

        self.g_best: List[float] = list(base_prior)
        self.g_best_score: float = 0.0

        self.active_particle = 0
        self.epoch_execs = 0
        self.epoch_count = 0

        self.epoch_attempts: Dict[str, int] = {op: 0 for op in self.operators}
        self.epoch_finds: Dict[str, int] = {op: 0 for op in self.operators}
        self.total_attempts: Dict[str, int] = {op: 0 for op in self.operators}
        self.total_finds: Dict[str, int] = {op: 0 for op in self.operators}

    def _normalize(self, vec: List[float]) -> List[float]:
        clamped = [max(self.min_prob, min(0.70, v)) for v in vec]
        total = sum(clamped)
        if total <= 0:
            return [1.0 / self.num_ops] * self.num_ops
        return [v / total for v in clamped]

    def sample_operator(self) -> str:
        with self._lock:
            probs = self.particles[self.active_particle]
            chosen = random.choices(self.operators, weights=probs, k=1)[0]
            self.epoch_attempts[chosen] += 1
            self.total_attempts[chosen] += 1
            self.epoch_execs += 1
            if self.epoch_execs >= self.epoch_budget:
                self._advance_epoch()
            return chosen

    def record_reward(self, operator: str, weight: int = 1):
        """Reward an operator that discovered new coverage or a unique crash."""
        with self._lock:
            if operator in self.epoch_finds:
                self.epoch_finds[operator] += weight
                self.total_finds[operator] += weight

    def _advance_epoch(self):
        """Evaluate current particle efficiency and run PSO velocity/position update."""
        p_idx = self.active_particle
        total_finds_epoch = sum(self.epoch_finds.values())
        particle_fitness = total_finds_epoch / max(1, self.epoch_execs)

        if total_finds_epoch > 0:
            # Construct empirical operator efficiency distribution for this epoch
            op_eff = []
            for op in self.operators:
                att = max(1, self.epoch_attempts[op])
                op_eff.append((self.epoch_finds[op] / att) + self.min_prob)
            target_dist = self._normalize(op_eff)

            if particle_fitness >= self.l_best_score[p_idx]:
                self.l_best_score[p_idx] = particle_fitness
                self.l_best[p_idx] = list(target_dist)

            if particle_fitness >= self.g_best_score:
                self.g_best_score = particle_fitness
                self.g_best = list(target_dist)

        # Reset epoch counters
        for op in self.operators:
            self.epoch_attempts[op] = 0
            self.epoch_finds[op] = 0
        self.epoch_execs = 0
        self.epoch_count += 1

        # Move to next particle; after full swarm sweep, update all particles via PSO
        self.active_particle = (self.active_particle + 1) % self.swarm_size
        if self.active_particle == 0:
            w_inertia = 0.65
            c_local = 1.35
            c_global = 1.55
            for i in range(self.swarm_size):
                r1 = random.random()
                r2 = random.random()
                new_pos = []
                for d in range(self.num_ops):
                    v = (
                        w_inertia * self.velocities[i][d]
                        + c_local * r1 * (self.l_best[i][d] - self.particles[i][d])
                        + c_global * r2 * (self.g_best[d] - self.particles[i][d])
                    )
                    self.velocities[i][d] = max(-0.25, min(0.25, v))
                    new_pos.append(self.particles[i][d] + self.velocities[i][d])
                self.particles[i] = self._normalize(new_pos)

    def get_weights(self) -> Dict[str, float]:
        with self._lock:
            cur = self.particles[self.active_particle]
            return {op: round(cur[i], 4) for i, op in enumerate(self.operators)}

    def get_efficiency_summary(self) -> Dict[str, Dict[str, float]]:
        with self._lock:
            cur = self.particles[self.active_particle]
            out: Dict[str, Dict[str, float]] = {}
            for i, op in enumerate(self.operators):
                att = self.total_attempts[op]
                fnd = self.total_finds[op]
                out[op] = {
                    "probability": round(cur[i], 4),
                    "attempts": att,
                    "finds": fnd,
                    "hit_rate_pct": round((fnd / att * 100.0) if att > 0 else 0.0, 2),
                }
            return out
