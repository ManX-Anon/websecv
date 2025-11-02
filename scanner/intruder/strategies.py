"""
Attack strategies for Intruder
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Iterator
from itertools import product


class AttackStrategy(ABC):
    """Base class for attack strategies"""
    
    @abstractmethod
    def generate_combinations(
        self,
        positions: Dict[str, List[str]]
    ) -> Iterator[Dict[str, str]]:
        """Generate payload combinations for attack"""
        pass


class SniperStrategy(AttackStrategy):
    """
    Sniper strategy: Iterate through each position independently,
    using one payload at a time
    """
    
    def generate_combinations(
        self,
        positions: Dict[str, List[str]]
    ) -> Iterator[Dict[str, str]]:
        """Generate single-position combinations"""
        for param, payloads in positions.items():
            for payload in payloads:
                yield {param: payload}


class BatteringRamStrategy(AttackStrategy):
    """
    Battering Ram strategy: Use the same payload for all positions
    """
    
    def generate_combinations(
        self,
        positions: Dict[str, List[str]]
    ) -> Iterator[Dict[str, str]]:
        """Generate same payload for all positions"""
        # Get all unique payloads across all positions
        all_payloads = set()
        for payloads in positions.values():
            all_payloads.update(payloads)
        
        for payload in all_payloads:
            result = {}
            for param in positions.keys():
                result[param] = payload
            yield result


class PitchforkStrategy(AttackStrategy):
    """
    Pitchfork strategy: Iterate through payloads in parallel,
    one payload per position
    """
    
    def generate_combinations(
        self,
        positions: Dict[str, List[str]]
    ) -> Iterator[Dict[str, str]]:
        """Generate parallel combinations"""
        param_names = list(positions.keys())
        payload_lists = [positions[name] for name in param_names]
        
        # Generate combinations of equal length
        max_len = max(len(payloads) for payloads in payload_lists)
        
        for i in range(max_len):
            result = {}
            for param_name, payloads in positions.items():
                if i < len(payloads):
                    result[param_name] = payloads[i]
            if result:
                yield result


class ClusterBombStrategy(AttackStrategy):
    """
    Cluster Bomb strategy: Generate all combinations of payloads
    across all positions
    """
    
    def generate_combinations(
        self,
        positions: Dict[str, List[str]]
    ) -> Iterator[Dict[str, str]]:
        """Generate all combinations"""
        param_names = list(positions.keys())
        payload_lists = [positions[name] for name in param_names]
        
        # Cartesian product of all payload lists
        for combination in product(*payload_lists):
            result = {}
            for param_name, payload in zip(param_names, combination):
                result[param_name] = payload
            yield result

