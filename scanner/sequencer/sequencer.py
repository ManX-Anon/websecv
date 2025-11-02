"""
Sequencer for statistical analysis of token entropy
"""

import logging
from typing import List, Dict, Any, Optional
import numpy as np
from scipy import stats

logger = logging.getLogger(__name__)


class Sequencer:
    """Analyze randomness/entropy of tokens (session IDs, CSRF tokens, etc.)"""
    
    def __init__(self):
        self.tokens: List[str] = []
    
    def add_tokens(self, tokens: List[str]):
        """Add tokens for analysis"""
        self.tokens.extend(tokens)
    
    def analyze(self) -> Dict[str, Any]:
        """Perform statistical analysis on tokens"""
        if len(self.tokens) < 10:
            logger.warning("Insufficient tokens for reliable analysis (need at least 10)")
        
        results = {
            'token_count': len(self.tokens),
            'entropy': self._calculate_entropy(),
            'chi_square': self._chi_square_test(),
            'bit_distribution': self._bit_distribution(),
            'predictability_score': self._predictability_score(),
            'recommendations': [],
        }
        
        # Generate recommendations
        if results['predictability_score'] > 0.7:
            results['recommendations'].append(
                "Tokens show high predictability. Consider using cryptographically "
                "secure random number generators."
            )
        
        if results['entropy'] < 4.0:
            results['recommendations'].append(
                "Low entropy detected. Tokens may be guessable."
            )
        
        return results
    
    def _calculate_entropy(self) -> float:
        """Calculate Shannon entropy"""
        if not self.tokens:
            return 0.0
        
        # Combine all tokens into a single string
        all_chars = ''.join(self.tokens)
        
        if not all_chars:
            return 0.0
        
        # Calculate character frequency
        from collections import Counter
        counter = Counter(all_chars)
        total = len(all_chars)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / total
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _chi_square_test(self) -> Dict[str, float]:
        """Perform chi-square test for randomness"""
        if not self.tokens:
            return {'statistic': 0.0, 'p_value': 0.0}
        
        # Extract all characters
        all_chars = ''.join(self.tokens)
        
        # Count character frequencies
        from collections import Counter
        counter = Counter(all_chars)
        
        # Expected frequency (uniform distribution)
        unique_chars = len(counter)
        if unique_chars == 0:
            return {'statistic': 0.0, 'p_value': 0.0}
        
        expected_freq = len(all_chars) / unique_chars
        
        # Calculate chi-square statistic
        observed = list(counter.values())
        expected = [expected_freq] * len(observed)
        
        chi2, p_value = stats.chisquare(observed, expected)
        
        return {
            'statistic': float(chi2),
            'p_value': float(p_value),
            'is_random': p_value > 0.05,  # Higher p-value suggests randomness
        }
    
    def _bit_distribution(self) -> Dict[str, Any]:
        """Analyze bit distribution"""
        if not self.tokens:
            return {}
        
        # Convert tokens to binary
        all_bits = []
        for token in self.tokens:
            binary = ''.join(format(ord(c), '08b') for c in token)
            all_bits.extend([int(b) for b in binary])
        
        if not all_bits:
            return {}
        
        # Calculate bit distribution
        ones = sum(all_bits)
        zeros = len(all_bits) - ones
        
        ratio = ones / len(all_bits) if len(all_bits) > 0 else 0.5
        
        return {
            'total_bits': len(all_bits),
            'ones': ones,
            'zeros': zeros,
            'ratio': ratio,
            'expected_ratio': 0.5,
            'deviation': abs(ratio - 0.5),
        }
    
    def _predictability_score(self) -> float:
        """Calculate a predictability score (0.0 = random, 1.0 = predictable)"""
        if not self.tokens or len(self.tokens) < 2:
            return 0.0
        
        # Check for patterns
        patterns = []
        
        # Check for sequential patterns
        for i in range(len(self.tokens) - 1):
            try:
                token1_int = int(self.tokens[i], 16) if len(self.tokens[i]) > 0 else 0
                token2_int = int(self.tokens[i + 1], 16) if len(self.tokens[i + 1]) > 0 else 0
                diff = abs(token2_int - token1_int)
                if diff == 1:
                    patterns.append('sequential')
            except:
                pass
        
        # Check for repeating patterns
        unique_tokens = set(self.tokens)
        if len(unique_tokens) < len(self.tokens) * 0.9:
            patterns.append('repeating')
        
        # Check entropy
        entropy = self._calculate_entropy()
        entropy_score = max(0, 1 - (entropy / 8))  # Normalize to 0-1
        
        # Combine scores
        pattern_score = len(patterns) * 0.3
        predictability = min(1.0, pattern_score + entropy_score * 0.7)
        
        return predictability
    
    def clear(self):
        """Clear collected tokens"""
        self.tokens.clear()

