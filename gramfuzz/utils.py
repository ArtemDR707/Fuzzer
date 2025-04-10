"""
Utility functions for GramFuzz.
"""

import random
import math

def chance(probability):
    """Return True with the given probability."""
    return random.random() < probability

def normal(mean, stddev, min_val=None, max_val=None):
    """Generate a random number from a normal distribution."""
    val = random.normalvariate(mean, stddev)
    
    if min_val is not None:
        val = max(val, min_val)
    
    if max_val is not None:
        val = min(val, max_val)
    
    return val

def cut_off_normal(mean, stddev, min_val, max_val):
    """Generate a random number from a normal distribution with cutoffs."""
    while True:
        val = random.normalvariate(mean, stddev)
        if min_val <= val <= max_val:
            return val
