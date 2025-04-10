"""
GramFuzz - Grammar-based Fuzzing Library

This is a custom implementation of a grammar-based fuzzing library
for the Intelligent Fuzzing Tool project.
"""

import random
import string
import re
import logging

logger = logging.getLogger('gramfuzz')

class GramFuzzer:
    """Main class for grammar-based fuzzing."""
    
    def __init__(self):
        """Initialize the fuzzer."""
        self.categories = {}
        self.rules = {}
    
    def cat(self, name):
        """Define a category."""
        if name not in self.categories:
            self.categories[name] = []
        return name
    
    def add_rule(self, rule, cat=None):
        """Add a rule to the grammar."""
        if cat:
            if cat not in self.categories:
                self.cat(cat)
            self.categories[cat].append(rule)
        
        rule_name = getattr(rule, 'name', None)
        if rule_name:
            self.rules[rule_name] = rule
        
        return rule
    
    def get_categories(self):
        """Get list of defined categories."""
        return list(self.categories.keys())
    
    def gen(self, cat, num=1):
        """Generate fuzzing examples from the given category."""
        if cat not in self.categories:
            logger.error(f"Unknown category: {cat}")
            return [""] * num
        
        results = []
        for _ in range(num):
            try:
                # Choose a random rule from the category
                rule = random.choice(self.categories[cat])
                
                # Generate from the rule
                result = rule.build()
                results.append(result)
            except Exception as e:
                logger.error(f"Error generating from category {cat}: {e}")
                results.append("")
        
        return results

# Import fields and utils
from .fields import *
from .utils import *