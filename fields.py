"""
Field definitions for GramFuzz.
"""

import random
import string
import logging

logger = logging.getLogger('gramfuzz.fields')

class Field:
    """Base class for all grammar fields."""
    
    def __init__(self, name=None, cat=None):
        """Initialize the field."""
        self.name = name
        self.cat = cat
        
        # If we have a category, add this rule to it
        if hasattr(self, 'fuzzer') and self.fuzzer and cat:
            self.fuzzer.add_rule(self, cat)
    
    def build(self):
        """Build the field value."""
        raise NotImplementedError("Subclasses must implement this method")

class String(Field):
    """A string literal field."""
    
    def __init__(self, value, name=None, cat=None):
        """Initialize with a fixed string value."""
        super().__init__(name, cat)
        self.value = value
    
    def build(self):
        """Return the fixed string value."""
        return self.value

class Int(Field):
    """An integer field."""
    
    def __init__(self, min_val=0, max_val=100, name=None, cat=None):
        """Initialize with min and max values."""
        super().__init__(name, cat)
        self.min_val = min_val
        self.max_val = max_val
    
    def build(self):
        """Return a random integer between min_val and max_val."""
        return str(random.randint(self.min_val, self.max_val))

class Float(Field):
    """A float field."""
    
    def __init__(self, min_val=0.0, max_val=1.0, name=None, cat=None):
        """Initialize with min and max values."""
        super().__init__(name, cat)
        self.min_val = min_val
        self.max_val = max_val
    
    def build(self):
        """Return a random float between min_val and max_val."""
        return str(random.uniform(self.min_val, self.max_val))

class Char(Field):
    """A single character field."""
    
    def __init__(self, charset=None, name=None, cat=None):
        """Initialize with an optional character set."""
        super().__init__(name, cat)
        self.charset = charset or string.printable
    
    def build(self):
        """Return a random character from the charset."""
        return random.choice(self.charset)

class URef(Field):
    """A reference to another field/category."""
    
    def __init__(self, ref, name=None, cat=None):
        """Initialize with a reference name."""
        super().__init__(name, cat)
        self.ref = ref
    
    def build(self):
        """Build from the referenced field/category."""
        if hasattr(self, 'fuzzer') and self.fuzzer:
            if self.ref in self.fuzzer.categories:
                # Reference to a category
                return random.choice(self.fuzzer.categories[self.ref]).build()
            elif self.ref in self.fuzzer.rules:
                # Reference to a named rule
                return self.fuzzer.rules[self.ref].build()
        
        logger.error(f"Unknown reference: {self.ref}")
        return ""

class Or(Field):
    """A field that chooses between multiple options."""
    
    def __init__(self, options, name=None, cat=None):
        """Initialize with a list of options."""
        super().__init__(name, cat)
        self.options = options
    
    def build(self):
        """Choose a random option and build it."""
        option = random.choice(self.options)
        
        if isinstance(option, Field):
            return option.build()
        elif isinstance(option, str):
            return option
        elif callable(option):
            return option()
        else:
            return str(option)

class And(Field):
    """A field that concatenates multiple fields."""
    
    def __init__(self, fields, sep="", name=None, cat=None):
        """Initialize with a list of fields and an optional separator."""
        super().__init__(name, cat)
        self.fields = fields
        self.sep = sep
    
    def build(self):
        """Build all fields and join them."""
        parts = []
        
        for field in self.fields:
            if isinstance(field, Field):
                parts.append(field.build())
            elif isinstance(field, str):
                parts.append(field)
            elif callable(field):
                parts.append(field())
            else:
                parts.append(str(field))
        
        return self.sep.join(parts)

class Opt(Field):
    """An optional field that may or may not be included."""
    
    def __init__(self, field, probability=0.5, name=None, cat=None):
        """Initialize with a field and the probability of including it."""
        super().__init__(name, cat)
        self.field = field
        self.probability = probability
    
    def build(self):
        """Optionally build the field."""
        if random.random() < self.probability:
            if isinstance(self.field, Field):
                return self.field.build()
            elif isinstance(self.field, str):
                return self.field
            elif callable(self.field):
                return self.field()
            else:
                return str(self.field)
        else:
            return ""

class Def(Field):
    """A field definition that can be referenced by name."""
    
    def __init__(self, name, value, cat=None):
        """Initialize with a name and value."""
        super().__init__(name, cat)
        self.value = value
    
    def build(self):
        """Build the field value."""
        if isinstance(self.value, Field):
            return self.value.build()
        elif isinstance(self.value, list):
            return And(self.value).build()
        elif isinstance(self.value, str):
            return self.value
        elif callable(self.value):
            return self.value()
        else:
            return str(self.value)

class Rep(Field):
    """A field that repeats another field multiple times."""
    
    def __init__(self, field, min_reps=0, max_reps=10, sep="", name=None, cat=None):
        """Initialize with a field and min/max repetitions."""
        super().__init__(name, cat)
        self.field = field
        self.min_reps = min_reps
        self.max_reps = max_reps
        self.sep = sep
    
    def build(self):
        """Build the field repeated a random number of times."""
        reps = random.randint(self.min_reps, self.max_reps)
        parts = []
        
        for _ in range(reps):
            if isinstance(self.field, Field):
                parts.append(self.field.build())
            elif isinstance(self.field, str):
                parts.append(self.field)
            elif callable(self.field):
                parts.append(self.field())
            else:
                parts.append(str(self.field))
        
        return self.sep.join(parts)