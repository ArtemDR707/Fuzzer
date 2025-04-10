"""
Source Code Analyzer for Intelligent Fuzzing

This module analyzes source code to extract useful information
for fuzzing, such as function signatures, input formats, and
potential vulnerabilities.
"""

import os
import re
import ast
import logging
import json
from pathlib import Path
from collections import defaultdict

# Get logger
logger = logging.getLogger(__name__)

class SourceAnalyzer:
    """
    Analyzes source code to extract information for fuzzing.
    
    This class identifies input handling functions, parses program
    structure, and detects potential vulnerability patterns to help
    guide the fuzzing process.
    """
    
    def __init__(self):
        """Initialize the source analyzer."""
        self.analyzed_files = set()
        self.input_functions = []
        self.vulnerability_patterns = []
        self.function_signatures = {}
        self.data_structures = {}
        self.input_formats = set()
        
        # Initialize language-specific analyzers
        self.analyzers = {
            '.c': self._analyze_c_file,
            '.cpp': self._analyze_cpp_file,
            '.cc': self._analyze_cpp_file,
            '.py': self._analyze_python_file,
            '.js': self._analyze_javascript_file,
            '.java': self._analyze_java_file,
            '.go': self._analyze_go_file,
            '.rs': self._analyze_rust_file
        }
        
        # Initialize vulnerability patterns
        self._init_vulnerability_patterns()
    
    def _init_vulnerability_patterns(self):
        """Initialize patterns for detecting potential vulnerabilities."""
        self.vulnerability_patterns = [
            # C/C++ patterns
            {
                'language': ['c', 'cpp', 'cc'],
                'name': 'buffer_overflow',
                'pattern': r'(strcpy|strcat|sprintf|gets|scanf)\s*\(',
                'description': 'Unsafe string/buffer functions (potential buffer overflow)'
            },
            {
                'language': ['c', 'cpp', 'cc'],
                'name': 'format_string',
                'pattern': r'(printf|sprintf|fprintf|snprintf|vprintf|vsprintf|vfprintf|vsnprintf)\s*\(\s*([^,]*,)?\s*[^"]*\)',
                'description': 'Format string vulnerability (user input in format string)'
            },
            {
                'language': ['c', 'cpp', 'cc'],
                'name': 'integer_overflow',
                'pattern': r'(malloc|alloca|calloc)\s*\(\s*([^)]*\*[^)]*)\s*\)',
                'description': 'Potential integer overflow in memory allocation'
            },
            {
                'language': ['c', 'cpp', 'cc'],
                'name': 'command_injection',
                'pattern': r'(system|popen|exec[lv][pe]?)\s*\(',
                'description': 'Command execution functions (potential command injection)'
            },
            {
                'language': ['c', 'cpp', 'cc'],
                'name': 'use_after_free',
                'pattern': r'free\s*\(\s*([a-zA-Z0-9_]+)\s*\)(?!.*?\1\s*=\s*NULL)',
                'description': 'Potential use after free (no NULL assignment after free)'
            },
            
            # Python patterns
            {
                'language': ['py'],
                'name': 'command_injection',
                'pattern': r'(os\.system|os\.popen|subprocess\.Popen|subprocess\.call|subprocess\.run|eval|exec)\s*\(',
                'description': 'Command execution functions (potential command injection)'
            },
            {
                'language': ['py'],
                'name': 'sql_injection',
                'pattern': r'(cursor\.execute|execute|executemany)\s*\(\s*["\'](?:[^"\']*?\%s[^"\']*?|.*?\+)["\']',
                'description': 'Potential SQL injection (non-parameterized queries)'
            },
            
            # JavaScript patterns
            {
                'language': ['js'],
                'name': 'command_injection',
                'pattern': r'(eval|setTimeout|setInterval|Function|child_process\.exec)\s*\(',
                'description': 'Code execution functions (potential code/command injection)'
            },
            {
                'language': ['js'],
                'name': 'dom_xss',
                'pattern': r'(innerHTML|outerHTML|document\.write|document\.writeln)\s*=',
                'description': 'Potential DOM-based XSS vulnerabilities'
            },
            
            # Java patterns
            {
                'language': ['java'],
                'name': 'command_injection',
                'pattern': r'(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(',
                'description': 'Command execution functions (potential command injection)'
            },
            {
                'language': ['java'],
                'name': 'sql_injection',
                'pattern': r'(prepareStatement|createStatement|executeQuery)\s*\(\s*["\'](?:[^"\']*?\+[^"\']*?|.*?\+)',
                'description': 'Potential SQL injection (non-parameterized queries)'
            }
        ]
    
    def analyze_file(self, file_path):
        """
        Analyze a source code file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return {}
        
        # Check if file has already been analyzed
        if file_path in self.analyzed_files:
            logger.debug(f"File already analyzed: {file_path}")
            return {}
        
        # Get file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Check if we have an analyzer for this file type
        if ext not in self.analyzers:
            logger.debug(f"No analyzer available for file type: {ext}")
            return {}
        
        logger.info(f"Analyzing file: {file_path}")
        
        # Run the appropriate analyzer
        results = self.analyzers[ext](file_path)
        
        # Mark file as analyzed
        self.analyzed_files.add(file_path)
        
        return results
    
    def analyze_directory(self, directory, recursive=True):
        """
        Analyze all source files in a directory.
        
        Args:
            directory: Directory to analyze
            recursive: Whether to recursively analyze subdirectories
            
        Returns:
            dict: Analysis results
        """
        if not os.path.isdir(directory):
            logger.error(f"Not a directory: {directory}")
            return {}
        
        results = {
            'input_functions': [],
            'vulnerabilities': [],
            'functions': {},
            'data_structures': {},
            'input_formats': set(),
            'files_analyzed': []
        }
        
        # Get list of source files
        source_files = []
        for ext in self.analyzers.keys():
            if recursive:
                # Use pathlib.Path for recursive glob
                source_files.extend(list(Path(directory).rglob(f"*{ext}")))
            else:
                # Use pathlib.Path for non-recursive glob
                source_files.extend(list(Path(directory).glob(f"*{ext}")))
        
        # Analyze each file
        for file_path in source_files:
            file_path_str = str(file_path)
            file_results = self.analyze_file(file_path_str)
            
            if file_results:
                # Merge results
                results['input_functions'].extend(file_results.get('input_functions', []))
                results['vulnerabilities'].extend(file_results.get('vulnerabilities', []))
                results['functions'].update(file_results.get('functions', {}))
                results['data_structures'].update(file_results.get('data_structures', {}))
                results['input_formats'].update(file_results.get('input_formats', []))
                results['files_analyzed'].append(file_path_str)
        
        # Convert set to list for serialization
        results['input_formats'] = list(results['input_formats'])
        
        # Log summary
        logger.info(f"Analyzed {len(results['files_analyzed'])} files in {directory}")
        logger.info(f"Found {len(results['input_functions'])} input functions, "
                   f"{len(results['vulnerabilities'])} potential vulnerabilities, "
                   f"{len(results['functions'])} functions, "
                   f"{len(results['data_structures'])} data structures, "
                   f"{len(results['input_formats'])} input formats")
        
        return results
    
    def _analyze_c_file(self, file_path):
        """
        Analyze a C source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        results = {
            'input_functions': [],
            'vulnerabilities': [],
            'functions': {},
            'data_structures': {},
            'input_formats': set()
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Extract function signatures
            function_pattern = r'(\w+)\s+(\w+)\s*\(([^)]*)\)'
            functions = re.finditer(function_pattern, code)
            
            for match in functions:
                return_type, name, params = match.groups()
                
                # Skip function declarations inside typedefs/structs
                if 'typedef' in return_type or 'struct' in return_type:
                    continue
                
                results['functions'][name] = {
                    'return_type': return_type.strip(),
                    'parameters': [p.strip() for p in params.split(',') if p.strip()],
                    'file': file_path,
                    'position': match.start()
                }
                
                # Check if this is an input function
                if any(input_func in name.lower() for input_func in ['read', 'input', 'parse', 'load', 'recv']):
                    results['input_functions'].append({
                        'name': name,
                        'type': 'function',
                        'file': file_path,
                        'position': match.start()
                    })
            
            # Extract struct definitions
            struct_pattern = r'(struct|typedef\s+struct)\s+(\w+)?\s*{([^}]*)}'
            structs = re.finditer(struct_pattern, code)
            
            for match in structs:
                struct_type, name, fields = match.groups()
                
                if name is None:
                    # Anonymous struct, look for name after closing brace
                    after_brace = code[match.end():match.end()+100]
                    name_match = re.search(r'\s*(\w+)', after_brace)
                    if name_match:
                        name = name_match.group(1)
                    else:
                        name = f"anonymous_struct_{match.start()}"
                
                results['data_structures'][name] = {
                    'type': 'struct',
                    'fields': {},
                    'file': file_path,
                    'position': match.start()
                }
                
                # Parse fields
                field_pattern = r'(\w+)\s+(\w+)(?:\[([^]]*)\])?'
                fields_matches = re.finditer(field_pattern, fields)
                
                for field_match in fields_matches:
                    field_type, field_name, array_size = field_match.groups()
                    
                    results['data_structures'][name]['fields'][field_name] = {
                        'type': field_type,
                        'is_array': array_size is not None,
                        'array_size': array_size
                    }
            
            # Identify input formats
            if 'json' in code.lower() or 'parser' in code.lower():
                results['input_formats'].add('json')
            if 'xml' in code.lower():
                results['input_formats'].add('xml')
            if 'command' in code.lower() or 'argv' in code.lower():
                results['input_formats'].add('command')
            
            # Check for potential vulnerabilities
            for pattern in self.vulnerability_patterns:
                if any(lang in file_path.lower() for lang in pattern['language']):
                    matches = re.finditer(pattern['pattern'], code)
                    for match in matches:
                        results['vulnerabilities'].append({
                            'type': pattern['name'],
                            'description': pattern['description'],
                            'file': file_path,
                            'position': match.start(),
                            'line': code[:match.start()].count('\n') + 1,
                            'code': match.group(0)
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing C file {file_path}: {e}")
            return results
    
    def _analyze_cpp_file(self, file_path):
        """
        Analyze a C++ source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        # C++ analysis is similar to C but with additional class parsing
        results = self._analyze_c_file(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Extract class definitions
            class_pattern = r'(class|struct)\s+(\w+)(?:\s*:\s*(?:public|protected|private)\s+(\w+))?\s*{([^}]*)}'
            classes = re.finditer(class_pattern, code)
            
            for match in classes:
                class_type, name, parent, content = match.groups()
                
                results['data_structures'][name] = {
                    'type': class_type,
                    'parent': parent,
                    'methods': {},
                    'fields': {},
                    'file': file_path,
                    'position': match.start()
                }
                
                # Parse methods
                method_pattern = r'(virtual\s+)?(\w+)\s+(\w+)\s*\(([^)]*)\)'
                methods = re.finditer(method_pattern, content) if content else []
                
                for method_match in methods:
                    virtual, return_type, method_name, params = method_match.groups()
                    
                    results['data_structures'][name]['methods'][method_name] = {
                        'return_type': return_type,
                        'parameters': [p.strip() for p in params.split(',') if p.strip()],
                        'is_virtual': virtual is not None
                    }
                    
                    # Check if this is an input method
                    if any(input_func in method_name.lower() for input_func in ['read', 'input', 'parse', 'load', 'recv']):
                        results['input_functions'].append({
                            'name': f"{name}::{method_name}",
                            'type': 'method',
                            'class': name,
                            'file': file_path,
                            'position': match.start() + method_match.start()
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing C++ file {file_path}: {e}")
            return results
    
    def _analyze_python_file(self, file_path):
        """
        Analyze a Python source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        results = {
            'input_functions': [],
            'vulnerabilities': [],
            'functions': {},
            'data_structures': {},
            'input_formats': set()
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            try:
                # Parse the Python code
                tree = ast.parse(code, filename=file_path)
                
                # Visit all function definitions
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        # Extract function information
                        name = node.name
                        
                        # Get parameters
                        params = []
                        for arg in node.args.args:
                            params.append(getattr(arg, 'arg', arg.id if hasattr(arg, 'id') else str(arg)))
                        
                        results['functions'][name] = {
                            'parameters': params,
                            'file': file_path,
                            'line': node.lineno
                        }
                        
                        # Check if this is an input function
                        if any(input_func in name.lower() for input_func in ['read', 'input', 'parse', 'load', 'recv']):
                            results['input_functions'].append({
                                'name': name,
                                'type': 'function',
                                'file': file_path,
                                'line': node.lineno
                            })
                    
                    elif isinstance(node, ast.ClassDef):
                        # Extract class information
                        name = node.name
                        
                        # Get parent classes
                        parents = []
                        for base in node.bases:
                            if isinstance(base, ast.Name):
                                parents.append(base.id)
                            elif isinstance(base, ast.Attribute):
                                parents.append(f"{base.value.id}.{base.attr}")
                        
                        results['data_structures'][name] = {
                            'type': 'class',
                            'parents': parents,
                            'methods': {},
                            'file': file_path,
                            'line': node.lineno
                        }
                        
                        # Extract methods
                        for child in node.body:
                            if isinstance(child, ast.FunctionDef):
                                method_name = child.name
                                
                                # Get parameters (skip 'self')
                                params = []
                                for arg in child.args.args:
                                    arg_name = getattr(arg, 'arg', arg.id if hasattr(arg, 'id') else str(arg))
                                    if arg_name != 'self':
                                        params.append(arg_name)
                                
                                results['data_structures'][name]['methods'][method_name] = {
                                    'parameters': params,
                                    'line': child.lineno
                                }
                                
                                # Check if this is an input method
                                if any(input_func in method_name.lower() for input_func in ['read', 'input', 'parse', 'load', 'recv']):
                                    results['input_functions'].append({
                                        'name': f"{name}.{method_name}",
                                        'type': 'method',
                                        'class': name,
                                        'file': file_path,
                                        'line': child.lineno
                                    })
                
            except SyntaxError as e:
                logger.warning(f"Syntax error in Python file {file_path}: {e}")
                # Fall back to regex-based parsing for files with syntax errors
            
            # Identify input formats using regex
            if 'json' in code.lower():
                results['input_formats'].add('json')
            if 'xml' in code.lower() or 'lxml' in code.lower():
                results['input_formats'].add('xml')
            if 'argparse' in code.lower() or 'sys.argv' in code.lower():
                results['input_formats'].add('command')
            
            # Check for potential vulnerabilities
            for pattern in self.vulnerability_patterns:
                if 'py' in pattern['language']:
                    matches = re.finditer(pattern['pattern'], code)
                    for match in matches:
                        results['vulnerabilities'].append({
                            'type': pattern['name'],
                            'description': pattern['description'],
                            'file': file_path,
                            'position': match.start(),
                            'line': code[:match.start()].count('\n') + 1,
                            'code': match.group(0)
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing Python file {file_path}: {e}")
            return results
    
    def _analyze_javascript_file(self, file_path):
        """
        Analyze a JavaScript source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        results = {
            'input_functions': [],
            'vulnerabilities': [],
            'functions': {},
            'data_structures': {},
            'input_formats': set()
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Extract function definitions
            function_pattern = r'(function\s+(\w+)|(\w+)\s*=\s*function|(\w+)\s*:\s*function)\s*\(([^)]*)\)'
            functions = re.finditer(function_pattern, code)
            
            for match in functions:
                func_def, name1, name2, name3, params = match.groups()
                name = name1 or name2 or name3 or 'anonymous'
                
                if name != 'anonymous':
                    results['functions'][name] = {
                        'parameters': [p.strip() for p in params.split(',') if p.strip()],
                        'file': file_path,
                        'position': match.start()
                    }
                    
                    # Check if this is an input function
                    if any(input_func in name.lower() for input_func in ['read', 'input', 'parse', 'load', 'fetch']):
                        results['input_functions'].append({
                            'name': name,
                            'type': 'function',
                            'file': file_path,
                            'position': match.start()
                        })
            
            # Extract class/object definitions
            class_pattern = r'(class\s+(\w+)|(\w+)\s*=\s*class|const\s+(\w+)\s*=\s*{)'
            classes = re.finditer(class_pattern, code)
            
            for match in classes:
                class_def, name1, name2, name3 = match.groups()
                name = name1 or name2 or name3 or 'anonymous'
                
                if name != 'anonymous':
                    results['data_structures'][name] = {
                        'type': 'class' if 'class' in class_def else 'object',
                        'methods': {},
                        'file': file_path,
                        'position': match.start()
                    }
            
            # Identify input formats
            if 'json' in code.lower() or 'JSON.parse' in code:
                results['input_formats'].add('json')
            if 'xml' in code.lower() or 'DOMParser' in code:
                results['input_formats'].add('xml')
            if 'process.argv' in code or 'commander' in code.lower() or 'yargs' in code.lower():
                results['input_formats'].add('command')
            
            # Check for potential vulnerabilities
            for pattern in self.vulnerability_patterns:
                if 'js' in pattern['language']:
                    matches = re.finditer(pattern['pattern'], code)
                    for match in matches:
                        results['vulnerabilities'].append({
                            'type': pattern['name'],
                            'description': pattern['description'],
                            'file': file_path,
                            'position': match.start(),
                            'line': code[:match.start()].count('\n') + 1,
                            'code': match.group(0)
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing JavaScript file {file_path}: {e}")
            return results
    
    def _analyze_java_file(self, file_path):
        """
        Analyze a Java source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        results = {
            'input_functions': [],
            'vulnerabilities': [],
            'functions': {},
            'data_structures': {},
            'input_formats': set()
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Extract class definitions
            class_pattern = r'(public|private|protected)?\s*(class|interface|enum)\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([^{]*))?'
            classes = re.finditer(class_pattern, code)
            
            for match in classes:
                access, class_type, name, parent, interfaces = match.groups()
                
                results['data_structures'][name] = {
                    'type': class_type,
                    'access': access,
                    'parent': parent,
                    'interfaces': [i.strip() for i in interfaces.split(',')] if interfaces else [],
                    'methods': {},
                    'file': file_path,
                    'position': match.start()
                }
            
            # Extract method definitions
            method_pattern = r'(public|private|protected)?\s*(static)?\s*([\w<>\[\]]+)\s+(\w+)\s*\(([^)]*)\)'
            methods = re.finditer(method_pattern, code)
            
            for match in methods:
                access, static, return_type, name, params = match.groups()
                
                # Skip method references inside other code
                if 'return' in code[max(0, match.start()-10):match.start()]:
                    continue
                
                results['functions'][name] = {
                    'return_type': return_type,
                    'access': access,
                    'static': static is not None,
                    'parameters': [p.strip() for p in params.split(',') if p.strip()],
                    'file': file_path,
                    'position': match.start()
                }
                
                # Check if this is an input function
                if any(input_func in name.lower() for input_func in ['read', 'input', 'parse', 'load', 'receive']):
                    results['input_functions'].append({
                        'name': name,
                        'type': 'method',
                        'file': file_path,
                        'position': match.start()
                    })
            
            # Identify input formats
            if 'json' in code.lower() or 'JsonParser' in code:
                results['input_formats'].add('json')
            if 'xml' in code.lower() or 'DocumentBuilder' in code:
                results['input_formats'].add('xml')
            if 'CommandLine' in code or 'args' in code:
                results['input_formats'].add('command')
            
            # Check for potential vulnerabilities
            for pattern in self.vulnerability_patterns:
                if 'java' in pattern['language']:
                    matches = re.finditer(pattern['pattern'], code)
                    for match in matches:
                        results['vulnerabilities'].append({
                            'type': pattern['name'],
                            'description': pattern['description'],
                            'file': file_path,
                            'position': match.start(),
                            'line': code[:match.start()].count('\n') + 1,
                            'code': match.group(0)
                        })
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing Java file {file_path}: {e}")
            return results
    
    def _analyze_go_file(self, file_path):
        """
        Analyze a Go source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        results = {
            'input_functions': [],
            'vulnerabilities': [],
            'functions': {},
            'data_structures': {},
            'input_formats': set()
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Extract function definitions
            function_pattern = r'func\s+(\w+)\s*\(([^)]*)\)(?:\s+\([^)]*\)|\s+[\w*]+)?'
            functions = re.finditer(function_pattern, code)
            
            for match in functions:
                name, params = match.groups()
                
                results['functions'][name] = {
                    'parameters': [p.strip() for p in params.split(',') if p.strip()],
                    'file': file_path,
                    'position': match.start()
                }
                
                # Check if this is an input function
                if any(input_func in name.lower() for input_func in ['read', 'input', 'parse', 'load', 'recv']):
                    results['input_functions'].append({
                        'name': name,
                        'type': 'function',
                        'file': file_path,
                        'position': match.start()
                    })
            
            # Extract struct definitions
            struct_pattern = r'type\s+(\w+)\s+struct\s*{([^}]*)}'
            structs = re.finditer(struct_pattern, code)
            
            for match in structs:
                name, fields = match.groups()
                
                results['data_structures'][name] = {
                    'type': 'struct',
                    'fields': {},
                    'file': file_path,
                    'position': match.start()
                }
                
                # Parse fields
                field_pattern = r'(\w+)\s+(\w+)'
                fields_matches = re.finditer(field_pattern, fields)
                
                for field_match in fields_matches:
                    field_name, field_type = field_match.groups()
                    
                    results['data_structures'][name]['fields'][field_name] = {
                        'type': field_type
                    }
            
            # Identify input formats
            if 'json' in code.lower() or 'encoding/json' in code:
                results['input_formats'].add('json')
            if 'xml' in code.lower() or 'encoding/xml' in code:
                results['input_formats'].add('xml')
            if 'flag' in code.lower() or 'os.Args' in code:
                results['input_formats'].add('command')
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing Go file {file_path}: {e}")
            return results
    
    def _analyze_rust_file(self, file_path):
        """
        Analyze a Rust source file.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            dict: Analysis results
        """
        results = {
            'input_functions': [],
            'vulnerabilities': [],
            'functions': {},
            'data_structures': {},
            'input_formats': set()
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            # Extract function definitions
            function_pattern = r'fn\s+(\w+)\s*(?:<[^>]*>)?\s*\(([^)]*)\)(?:\s+->\s+[^{]+)?'
            functions = re.finditer(function_pattern, code)
            
            for match in functions:
                name, params = match.groups()
                
                results['functions'][name] = {
                    'parameters': [p.strip() for p in params.split(',') if p.strip()],
                    'file': file_path,
                    'position': match.start()
                }
                
                # Check if this is an input function
                if any(input_func in name.lower() for input_func in ['read', 'input', 'parse', 'load', 'recv']):
                    results['input_functions'].append({
                        'name': name,
                        'type': 'function',
                        'file': file_path,
                        'position': match.start()
                    })
            
            # Extract struct definitions
            struct_pattern = r'struct\s+(\w+)(?:<[^>]*>)?\s*{([^}]*)}'
            structs = re.finditer(struct_pattern, code)
            
            for match in structs:
                name, fields = match.groups()
                
                results['data_structures'][name] = {
                    'type': 'struct',
                    'fields': {},
                    'file': file_path,
                    'position': match.start()
                }
                
                # Parse fields
                field_pattern = r'(\w+)\s*:\s*([^,]+)'
                fields_matches = re.finditer(field_pattern, fields)
                
                for field_match in fields_matches:
                    field_name, field_type = field_match.groups()
                    
                    results['data_structures'][name]['fields'][field_name] = {
                        'type': field_type.strip()
                    }
            
            # Identify input formats
            if 'json' in code.lower() or 'serde_json' in code:
                results['input_formats'].add('json')
            if 'xml' in code.lower() or 'serde_xml' in code:
                results['input_formats'].add('xml')
            if 'clap' in code.lower() or 'std::env::args' in code:
                results['input_formats'].add('command')
            
            return results
            
        except Exception as e:
            logger.error(f"Error analyzing Rust file {file_path}: {e}")
            return results
    
    def generate_test_cases(self, results, output_dir=None):
        """
        Generate test cases based on analysis results.
        
        Args:
            results: Analysis results
            output_dir: Directory to write test cases to
            
        Returns:
            list: Generated test cases
        """
        import random
        from datetime import datetime
        
        test_cases = []
        
        # Create output directory if needed
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamp for file names
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate test cases for each input format
        for input_format in results['input_formats']:
            # Number of test cases to generate
            num_cases = random.randint(5, 10)
            
            for i in range(num_cases):
                test_case = {
                    'format': input_format,
                    'is_valid': random.random() < 0.8,  # 80% valid, 20% invalid
                    'data': None,
                    'metadata': {
                        'generated': timestamp,
                        'index': i
                    }
                }
                
                # Generate data based on format
                if input_format == 'json':
                    # Import the JSON grammar
                    try:
                        import grammars.json_grammar as json_grammar
                        test_case['data'] = json_grammar.generate(valid=test_case['is_valid'])
                    except ImportError:
                        test_case['data'] = '{"test": "data"}'
                
                elif input_format == 'xml':
                    # Import the XML grammar
                    try:
                        import grammars.xml_grammar as xml_grammar
                        test_case['data'] = xml_grammar.generate(valid=test_case['is_valid'])
                    except ImportError:
                        test_case['data'] = '<root><test>data</test></root>'
                
                elif input_format == 'command':
                    # Import the command grammar
                    try:
                        import grammars.command_grammar as command_grammar
                        test_case['data'] = command_grammar.generate(valid=test_case['is_valid'])
                    except ImportError:
                        test_case['data'] = 'program --option value'
                
                else:
                    # Default random data
                    test_case['data'] = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(20))
                
                # Add to test cases
                test_cases.append(test_case)
                
                # Write to file if output directory is specified
                if output_dir:
                    file_name = f"{input_format}_testcase_{i:03d}_{timestamp}"
                    
                    if input_format == 'json':
                        file_path = os.path.join(output_dir, f"{file_name}.json")
                    elif input_format == 'xml':
                        file_path = os.path.join(output_dir, f"{file_name}.xml")
                    elif input_format == 'command':
                        file_path = os.path.join(output_dir, f"{file_name}.cmd")
                    else:
                        file_path = os.path.join(output_dir, f"{file_name}.txt")
                    
                    with open(file_path, 'w') as f:
                        f.write(test_case['data'])
                    
                    test_case['file'] = file_path
        
        logger.info(f"Generated {len(test_cases)} test cases")
        return test_cases
    
    def save_results(self, results, output_file):
        """
        Save analysis results to a file.
        
        Args:
            results: Analysis results
            output_file: Path to save results to
            
        Returns:
            bool: Success status
        """
        try:
            # Convert set to list for JSON serialization
            if 'input_formats' in results and isinstance(results['input_formats'], set):
                results['input_formats'] = list(results['input_formats'])
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Saved analysis results to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving analysis results: {e}")
            return False