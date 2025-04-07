#!/usr/bin/env python3
"""
Simple test target for fuzzing.
This program processes JSON input and can crash under certain conditions.
"""
import sys
import json

def process_data(data):
    """Process input data and trigger vulnerabilities."""
    try:
        # Parse JSON input
        obj = json.loads(data)
        
        # Potential crash 1: If "magic" key has specific value
        if "magic" in obj and obj["magic"] == "crash_me_now":
            # Simulate a crash
            raise RuntimeError("Simulated crash 1")
        
        # Potential crash 2: Buffer overflow simulation
        if "buffer" in obj and isinstance(obj["buffer"], str):
            buffer = obj["buffer"]
            if len(buffer) > 100:
                # Simulate buffer overflow
                raise RuntimeError("Simulated buffer overflow")
        
        # Potential crash 3: Division by zero
        if "divisor" in obj and isinstance(obj["divisor"], (int, float)):
            result = 100 / obj["divisor"]  # Can cause division by zero
            print(f"Division result: {result}")
            
        # Potential crash 4: Deep recursion simulation
        if "depth" in obj and isinstance(obj["depth"], int):
            if obj["depth"] > 1000:
                # Simulate stack overflow
                raise RuntimeError("Simulated stack overflow")
        
        print("Processing completed successfully.")
        return True
        
    except json.JSONDecodeError:
        print("Invalid JSON format")
        return False
    except ZeroDivisionError:
        # This is a real crash, not simulated
        print("Error: Division by zero")
        raise  # Reraise to cause a real crash
    except Exception as e:
        print(f"Error: {e}")
        raise  # Reraise to cause a crash
        
def main():
    # Read input from stdin or file
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            data = f.read()
    else:
        data = sys.stdin.read()
    
    # Process the data
    process_data(data)

if __name__ == "__main__":
    main()