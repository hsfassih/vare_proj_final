import subprocess
import os
import time
from datetime import datetime
# import pandas as pd
import re
import joblib
import os





def run_regshot_powershell(regshot_path, output_dir, timestamp):
    """Run Regshot using PowerShell commands before binary execution."""
    try:
        if os.path.exists("start.hivu"):
            before_reg = os.path.join(output_dir, f"reg_before_{timestamp}.hivu")
            compare_reg = os.path.join(output_dir, f"reg_compare_{timestamp}.txt")
            print("already reshot taken")
            return before_reg, compare_reg
        # Ensure regshot_path is valid
        if not os.path.exists(regshot_path):
            raise FileNotFoundError(f"Regshot executable not found at {regshot_path}")
        
        # Paths for output files (for reference, though Regshot may handle internally)
        before_reg = os.path.join(output_dir, f"reg_before_{timestamp}.hivu")
        compare_reg = os.path.join(output_dir, f"reg_compare_{timestamp}.txt")
        
        # Run first Regshot command: "Regshot_cmd-x64-ANSI.exe start.hivu"
        print(f"Running Regshot: First snapshot with {regshot_path} start.hivu")
        result = subprocess.run(
            [regshot_path, "start.hivu"],
            capture_output=True, text=True, check=True
        )
        print(f"Regshot stdout: {result.stdout}")
        print(f"Regshot stderr: {result.stderr}")
        print(f"Regshot: First snapshot completed")
        
        return before_reg, compare_reg
    except Exception as e:
        print(f"Error running Regshot first snapshot: {e}")
        raise

def run_regshot_powershell_compare(regshot_path, compare_reg):
    """Run Regshot comparison using PowerShell command after binary execution."""
    try:
        # Run second Regshot command: "Regshot_cmd-x64-ANSI.exe start.hivu -C"
        print(f"Running Regshot: Comparison with {regshot_path} start.hivu -C")
        result = subprocess.run(
            [regshot_path, "start.hivu", "-C"],
            capture_output=True, text=True, check=True
        )
        print(f"Regshot stdout: {result.stdout}")
        print(f"Regshot stderr: {result.stderr}")
        print(f"Regshot: Comparison saved to {compare_reg}")
    except Exception as e:
        print(f"Error running Regshot comparison: {e}")
        raise

def run_noriben(binary_path, output_dir, timeout):
    """Run Noriben to capture Procmon data and export to CSV."""
    try:
        noriben_script = os.path.join(os.getcwd(), "Noriben.py")
        if not os.path.exists(noriben_script):
            raise FileNotFoundError("Noriben.py not found in current directory")
        if not os.path.exists(binary_path):
            raise FileNotFoundError(f"Binary {binary_path} not found")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Run Noriben with command-line arguments
        cmd = [
            "python", noriben_script,
            "--cmd", binary_path,
            "--output", output_dir,
            "--timeout", str(timeout)
        ]
        print(f"Running Noriben: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"Noriben stdout: {result.stdout}")
        print(f"Noriben stderr: {result.stderr}")
        if result.returncode != 0:
            raise RuntimeError(f"Noriben failed with code {result.returncode}")
        # Find the generated CSV
        csv_files = [f for f in os.listdir(output_dir) if f.endswith(".csv") and "timeline" not in f]
        if csv_files:
            print(f"Noriben CSV output: {os.path.join(output_dir, csv_files[0])}")
        else:
            print("Warning: No CSV file found in output directory")
    except Exception as e:
        print(f"Error running Noriben: {e}")
        raise

def main():
    # Hardcoded configuration
    binary_path = r"malware1.exe"  # Replace with actual binary path
    output_dir = r"OUTPUT"         # Output directory for results
    timeout = 60                            # Timeout for Noriben execution (seconds)
    regshot_path = r"./Regshot_cmd-x64-ANSI.exe"  # Replace with actual Regshot path

    # Setup paths
    output_dir = os.path.abspath(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Run Regshot first snapshot
    before_reg, compare_reg = run_regshot_powershell(regshot_path, output_dir, timestamp)

    # Run Noriben to execute binary and capture Procmon data
    run_noriben(binary_path, output_dir, timeout)

    # Run Regshot comparison
    run_regshot_powershell_compare(regshot_path, compare_reg)





if __name__ == "__main__":
    main()