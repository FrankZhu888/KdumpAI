#!/usr/bin/env python3
# KdumpAI - Automated Crash Kdump Analyzer with AI Integration
# Written by Frank Zhu <frz@microsoft.com>      2025-03-17

import subprocess
import sys
import os
import requests
import platform
import re
from datetime import datetime
from jinja2 import Template
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# AI API configuration
#AI_API_KEY = "Your-AI-API-key"
#AI_API_URL = "https://<Your-endpoint>/openai/deployments/<deployment>/chat/completions?api-version=2024-02-15-preview"

# Default output file
DEFAULT_OUTPUT_HTML = "kdump_ai_report.html"

# Updated default crash command set
DEFAULT_COMMANDS = [
    "sys", "kmem -i", "bt -a", "ps", "runq", "dev -i", "log", "irq", "swap", "timer", "sig", "net", "mach", "mod", "ipcs", "waitq" 
]

def print_usage():
    """Display usage instructions"""
    usage = """
Usage: # ./KdumpAI.py --vmcore <vmcore_path> --vmlinux <vmlinux_path> [--output <output_html>]

Description:
    Analyzes a kdump vmcore file on RHEL 8 and RHEL 9 systems using AI (supports Azure OpenAI and DeepSeek) to
    identify potential crash causes, including system info, memory usage, backtraces, process states, run queues,
    device status, kernel logs, and more.
    Outputs results to an HTML report.

Required Arguments:
    --vmcore    Path to the vmcore file (e.g., /var/crash/127.0.0.1-2025-03-13-14:50:01/vmcore)
    --vmlinux   Path to the vmlinux file with debug symbols (e.g., /usr/lib/debug/lib/modules/$(uname -r)/vmlinux)

Optional Arguments:
    --output    Path to the output HTML report (default: kdump_ai_report.html)

Example:
    # ./KdumpAI.py --vmcore /var/crash/127.0.0.1-2025-03-13-14:50:01/vmcore \\
                     --vmlinux /usr/lib/debug/lib/modules/5.14.0-503.26.1.el9_5.x86_64/vmlinux \\
                     --output report.html

Notes:
    - Requires root privileges (sudo) to run crash tools if not installed.
    - Ensure the vmcore and vmlinux files match the crashed kernel version.
    - Update AI_API_KEY and AI_API_URL with your own AI API settings. Supported models and URL format example:
      * Azure OpenAI:   https://URI/chat/completions?api-version=2024-02-15-preview
      * DeepSeek:       https://URI/chat/completions

Support Contact: Frank Zhu <frz@microsoft.com>   Microsoft Azure Linux Escalation Team
    """
    print(usage)

def log_progress(message, color=None):
    """Print log messages with timestamp and optional color"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if color == "red":
        print(f"\033[31m[{timestamp}] {message}\033[0m")
    elif color == "green":
        print(f"\033[32m[{timestamp}] {message}\033[0m")
    else:
        print(f"[{timestamp}] {message}")

def setup_crash_environment():
    """Check and install crash environment if not present"""
    log_progress("Checking crash environment...")
    try:
        subprocess.run(["crash", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_progress("Crash environment is already installed, skipping setup.")
    except FileNotFoundError:
        log_progress("Crash not found, installing crash environment...", color="red")
        try:
            subprocess.run(["sudo", "dnf", "install", "-y", "crash"], check=True)
            log_progress("Crash environment installed successfully.")
        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to install crash environment: {e}")

def get_rhel_version():
    """Detect the RHEL version of the current system, returns '8' or '9'"""
    try:
        with open("/etc/os-release", "r") as f:
            content = f.read()
            match = re.search(r'VERSION_ID="(\d+)\.\d+"', content)
            if match:
                major_version = match.group(1)
                if major_version in ["8", "9"]:
                    return major_version
        release = platform.release()
        if "el8" in release:
            return "8"
        elif "el9" in release:
            return "9"
        raise Exception("Unable to determine RHEL version.")
    except Exception as e:
        log_progress(f"Error detecting RHEL version: {e}", color="red")
        raise Exception("System version detection failed. Ensure running on RHEL 8 or 9.")

def run_crash_command_rhel8(command, vmcore_path, vmlinux_path, debug=False):
    """Execute and filter crash command output for RHEL 8"""
    full_cmd = ["crash", vmlinux_path, vmcore_path]
    process = subprocess.Popen(full_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True, bufsize=1024*1024)
    stdout, stderr = process.communicate(input=f"{command}\nquit\n")

    if debug:
        log_progress(f"Raw output for '{command}' (RHEL 8):\n{stdout}")

    if process.returncode != 0:
        raise Exception(f"Crash command failed: {stderr}\nCommand: {command}")

    lines = stdout.splitlines()
    filtered_output = []
    state_found = False
    capture = False

    for line in lines:
        if any(keyword in line for keyword in [
            "crash ", "Copyright", "GNU gdb (GDB)", "This GDB was configured", "Type", "For help",
            "please wait...", "NOTE: stdin: not a tty", "quit", "License GPLv3+", "This program",
            "show copying", "show warranty", "free software", "no warranty"
        ]):
            continue

        if "STATE:" in line:
            state_found = True
            continue

        if state_found and not line.strip() and not capture:
            capture = True
            continue

        if capture:
            filtered_output.append(line)

    output = "\n".join(filtered_output).strip()

    if debug:
        log_progress(f"Filtered output for '{command}' (RHEL 8):\n{output}")

    if not output:
        log_progress(f"Warning: No valid output from command '{command}'")

    return output

def run_crash_command_rhel9(command, vmcore_path, vmlinux_path, debug=False):
    """Execute and filter crash command output for RHEL 9"""
    full_cmd = ["crash", vmlinux_path, vmcore_path]
    process = subprocess.Popen(full_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, bufsize=1024*1024)
    stdout, stderr = process.communicate(input=f"{command}\nquit\n")

    if debug:
        log_progress(f"Raw output for '{command}' (RHEL 9):\n{stdout}")

    if process.returncode != 0:
        raise Exception(f"Crash command failed: {stderr}\nCommand: {command}")

    lines = stdout.splitlines()
    filtered_output = []
    capture = False

    for line in lines:
        if line.startswith("crash ") and "Copyright" in line:
            continue
        if "GNU gdb (GDB)" in line or "This GDB was configured" in line or "Type" in line or "For help" in line:
            continue
        if "please wait..." in line:
            continue
        if line.startswith("crash>"):
            capture = True
            continue
        if capture and line.strip() == "quit":
            break
        if capture:
            filtered_output.append(line)

    output = "\n".join(filtered_output).strip()

    if debug:
        log_progress(f"Filtered output for '{command}' (RHEL 9):\n{output}")

    if not output:
        log_progress(f"Warning: No valid output from command '{command}'")

    return output

def run_crash_command(command, vmcore_path, vmlinux_path, rhel_version):
    """Run the appropriate crash command based on RHEL version"""
    if rhel_version == "8":
        return run_crash_command_rhel8(command, vmcore_path, vmlinux_path)
    else:  # rhel_version == "9"
        return run_crash_command_rhel9(command, vmcore_path, vmlinux_path)

def analyze_with_ai(crash_output):
    """Call AI API to analyze crash output"""
    headers = {
        "Authorization": f"Bearer {AI_API_KEY}",
        "Content-Type": "application/json"
    }
    prompt = f"""
You are a Linux kernel expert. Below is the output from the crash tool analyzing a kdump, containing results from multiple commands:
    {crash_output}
    Please analyze and provide a preliminary conclusion, focusing on potential crash causes (e.g., deadlock, memory issues, driver errors).
Return format:
- **Problem Overview**: [Brief description of the issue]
- **Possible Causes**: [Detailed analysis of causes]
- **Recommendations**: [Suggestions for investigation or resolution]
"""
    payload = {
        "messages": [
            {"role": "system", "content": "You are a Linux kernel expert."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 2000,
        "temperature": 0.5,
        "top_p": 0.95
    }

    try:
        log_progress("Calling AI API for crash analysis...")
        word_count = len(crash_output.split())
        log_progress(f"Kdump trace length: {word_count} tokens")
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        response = session.post(AI_API_URL, json=payload, headers=headers, timeout=900)
        response.raise_for_status()
        data = response.json()
        if "choices" not in data or not data["choices"]:
            raise ValueError("Invalid response format from AI API")
        result = data["choices"][0]["message"]["content"].strip()
        think_match = re.search(r'<think>(.*?)</think>', result, re.DOTALL)
        think_content = think_match.group(1).strip() if think_match else "No <think> content found"
        print(f"\n{think_content}\n")
        cleaned_result = re.sub(r'<think>.*?</think>', '', result, flags=re.DOTALL).strip()
        log_progress("Kdump analysis completed successfully", color="green")
        return cleaned_result
    except requests.exceptions.RequestException as e:
        log_progress(f"AI API request failed: {e}", color="red")
        return "Analysis failed due to network or API error. Please check connectivity and API status."
    except ValueError as e:
        log_progress(f"AI API response error: {e}", color="red")
        return "Analysis failed due to invalid API response format."
    except Exception as e:
        log_progress(f"Unexpected error during AI API call: {e}", color="red")
        return "Analysis failed due to an unexpected error."

def generate_report(crash_outputs, ai_analysis, output_file):
    """Generate an HTML report with AI analysis at the top and bold headings"""
    ai_analysis_html = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', ai_analysis)
    template_str = """
<!DOCTYPE html>
<html>
<head>
    <title>Kdump AI Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        pre { background-color: #f8f8f8; padding: 10px; white-space: pre-wrap; border: 1px solid #ddd; }
        b { font-weight: bold; }
    </style>
</head>
<body>
    <h1>Kdump AI Analysis Report</h1>
    <p>Generated on: {{ timestamp }} | Support Contact: <a href="mailto:frz@microsoft.com">frz@microsoft.com</a> Microsoft Azure Linux Escalation Team</p>
    <h2>AI Analysis Conclusion</h2>
    <pre>{{ ai_analysis }}</pre>
    <h2>Kdump Analysis Output</h2>
    <pre>{{ crash_outputs }}</pre>
</body>
</html>
"""
    template = Template(template_str)
    html_content = template.render(
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        crash_outputs=crash_outputs,
        ai_analysis=ai_analysis_html
    )
    with open(output_file, "w") as f:
        f.write(html_content)
    log_progress(f"Report generated and saved to {output_file}", color="green")

def run_default_analysis(vmcore_path, vmlinux_path, rhel_version, output_file=DEFAULT_OUTPUT_HTML):
    """Run default command set and perform AI analysis with dynamic command support"""
    log_progress("Initiating KdumpAI for automated crash analysis...", color="red")
    log_progress(f"RHEL {rhel_version} detected, applying corresponding settings.")
    setup_crash_environment()
    log_progress("Processing crash dump to collect kernel data...")
    crash_outputs = ""
    pid_list = []

    # First pass: Collect ps output to identify D state processes
    ps_output = run_crash_command("ps", vmcore_path, vmlinux_path, rhel_version)
    crash_outputs += f"Command: ps\n{ps_output}\n\n"
    for line in ps_output.splitlines():
        if " UN " in line:  # D state processes
            pid = line.split()[0]
            pid_list.append(pid)

    # Second pass: Collect bt -a output to extract addresses
    bt_output = run_crash_command("bt -a", vmcore_path, vmlinux_path, rhel_version)
    crash_outputs += f"Command: bt -a\n{bt_output}\n\n"
    addr_match = re.search(r"rip: ([0-9a-f]+)", bt_output)
    crash_addr = addr_match.group(1) if addr_match else None

    # Execute default commands and dynamic commands
    dynamic_commands = ["files", "task", "vm", "pte"]
    for command in DEFAULT_COMMANDS + dynamic_commands:
        try:
            if command in ["files", "task", "vm"] and pid_list:
                for pid in pid_list[:3]:  # Limit to 3 PIDs to avoid excessive output
                    output = run_crash_command(f"{command} {pid}", vmcore_path, vmlinux_path, rhel_version)
                    crash_outputs += f"Command: {command} {pid}\n{output}\n\n"
            elif command == "pte" and crash_addr:
                output = run_crash_command(f"pte {crash_addr}", vmcore_path, vmlinux_path, rhel_version)
                crash_outputs += f"Command: pte {crash_addr}\n{output}\n\n"
            elif command not in dynamic_commands:  # Static commands from DEFAULT_COMMANDS
                output = run_crash_command(command, vmcore_path, vmlinux_path, rhel_version)
                crash_outputs += f"Command: {command}\n{output}\n\n"
        except Exception as e:
            crash_outputs += f"Command: {command}\nError: {e}\n\n"

    if not crash_outputs.strip():
        log_progress("No valid crash output available for analysis", color="red")
        return

    ai_analysis = analyze_with_ai(crash_outputs)
    generate_report(crash_outputs, ai_analysis, output_file)

def main():
    """Main function to parse arguments and run default analysis"""
    if len(sys.argv) < 5 or "--vmcore" not in sys.argv or "--vmlinux" not in sys.argv:
        print_usage()
        sys.exit(1)

    vmcore_path = None
    vmlinux_path = None
    output_file = DEFAULT_OUTPUT_HTML

    # Parse arguments
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--vmcore" and i + 1 < len(sys.argv):
            vmcore_path = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--vmlinux" and i + 1 < len(sys.argv):
            vmlinux_path = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--output" and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        else:
            print(f"Unknown or invalid argument: {sys.argv[i]}")
            print_usage()
            sys.exit(1)

    if not vmcore_path or not vmlinux_path:
        print("Error: Both --vmcore and --vmlinux arguments are required")
        print_usage()
        sys.exit(1)

    if not os.path.exists(vmcore_path) or not os.path.exists(vmlinux_path):
        log_progress("vmcore or vmlinux file does not exist, please check the paths", color="red")
        sys.exit(1)

    try:
        rhel_version = get_rhel_version()
        run_default_analysis(vmcore_path, vmlinux_path, rhel_version, output_file)
    except Exception as e:
        log_progress(f"Analysis failed: {e}", color="red")
        sys.exit(1)

if __name__ == "__main__":
    main()
