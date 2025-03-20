# KdumpAI - Automated Crash Kdump Analyzer with AI Integration

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

## Overview

KdumpAI is a Python-based tool designed to automate the analysis of Linux kernel crash dumps (kdump vmcore files) on RHEL 8 and RHEL 9 systems. By leveraging AI models (currently supporting Azure OpenAI and DeepSeek), it identifies potential crash causes such as deadlocks, memory issues, or driver errors, and generates a detailed HTML report.

The tool collects critical system data using the `crash` utility, including system info, memory usage, backtraces, process states, run queues, device statistics, kernel logs, and more. The AI then analyzes this data to provide a preliminary conclusion with actionable recommendations.

## Features

- **Automated Analysis**: Processes kdump vmcore files with a single command.
- **AI-Powered Insights**: Integrates with Azure OpenAI or DeepSeek for intelligent crash analysis.
- **Comprehensive Data Collection**: Uses a rich set of `crash` commands to gather system state.
- **HTML Reporting**: Outputs results in an easy-to-read HTML format.
- **RHEL Compatibility**: Supports Red Hat Enterprise Linux 8 and 9.

## Prerequisites

- **Operating System**: RHEL 8 or RHEL 9.
- **Python**: Version 3.6 or higher.
- **Crash Utility**: Automatically installed if not present (requires root privileges).
- **Dependencies**: Install required Python packages:
  ```bash
  pip install requests jinja2

AI API Access: An API key and endpoint for either Azure OpenAI or DeepSeek.

Installation

    Clone the repository:
    bash

git clone https://github.com/<your-username>/KdumpAI.git
cd KdumpAI
Configure AI API settings:

    Edit KdumpAI.py to update AI_API_KEY and AI_API_URL with your credentials.
    Example for Azure OpenAI:
    python

    AI_API_KEY = "your-azure-openai-key"
    AI_API_URL = "https://<your-endpoint>/openai/deployments/<deployment>/chat/completions?api-version=2024-02-15-preview"

Ensure executable permissions:
bash

    chmod +x KdumpAI.py

Usage

Run the tool with the required vmcore and vmlinux files:
bash
sudo ./KdumpAI.py --vmcore /var/crash/127.0.0.1-2025-03-13-14:50:01/vmcore \
                  --vmlinux /usr/lib/debug/lib/modules/$(uname -r)/vmlinux \
                  [--output report.html]

    --vmcore: Path to the kdump vmcore file.
    --vmlinux: Path to the matching vmlinux file with debug symbols.
    --output: Optional output HTML report path (default: kdump_ai_report.html).

Example Output
text
[2025-03-14 10:00:00] Initiating KdumpAI for automated crash analysis...
[2025-03-14 10:00:00] RHEL 9 detected, applying corresponding settings.
[2025-03-14 10:00:00] Checking crash environment...
[2025-03-14 10:00:00] Crash environment is already installed, skipping setup.
[2025-03-14 10:00:01] Processing crash dump to collect kernel data...
[2025-03-14 10:00:10] Report generated and saved to kdump_ai_report.html
Supported AI Models

    Azure OpenAI: https://<endpoint>/chat/completions?api-version=2024-02-15-preview
    DeepSeek: https://<endpoint>/chat/completions

Update AI_API_KEY and AI_API_URL in the script to match your chosen model.

Default Crash Commands
The tool collects data using the following crash commands:

    sys, kmem -i, bt -a, ps, runq, dev -i, log
    irq, swap, timer, sig, net, mach, mod

These provide a comprehensive view of system state for AI analysis.

Contributing
Contributions are welcome! Please submit a pull request or open an issue on GitHub.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Support
For questions or support, contact Frank Zhu at frz@microsoft.com, Microsoft Azure Linux Escalation Team.
