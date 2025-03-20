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
- **AI API**: Azure OpenAI or DeepSeek  

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

Run the tool with the required vmcore and vmlinux files:
bash
sudo ./KdumpAI.py --vmcore /var/crash/127.0.0.1-2025-03-13-14:50:01/vmcore \
                  --vmlinux /usr/lib/debug/lib/modules/$(uname -r)/vmlinux \
                  [--output report.html]

    --vmcore: Path to the kdump vmcore file.
    --vmlinux: Path to the matching vmlinux file with debug symbols.
    --output: Optional output HTML report path (default: kdump_ai_report.html).

Support
For questions or support, contact Frank Zhu at frz@microsoft.com, Microsoft Azure Linux Escalation Team.
