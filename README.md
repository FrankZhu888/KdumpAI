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
- Python 3+
- `crash` utility, automatically installed if not present
- `kernel-debuginfo` (install via `debuginfo-install kernel`)
- Root privileges for execution
- AI API, Azure OpenAI or DeepSeek

## Installation

`$ git clone https://github.com/FrankZhu888/KdumpAI.git`

`$ cd KdumpAI`

Edit KdumpAI.py to update AI_API_KEY and AI_API_URL with your credentials, example for Azure OpenAI:

`AI_API_KEY = "your-azure-openai-key"`

`AI_API_URL = "https://<your-endpoint>/openai/deployments/<deployment>/chat/completions?api-version=2024-02-15-preview"`

## Usage
`#./KdumpAI.py --vmcore <vmcore_path> --vmlinux <vmlinux_path> [--output <output_html>]`
![image](https://github.com/user-attachments/assets/253fc2d9-0797-4c47-92b6-c470b6852262)

## Example
`# ./KdumpAI.py --vmcore /var/crash/127.0.0.1-2025-03-13-14\:50\:01/vmcore --vmlinux /usr/lib/debug/lib/modules/5.14.0-503.26.1.el9_5.x86_64/vmlinux` 

Azure OpenAI:
![image](https://github.com/user-attachments/assets/18c0423b-3059-4172-bf41-cd7373883860)

DeepSeek R1:
![image](https://github.com/user-attachments/assets/dc93edd2-d99a-47ee-baf4-bfe46d991c90)



## Analysis Report
The script generates an HTML report (kdump_ai_report.html) containing detailed analysis results.

Azure OpenAI:
![image](https://github.com/user-attachments/assets/a34659d3-d20e-442e-b39e-93b558dea2b3)

DeepSeek R1:
![image](https://github.com/user-attachments/assets/c6f3c98e-08ad-44b6-bae1-667c09cf28ab)


## Notes
For now RHEL8 and RHEL9 are supported.

Ensure the vmcore and vmlinux files match the crashed kernel version.

The script requires root privileges to install dependencies and access vmcore files.

## Support Contact

For issues or questions, contact:

Frank Zhu [frz@microsoft.com](mailto:frz@microsoft.com)

Microsoft Azure Linux Escalation Team
