# Network Scanner for macOS (Non-Sudo)

A simple Python 3 script to scan a local subnet for active devices without requiring `sudo`. It uses **TCP Connect Scanning** to discover hosts with open ports on 80 or 443, and then checks for a reachable web interface. An HTML report (called `scan_ergebnisse.html`) is also generated.

## Features
- **TCP Connect Scan** (no sudo required on macOS)
- Checks for open ports `80` (HTTP) and `443` (HTTPS)
- Queries the detected web service to identify a basic “Device Type” (e.g., Router, NAS, Web Server, etc.)
- Generates an HTML report with scan results

## Prerequisites
- macOS (tested on Monterey or newer, but should work on most versions)
- [Homebrew](https://brew.sh/) (recommended but not mandatory)
- Python 3.6+ (installed via Homebrew or system Python 3, if available)
- `python-nmap` and `requests` Python packages

## Installation on macOS

1. **Install Homebrew (if you don’t have it already):**
    ```bash
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    ```
   
2. **Install (or verify) Python 3 via Homebrew:**
    ```bash
    brew update
    brew install python
    ```
   > **Note:** macOS might already have Python 3 installed.  
   You can check your Python version with `python3 --version`.

3. **Clone or download this repository:**
    ```bash
    git clone https://github.com/yourusername/your-repo-name.git
    cd your-repo-name
    ```

4. **Create and activate a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
    
5. **Install dependencies:**
    ```bash
    pip install python-nmap requests
    ```
   > **Alternatively, if you have a `requirements.txt` with the needed packages, you can run:**  
   `pip install -r requirements.txt`

## Usage

1. **Make the script executable (if needed):**
    ```bash
    chmod +x network_scanner.py
    ```

2. **Run the scanner (example subnet `192.168.178.0/24`):**
    ```bash
    ./network_scanner.py 192.168.178.0/24
    ```
   Or explicitly call Python:
    ```bash
    python3 network_scanner.py 192.168.178.0/24
    ```

3. **View the generated HTML report:**
    - After the script finishes, it writes an HTML file named `scan_ergebnisse.html` in the current folder.
    - Open it in your web browser:
      ```bash
      open scan_ergebnisse.html
      ```
