# ui-finder-local
# Network Scanner (No sudo required)

**Short Description**  
This Python script performs a TCP Connect Scan on a specified subnet (e.g., `192.168.178.0/24`) without requiring superuser privileges. It uses Nmap (via the `python-nmap` library) to find active hosts and open ports (80/443), then checks if any reachable web interfaces are present on those hosts. Results are printed in the console and saved to an HTML report.

---

## How to Run on macOS

Below is a simple step-by-step guide to install Python 3, create and activate a virtual environment, install the necessary dependencies, and finally execute the script.

### 1. Install or Verify Python 3
1. Open the **Terminal** app.
2. Check if Python 3 is installed by running:
   ```bash
   python3 --version
