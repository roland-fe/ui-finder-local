#!/usr/bin/env python3
"""
Network scanner for macOS that runs without sudo (TCP Connect Scan).
It finds all active devices in the specified subnet and checks
if a web interface (port 80 or 443) is reachable.

Usage:
    ./network_scanner.py <subnet>
Example:
    ./network_scanner.py 192.168.178.0/24
"""

import sys
import nmap
import requests
from requests.exceptions import RequestException

def main():
    # Check if a subnet argument was provided
    if len(sys.argv) < 2:
        print("Usage: python3 network_scanner.py <subnet>")
        print("Example: python3 network_scanner.py 192.168.178.0/24")
        sys.exit(1)

    subnet = sys.argv[1]
    print(f"Starting scan for network: {subnet}")
    print("This may take a while depending on the network size...\n")

    # Create an Nmap PortScanner object
    nm = nmap.PortScanner()

    try:
        # Scan ports 80, 443; -sT (TCP Connect Scan) = no sudo required
        # -n = no DNS resolve, -T4 = faster scan speed
        print("→ Starting Nmap (TCP Connect Scan)...")
        nm.scan(hosts=subnet, ports="80,443", arguments="-sT -n -T4")
    except nmap.PortScannerError as e:
        print("Error executing nmap:", str(e))
        sys.exit(1)

    # Get all detected hosts
    hosts_list = nm.all_hosts()
    total_hosts = len(hosts_list)
    print(f"\nFound {total_hosts} host(s) in the scan.\n")

    # Store results (list of tuples: (IP, Hostname, WebUI-Link, Device-Type))
    results = []

    # Iterate through the host list and gather details
    for i, host in enumerate(hosts_list, start=1):
        state = nm[host].state()
        print(f"[{i}/{total_hosts}] Checking host: {host} (State: {state})")

        if state != "up":
            continue

        # Determine hostname (can be empty)
        hostname = nm[host].hostname() or "-"

        # Check if port 80 or 443 is open; if so, test HTTP request
        webui_link = "-"
        device_type = "Unknown"
        
        if 'tcp' in nm[host]:
            # Order: first 443 (HTTPS), then 80 (HTTP)
            for port in [443, 80]:
                port_info = nm[host]['tcp'].get(port)
                if port_info and port_info['state'] == 'open':
                    protocol = "https" if port == 443 else "http"
                    url = f"{protocol}://{host}:{port}"
                    print(f"   -> Port {port} is open, testing HTTP request: {url}")

                    try:
                        # HTTP(S) request (short timeout, disable SSL verification for self-signed certificates)
                        r = requests.get(url, timeout=3, verify=False)
                        if r.status_code < 400:
                            webui_link = url
                            print(f"      ✓ WebUI detected (HTTP status: {r.status_code})")

                            # Read the Server header and guess the device type
                            server_header = r.headers.get("Server", "")
                            device_type = guess_device_type(server_header, hostname)
                            
                            # If we found a valid WebUI, stop checking further ports
                            break
                        else:
                            print(f"      ✗ Response: Status {r.status_code} (not a typical WebUI?)")
                    except RequestException as e:
                        print(f"      ✗ No response: {e}")

        # Add the result to the list
        results.append((host, hostname, webui_link, device_type))

    # Final overview in the console
    print("\n=== Scan Results ===")
    print("{:<16} {:<30} {:<30} {:<30}".format("IP Address", "Hostname", "WebUI-Link", "Device Type"))
    print("-" * 110)
    for (ip_addr, host_name, link, dev_type) in results:
        print("{:<16} {:<30} {:<30} {:<30}".format(ip_addr, host_name, link, dev_type))

    # Generate HTML report
    html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Network Scan Results</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        h1 {
            color: #333;
        }
        table {
            border-collapse: collapse;
            width: 80%;
            max-width: 1000px;
            margin: 10px 0;
        }
        th, td {
            border: 1px solid #bbb;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #eee;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .link a {
            color: #0066cc;
            text-decoration: none;
        }
        .link a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h1>Network Scan Results</h1>
    <p>Subnet: """ + subnet + """</p>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Hostname</th>
            <th>WebUI-Link</th>
            <th>Device Type</th>
        </tr>
"""

    for ip_addr, host_name, link, dev_type in results:
        # If there's a link, make it clickable in HTML
        if link != "-":
            link_html = f'<a href="{link}" target="_blank">{link}</a>'
        else:
            link_html = "-"
        html_content += f"""
        <tr>
            <td>{ip_addr}</td>
            <td>{host_name}</td>
            <td class="link">{link_html}</td>
            <td>{dev_type}</td>
        </tr>"""

    # End of HTML
    html_content += """
    </table>
</body>
</html>
"""

    # Write HTML to file
    output_filename = "scan_ergebnisse.html"
    try:
        with open(output_filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\nHTML report has been generated: {output_filename}")
    except IOError as e:
        print(f"Error writing HTML file: {e}")

    print("\nDone!")


def guess_device_type(server_header: str, hostname: str) -> str:
    """
    Simple heuristic approach to roughly guess the type of device/system
    based on the Server header (and possibly the hostname).
    """
    # In case no Server header is present
    server_header_lower = server_header.lower()

    if "apache" in server_header_lower:
        return "Apache Web Server (likely Linux/Unix)"
    elif "nginx" in server_header_lower:
        return "NGINX Web Server (likely Linux/Unix)"
    elif "mikrotik" in server_header_lower or "routeros" in server_header_lower:
        return "MikroTik Router"
    elif "openwrt" in server_header_lower:
        return "OpenWrt Router"
    elif "synology" in server_header_lower:
        return "Synology NAS"
    elif "lighttpd" in server_header_lower:
        return "Lighttpd (often used in embedded systems)"
    elif "iis" in server_header_lower:
        return "Microsoft IIS (Windows Server)"
    elif "jetty" in server_header_lower:
        return "Jetty (Java Web Server)"

    # As an example, you might also analyze the hostname
    # if you detect typical router hostnames (e.g., fritz.box).
    if "fritz.box" in hostname.lower():
        return "AVM Fritz!Box"

    # If none of the above applies, return unknown
    return "Unknown"


if __name__ == "__main__":
    main()