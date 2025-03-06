# Use Case: Automated Security Vulnerability Scanning
## 🔍 Objective: Scan a target system or network for open ports and vulnerabilities using Python.

# 🔧 Tools Used:

Nmap (Network Mapper) – Popular open-source tool for network scanning
Python Libraries:
python-nmap – For automating Nmap scans
requests – For checking web security vulnerabilities
shodan (optional) – For checking exposed services on the internet

#🔹 Step 1: Install Dependencies

Before running the script, install the required Python modules:
pip install python-nmap requests shodan

#🔹 Step 2: Python Script for Automated Vulnerability Scanning
This script:
✅ Scans open ports on a target system
✅ Identifies potential vulnerabilities (based on Nmap scripts)
✅ Checks if services are exposed on the internet (using Shodan API)

    import nmap
    import requests
    import shodan

    # Replace with your Shodan API key (sign up at https://www.shodan.io/)
    SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

    # Initialize scanners
    nm = nmap.PortScanner()
    shodan_api = shodan.Shodan(SHODAN_API_KEY)

    # Function to scan a target IP or domain
    def scan_target(target):
    print(f"Scanning target: {target}")

    # Run Nmap scan for open ports
    nm.scan(target, arguments="-sV --script=vuln")
    
    for host in nm.all_hosts():
        print(f"\n[+] Host: {host} ({nm[host].hostname()})")
        
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                state = nm[host][proto][port]['state']
                print(f"    - Port {port}/{proto} ({service}): {state}")

                # If any vulnerability script ran, print the output
                if 'script' in nm[host][proto][port]:
                    print("    Possible Vulnerabilities:")
                    for script, output in nm[host][proto][port]['script'].items():
                        print(f"        - {script}: {output}")

    # Function to check if the target is exposed on the internet using Shodan
    def check_shodan(target):
    print(f"\nChecking {target} on Shodan...")
    try:
        result = shodan_api.host(target)
        print("[+] Found in Shodan! Possible exposure:")
        print(f"    - IP: {result['ip_str']}")
        print(f"    - Organization: {result.get('org', 'N/A')}")
        print(f"    - OS: {result.get('os', 'N/A')}")
        print("    - Open Ports:", result["ports"])
    except shodan.APIError:
        print("[-] No public data found on Shodan.")
    # Run the scan and security checks
    if __name__ == "__main__":
    target_ip = input("Enter target IP/Domain: ")
    scan_target(target_ip)
    check_shodan(target_ip)

#🔹 Step 3: Running the Script
Save the script as security_scan.py

# Run it in the terminal:

python security_scan.py

Enter the target IP or domain when prompted.

#🔹 Step 4: Understanding the Output
✅ Port Scanning Results:

# Lists all open ports and running services.
Shows possible vulnerabilities based on Nmap scripts.
✅ Shodan Exposure Check:

Checks if the target is exposed publicly on the internet.
Displays any found information like open ports, organization, and OS.

