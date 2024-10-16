import subprocess
import re
import tkinter as tk
from tkinter import scrolledtext, messagebox, Menu
import shutil

# Function to check if a command exists
def command_exists(command):
    return shutil.which(command) is not None

# Function to run shell commands
def run_command(command):
    return subprocess.getoutput(command)

# Function to parse nmap results
def parse_nmap_output(output):
    devices = re.findall(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
    return set(devices)  # Remove duplicates

# Function to perform WHOIS lookup
def whois_lookup(ip):
    print(f"\nRunning WHOIS lookup for {ip}")
    return run_command(f"whois {ip}")

# Function to run nmap scan
def nmap_scan(subnet="192.168.1.0/24"):
    output = run_command(f"nmap -sn {subnet}")  # Adjust to your subnet
    devices = parse_nmap_output(output)
    return devices

# Function to run ARP scan
def arp_scan():
    if command_exists("arp-scan"):
        return run_command("sudo arp-scan -l")
    elif command_exists("arp"):
        return run_command("arp -a")
    else:
        return "No ARP scanning tool found. Please install arp-scan or use built-in arp command."

# Function to test network performance using iperf
def network_performance_test():
    # Note: This requires iperf server to be running on the target
    target_ip = "192.168.1.2"  # Adjust this target IP
    return run_command(f"iperf3 -c {target_ip}")

# Function to perform ping test
def ping_test(ip):
    return run_command(f"ping -c 4 {ip}")

# Function to perform DNS lookup
def dns_lookup(domain):
    return run_command(f"nslookup {domain}")

# Function for packet sniffing (using tcpdump)
def packet_sniffing():
    return run_command("sudo tcpdump -i any -c 10")  # Capture 10 packets

# Function to perform vulnerability scanning
def vulnerability_scan(ip):
    return run_command(f"sudo openvas -T {ip}")  # Requires OpenVAS setup

# Function to create network map (Nmap)
def network_mapping():
    return run_command("nmap -sn 192.168.1.0/24")  # Adjust to your subnet

# Function to scan Wi-Fi networks
def wifi_scan():
    return run_command("sudo iwlist scan")

# Function to perform malware scanning
def malware_scan():
    return run_command("clamscan -r /path/to/scan")  # Adjust the path

# Function to manage IP address (for demonstration)
def ip_address_management():
    return run_command("cat /etc/hosts")  # Show local IP address mappings

# Function to export reports (simple text export)
def export_reports(data):
    with open("scan_report.txt", "w") as f:
        f.write(data)

# Function to automate scans
def automated_scans():
    return run_command("cron")  # Display cron jobs for automation

# Function to perform Nmap scan and display results in the text box
def perform_nmap_scan():
    devices = nmap_scan()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "Devices found via Nmap:\n")
    for device in devices:
        output_text.insert(tk.END, f"{device}\n")

    # Perform WHOIS lookup for each device found
    output_text.insert(tk.END, "\nWHOIS Info:\n")
    for device in devices:
        whois_info = whois_lookup(device)
        output_text.insert(tk.END, f"WHOIS Info for {device}:\n{whois_info}\n")

# Function to perform ARP scan and display results in the text box
def perform_arp_scan():
    output = arp_scan()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "ARP-scan results:\n")
    output_text.insert(tk.END, output)

# Function to perform network performance test
def perform_network_performance_test():
    output = network_performance_test()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "Network Performance Test Results:\n")
    output_text.insert(tk.END, output)

# Function to perform ping test
def perform_ping_test():
    ip = "8.8.8.8"  # Example IP, can be changed
    output = ping_test(ip)
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, f"Ping Test Results for {ip}:\n")
    output_text.insert(tk.END, output)

# Function to perform DNS lookup
def perform_dns_lookup():
    domain = "example.com"  # Example domain, can be changed
    output = dns_lookup(domain)
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, f"DNS Lookup Results for {domain}:\n")
    output_text.insert(tk.END, output)

# Function for packet sniffing
def perform_packet_sniffing():
    output = packet_sniffing()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "Packet Sniffing Results:\n")
    output_text.insert(tk.END, output)

# Function to perform vulnerability scan
def perform_vulnerability_scan():
    ip = "192.168.1.2"  # Example IP, can be changed
    output = vulnerability_scan(ip)
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, f"Vulnerability Scan Results for {ip}:\n")
    output_text.insert(tk.END, output)

# Function to create network map
def perform_network_mapping():
    output = network_mapping()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "Network Mapping Results:\n")
    output_text.insert(tk.END, output)

# Function to perform Wi-Fi scan
def perform_wifi_scan():
    output = wifi_scan()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "Wi-Fi Scan Results:\n")
    output_text.insert(tk.END, output)

# Function to perform malware scan
def perform_malware_scan():
    output = malware_scan()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "Malware Scan Results:\n")
    output_text.insert(tk.END, output)

# Function to manage IP address
def perform_ip_address_management():
    output = ip_address_management()
    output_text.delete(1.0, tk.END)  # Clear previous output
    output_text.insert(tk.END, "IP Address Management:\n")
    output_text.insert(tk.END, output)

# Create the main window
window = tk.Tk()
window.title("Network Scanner Tool")
window.configure(bg="#f0f0f0")  # Set background color

# Create a menu bar
menu_bar = Menu(window)

# Create a 'Scan' menu with options
scan_menu = Menu(menu_bar, tearoff=0)
scan_menu.add_command(label="Run Nmap Scan", command=perform_nmap_scan)
scan_menu.add_command(label="Run ARP Scan", command=perform_arp_scan)
scan_menu.add_command(label="Network Performance Test", command=perform_network_performance_test)
scan_menu.add_command(label="Ping Test", command=perform_ping_test)
scan_menu.add_command(label="DNS Lookup", command=perform_dns_lookup)
scan_menu.add_command(label="Packet Sniffing", command=perform_packet_sniffing)
scan_menu.add_command(label="Vulnerability Scan", command=perform_vulnerability_scan)
scan_menu.add_command(label="Network Mapping", command=perform_network_mapping)
scan_menu.add_command(label="Wi-Fi Scan", command=perform_wifi_scan)
scan_menu.add_command(label="Malware Scan", command=perform_malware_scan)
scan_menu.add_command(label="IP Address Management", command=perform_ip_address_management)

menu_bar.add_cascade(label="Scans", menu=scan_menu)
window.config(menu=menu_bar)

# Create a scrolled text box for output
output_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, bg="white", fg="#333333")
output_text.grid(column=0, row=1, padx=10, pady=10, sticky='nsew')  # Sticky to expand in all directions

# Configure grid weights to allow for scaling
window.grid_rowconfigure(1, weight=1)  # Allow the output text box to expand
window.grid_columnconfigure(0, weight=1)  # Allow the column to expand

# Run the application
window.mainloop()
