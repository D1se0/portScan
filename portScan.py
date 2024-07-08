#!/bin/python3

import socket
import argparse
from datetime import datetime
from termcolor import colored
import subprocess
import ipaddress
from scapy.all import ARP, Ether, srp

# Function to generate IP addresses from CIDR range
def generate_ip_addresses(cidr):
    try:
        network = ipaddress.ip_network(cidr)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        print(colored(f"Error: Invalid CIDR notation ({e})", 'red'))
        return []

# Function to perform ARP scan using scapy
def arp_scan(ip):
    try:
        arp_request = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp_request
        result = srp(packet, timeout=3, verbose=False)[0]
        active_ips = []
        for sent, received in result:
            active_ips.append(received.psrc)
        return active_ips
    except Exception as e:
        print(colored(f"Error during ARP scan: {e}", 'red'))
        return []

# Function to generate the logo
def generate_logo():
    logo = """
    ****************************************
    *                                      *
    *            portScan Tool             *
    *            portScan v1.0             *
    *           by Diseo (@d1se0)          *
    *                                      *
    ****************************************
    """
    print(colored(logo, 'cyan'))

# Function to scan ports
def scan_ports(ip, port_range):
    open_ports = []
    filtered_ports = []
    all_ports = []
    for port in port_range:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
            all_ports.append((port, "open"))
        else:
            filtered_ports.append(port)
            all_ports.append((port, "filtered/closed"))
        s.close()
    return open_ports, filtered_ports, all_ports

# Function to print port details
def print_port_details(port, status):
    service_name = socket.getservbyport(port, "tcp") if status == "open" else "unknown"
    details = f"Port {port} ({service_name}) is {status}"
    if status == "open":
        print(colored(details, 'green'))
    else:
        print(colored(details, 'red'))

# Function to print detailed information about open ports for --only-open
def print_open_port_details(port):
    try:
        service_name = socket.getservbyport(port, "tcp")
    except:
        service_name = "unknown"
    print(colored(f"Port {port} is open", 'green'))
    print(colored(f" - Service: {service_name}", 'yellow'))
    print(colored(f" - Protocol: TCP", 'yellow'))

# Function to get detailed information using Nmap for --all
def get_detailed_info(ip, open_ports):
    detailed_info = ""
    ports = ",".join(map(str, open_ports))
    try:
        result = subprocess.check_output(['nmap', '-sCV', '-p' + ports, ip], stderr=subprocess.STDOUT, universal_newlines=True)
        detailed_info += result
    except subprocess.CalledProcessError as e:
        detailed_info += e.output
    return detailed_info

# Function to perform scan on multiple IPs
def scan_multiple_ips(ips, port_range, only_open, only_filtered, all, export):
    try:
        for ip in ips:
            print(colored(f"\nScanning {ip}...", 'yellow'))
            open_ports, filtered_ports, all_ports = scan_ports(ip, port_range)

            if only_open:
                print(colored("Detailed information for open ports:", 'blue'))
                for port in open_ports:
                    print_open_port_details(port)
            elif only_filtered:
                print(colored("Filtered/closed ports:", 'red'))
                for port in filtered_ports:
                    print_port_details(port, "filtered/closed")
            elif all:
                detailed_info = get_detailed_info(ip, open_ports)
                print(colored(detailed_info, 'green'))
            else:
                print(colored("Open ports:", 'green'))
                for port in open_ports:
                    print_port_details(port, "open")
                print(colored("\nFiltered/closed ports:", 'red'))
                for port in filtered_ports:
                    print_port_details(port, "filtered/closed")

            if export:
                with open(export, 'a') as file:
                    file.write(f"\nScanning {ip}...\n")
                    if only_open:
                        file.write("Detailed information for open ports:\n")
                        for port in open_ports:
                            service_name = socket.getservbyport(port, "tcp")
                            file.write(f"Port {port} is open\n")
                            file.write(f" - Service: {service_name}\n")
                            file.write(f" - Protocol: TCP\n")
                    elif only_filtered:
                        file.write("Filtered/closed ports:\n")
                        for port in filtered_ports:
                            file.write(f"Port {port} is filtered or closed\n")
                    elif all:
                        file.write(detailed_info)
                    else:
                        file.write("Open ports:\n")
                        for port in open_ports:
                            service_name = socket.getservbyport(port, "tcp")
                            file.write(f"Port {port} ({service_name}) is open\n")
                        file.write("\nFiltered/closed ports:\n")
                        for port in filtered_ports:
                            file.write(f"Port {port} is filtered or closed\n")
    except KeyboardInterrupt:
        print(colored("\n[+] Saliendo...", 'red'))
        exit()

# Function to perform network discovery using ARP
def perform_network_discovery(subnet):
    print(colored(f"Performing network discovery for subnet {subnet}...", 'yellow'))
    active_ips = arp_scan(subnet)

    if not active_ips:
        print(colored("No active hosts found.", 'red'))
    else:
        print(colored("\nActive hosts found:", 'green'))
        for ip in active_ips:
            print(colored(f" - {ip}", 'green'))
    return active_ips

# Main function
def main():
    parser = argparse.ArgumentParser(description=colored("""
    ****************************************
    *                                      *
    *            portScan Tool             *
    *            portScan v1.0             *
    *           by Diseo (@d1se0)          *
    *                                      *
    ****************************************
    """, 'cyan'),
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--ip", help="Single IP address to scan")
    group.add_argument("-s", "--subnet", help="CIDR notation for subnet to scan (e.g., 192.168.5.0/24)")
    parser.add_argument("--only-open", action="store_true", help="Show only open ports with brief details")
    parser.add_argument("--only-filtered", action="store_true", help="Show only filtered ports")
    parser.add_argument("--all", action="store_true", help="Show all open ports with detailed info using Nmap")
    parser.add_argument("--export", type=str, help="Export results to a .txt file")
    args = parser.parse_args()

    if args.only_open and args.all:
        print(colored("Error: --only-open and --all cannot be used together.", 'red'))
        return
    if args.only_filtered and args.all:
        print(colored("Error: --only-filtered and --all cannot be used together.", 'red'))
        return

    # Mostrar el logo al inicio del script
    generate_logo()

    if args.subnet:
        active_ips = perform_network_discovery(args.subnet)
        if not active_ips:
            return
        # Remove the scan after listing active hosts
        return
        # scan_multiple_ips(active_ips, range(1, 1024), args.only_open, args.only_filtered, args.all, args.export)
    else:
        ip = args.ip
        port_range = range(1, 1024)

        print(colored(f"Scanning {ip}...", 'yellow'))
        start_time = datetime.now()

        try:
            open_ports, filtered_ports, all_ports = scan_ports(ip, port_range)
        except KeyboardInterrupt:
            print(colored("\n[+] Saliendo...", 'red'))
            return

        end_time = datetime.now()
        total_time = end_time - start_time

        if args.only_open:
            print(colored("Detailed information for open ports:", 'blue'))
            for port in open_ports:
                print_open_port_details(port)
        elif args.only_filtered:
            print(colored("Filtered/closed ports:", 'red'))
            for port in filtered_ports:
                print_port_details(port, "filtered/closed")
        elif args.all:
            detailed_info = get_detailed_info(ip, open_ports)
            print(colored(detailed_info, 'green'))
        else:
            print(colored("Open ports:", 'green'))
            for port in open_ports:
                print_port_details(port, "open")
            print(colored("\nFiltered/closed ports:", 'red'))
            for port in filtered_ports:
                print_port_details(port, "filtered/closed")

        print(colored(f"\nScan completed in: {total_time}", 'yellow'))

        if args.export:
            with open(args.export, 'w') as file:
                file.write(f"Scanning {ip}...\n")
                file.write(f"Scan completed in: {total_time}\n\n")
                if args.only_open:
                    file.write("Detailed information for open ports:\n")
                    for port in open_ports:
                        service_name = socket.getservbyport(port, "tcp")
                        file.write(f"Port {port} is open\n")
                        file.write(f" - Service: {service_name}\n")
                        file.write(f" - Protocol: TCP\n")
                elif args.only_filtered:
                    file.write("Filtered/closed ports:\n")
                    for port in filtered_ports:
                        file.write(f"Port {port} is filtered or closed\n")
                elif args.all:
                    file.write(detailed_info)
                else:
                    file.write("Open ports:\n")
                    for port in open_ports:
                        service_name = socket.getservbyport(port, "tcp")
                        file.write(f"Port {port} ({service_name}) is open\n")
                    file.write("\nFiltered/closed ports:\n")
                    for port in filtered_ports:
                        file.write(f"Port {port} is filtered or closed\n")

if __name__ == "__main__":
    main()
