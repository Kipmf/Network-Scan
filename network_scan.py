import socket
import subprocess
import platform
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup

mac_lookup = MacLookup()

def get_ip_range():
    """
    Get the IP range based on the local IP address.
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        ip_parts = local_ip.split('.')
        ip_parts[-1] = '0/24'
        return '.'.join(ip_parts)
    except socket.error as e:
        print(f"Error getting local IP: {e}")
        return None

def ping_device(ip):
    """
    Ping a device to check if it is reachable.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', ip]
    try:
        return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2) == 0
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False

def get_mac_address(ip):
    """
    Get the MAC address of a device using its IP address.
    """
    if platform.system().lower() == 'windows':
        command = f"arp -a {ip}"
    else:
        command = f"arp {ip}"
    
    try:
        result = subprocess.check_output(command, shell=True).decode()
        match = re.search(r"(([a-f0-9]{2}[:-]){5}[a-f0-9]{2})", result, re.IGNORECASE)
        return match.group(0) if match else None
    except (subprocess.CalledProcessError, subprocess.SubprocessError) as e:
        print(f"Error getting MAC address for IP {ip}: {e}")
        return None

def get_hostname(ip):
    """
    Get the hostname of a device using its IP address.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def get_device_type(mac):
    """
    Get the device type based on the MAC address.
    """
    try:
        return mac_lookup.lookup(mac)
    except Exception as e:
        return "Unknown"

def scan_network(ip_range):
    """
    Scan the network for connected devices.
    """
    if not ip_range:
        return []

    ip_base = ip_range.rsplit('.', 1)[0]
    devices = []

    def scan_ip(ip):
        try:
            if ping_device(ip):
                mac = get_mac_address(ip)
                hostname = get_hostname(ip)
                device_type = get_device_type(mac) if mac else "Unknown"
                if mac:
                    devices.append((ip, mac, hostname, device_type))
        except Exception as e:
            print(f"Error scanning IP {ip}: {e}")

    with ThreadPoolExecutor(max_workers=50) as executor:
        for i in range(1, 255):
            ip = f"{ip_base}.{i}"
            executor.submit(scan_ip, ip)

    return devices

def main():
    """
    Main function to scan the network and print connected devices.
    """
    ip_range = get_ip_range()
    devices = scan_network(ip_range)
    
    print("Connected devices:")
    for ip, mac, hostname, device_type in devices:
        print(f"IP: {ip}, MAC: {mac}, Hostname: {hostname or 'Unknown'}, Device Type: {device_type}")

if __name__ == "__main__":
    main()
