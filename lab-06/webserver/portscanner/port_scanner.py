from scapy.all import IP, TCP, sr1, send
import socket

common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389]

def scan_common_ports(target_domain, timeout=2):  
    open_ports = []
    try:
        target_ip = socket.gethostbyname(target_domain)
    except socket.gaierror:
        print(f"Error: Unable to resolve domain '{target_domain}'.")
        return []

    for port in common_ports:
        try:
            response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"), timeout=timeout, verbose=0)
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12: 
                    open_ports.append(port)
                    send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=0)  
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports

def main():
    target_domain = input("Enter domain: ")
    open_ports = scan_common_ports(target_domain)
    if open_ports:
        print("Open ports:")
        print(open_ports)
    else:
        print("No open ports found.")

if __name__ == "__main__":
    main()