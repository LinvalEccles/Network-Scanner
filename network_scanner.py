from scapy.all import ARP, Ether, srp
from scapy.all import IP, TCP, sr1

def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            open_ports.append(port)

            sr1(IP(dst=ip)/TCP(dport=port, flags="R"),timeout=1, verbose=0)
    return open_ports

def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, recieved in result:
        open_ports = scan_ports(recieved.psrc, [80, 443])
        devices.append({'ip': recieved.psrc, 'mac': recieved.hwsrc, 'ports': open_ports})

    return devices

def print_results(devices):
    print("IP Address\t\tMAC Address")
    print("-------------------------------------------------")
    for device in devices:
        open_ports = ", ".join(map(str, device['ports']))
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    ip_range = "192.168.1.1/24"
    scanned_devices = scan(ip_range)
    print_results(scanned_devices)

    import tkinter as tk
from tkinter import messagebox

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")

        self.label = tk.Label(root, text="Enter IP range:")
        self.label.pack(pady=10)

        self.entry = tk.Entry(root, width=30)
        self.entry.pack(pady=10)

        self.scan_button = tk.Button(root, text="Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)  # Corrected here

        self.result_text = tk.Text(root, height=10, width=50)
        self.result_text.pack(pady=10)

    def start_scan(self):
        ip_range = self.entry.get()
        devices = scan(ip_range)
        result = "IP Address\tMAC Address\tOpen Ports\n---------------------------------------------------------\n"
        for device in devices:
            open_ports = ", ".join(map(str, device['ports']))
            result += f"{device['ip']}\t{device['mac']}\t{open_ports}\n"
        self.result_text.insert(tk.END, result)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
