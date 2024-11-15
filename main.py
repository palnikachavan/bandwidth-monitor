import time
import psutil
import tkinter as tk
from scapy.all import sniff, IP
import threading

class BandwidthMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Bandwidth Monitor")
        self.root.geometry("600x600")

        self.last_rec = psutil.net_io_counters().bytes_recv
        self.last_sent = psutil.net_io_counters().bytes_sent
        self.last_total = self.last_rec + self.last_sent

        # bandwidth usage
        self.recv_label = tk.Label(root, text="Received: 0.00 MB")
        self.recv_label.pack(pady=10)
        
        self.sent_label = tk.Label(root, text="Sent: 0.00 MB")
        self.sent_label.pack(pady=10)
        
        self.total_label = tk.Label(root, text="Total: 0.00 MB")
        self.total_label.pack(pady=10)

        
        self.packet_display = tk.Text(root, height=20, width=80)
        self.packet_display.pack(pady=10)
        
        
        self.update_speed()

        # Start the packet sniffing in a new thread
        packet_thread = threading.Thread(target=self.start_sniffing)
        packet_thread.daemon = True
        packet_thread.start()

    def update_speed(self):
        # current bandwidth stats
        bytes_recv = psutil.net_io_counters().bytes_recv
        bytes_sent = psutil.net_io_counters().bytes_sent
        bytes_total = bytes_recv + bytes_sent
        
        # calculate the difference since last check
        new_rec = bytes_recv - self.last_rec
        new_sent = bytes_sent - self.last_sent
        new_total = bytes_total - self.last_total

        # bytes to MB
        mb_rec = new_rec / (1024**2)
        mb_sent = new_sent / (1024**2)
        mb_total = new_total / (1024**2)

        #update the labels
        self.recv_label.config(text=f"Received: {mb_rec:.2f} MB")
        self.sent_label.config(text=f"Sent: {mb_sent:.2f} MB")
        self.total_label.config(text=f"Total: {mb_total:.2f} MB")

        # last values updated for the next comparison
        self.last_rec = bytes_recv
        self.last_sent = bytes_sent
        self.last_total = bytes_total

        # next update after
        self.root.after(1000, self.update_speed)

    def start_sniffing(self):
        # sniff for incoming packets and pass them to the packet handler
        sniff(prn=self.packet_handler, store=False)

    def packet_handler(self, packet):
        # display packet details 
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}   # map for known protocols
            proto_name = protocol_map.get(proto, "Unknown")
            packet_info = f"Src: {src_ip} -> Dst: {dst_ip} | Protocol: {proto_name}\n"
            
            # put info to GUI
            self.packet_display.insert(tk.END, packet_info)
            self.packet_display.see(tk.END)  # Auto-scroll to the bottom


if __name__ == "__main__":
    root = tk.Tk()
    app = BandwidthMonitor(root)
    root.mainloop()
