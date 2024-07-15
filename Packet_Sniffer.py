import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading

class PacketSniffer:
    def __init__(self):
        self.is_sniffing = False
        self.packets = []

    def start_sniffing(self):
        self.is_sniffing = True
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.is_sniffing)

    def stop_sniffing(self):
        self.is_sniffing = False

    def process_packet(self, packet):
        self.packets.append(packet)
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            payload = packet[IP].payload

            protocol_map = {6: 'TCP', 17: 'UDP'}
            protocol_name = protocol_map.get(protocol, 'Other')

            packet_info = f"Source: {ip_src}, Destination: {ip_dst}, Protocol: {protocol_name}, Payload: {payload}\n"
            app.update_packet_display(packet_info)

sniffer = PacketSniffer()

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("700x500")
        self.root.configure(bg='#2b2b2b')
        self.create_widgets()
        self.sniffer_thread = None

    def create_widgets(self):
        tk.Label(self.root, text="Packet Sniffer", font=("Helvetica", 18), bg='#2b2b2b', fg='#ffffff').pack(pady=10)

        self.start_button = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing, font=("Helvetica", 12), bg='#3a3a3a', fg='#ffffff')
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing, font=("Helvetica", 12), bg='#3a3a3a', fg='#ffffff', state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        self.packet_display = scrolledtext.ScrolledText(self.root, width=80, height=20, font=("Helvetica", 10), bg='#404040', fg='#ffffff', insertbackground='white')
        self.packet_display.pack(pady=10)

    def start_sniffing(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.sniffer_thread = threading.Thread(target=sniffer.start_sniffing)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        sniffer.stop_sniffing()
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.sniffer_thread:
            self.sniffer_thread.join()

    def update_packet_display(self, packet_info):
        self.packet_display.insert(tk.END, packet_info)
        self.packet_display.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
