import threading
import tkinter as tk
import socket
import sys
import constants
from struct import *
import select
from constants import ETH_LENGTH
import matplotlib.pyplot as plt
from pandas import DataFrame
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from collections import defaultdict
import random


def plot_bar_graph(dictionary, key_title, value_title, title):
    lists = sorted(dictionary.items())
    x, y = zip(*lists)
    data = {key_title: x, value_title: y}
    data_frame = DataFrame(data, columns=[key_title, value_title])
    figure = plt.Figure(figsize=(5, 4), dpi=100)
    ax = figure.add_subplot(111)
    ax.set_title(title)
    bar = FigureCanvasTkAgg(figure, root)
    bar = bar.get_tk_widget()
    bar.grid(row=4, column=1)
    df = data_frame[[key_title, value_title]].groupby(key_title).sum()
    df.plot(kind='bar', legend=True, ax=ax)
    return bar


def plot_line_graph(data_length):
    lists = sorted(data_length.items())
    line_graphs = []
    protocols, data_lengths = zip(*lists)
    i = 0
    while i < len(data_lengths):
        r = random.random()
        b = random.random()
        g = random.random()
        color = (r, g, b)
        figure = plt.Figure(figsize=(4, 5), dpi=100)
        ax = figure.add_subplot(111)
        ax.set_title("Lengths of packets in " + protocols[i] + " protocol")
        line = FigureCanvasTkAgg(figure, root)
        line = line.get_tk_widget()
        line.grid(row=5, column=i)
        line_graphs.append(line)
        data = {'Indices': range(0, len(data_lengths[i])), 'Data lengths': data_lengths[i]}
        data_frame = DataFrame(data, columns=['Indices', 'Data lengths'])
        data_frame = data_frame[['Indices', 'Data lengths']].groupby('Indices').sum()
        data_frame.plot(kind='line', legend=True, ax=ax, color=color)
        i += 1
    return line_graphs


class GuiPart:
    def __init__(self, master, start_command, end_command):
        self.tcp = tk.IntVar()
        self.udp = tk.IntVar()
        self.icmp = tk.IntVar()

        cbx_tcp = tk.Checkbutton(master, text="TCP", variable=self.tcp)
        cbx_udp = tk.Checkbutton(master, text="UDP", variable=self.udp)
        cbx_icmp = tk.Checkbutton(master, text="ICMP", variable=self.icmp)

        cbx_tcp.select()
        cbx_udp.select()
        cbx_icmp.select()

        cbx_tcp.grid(row=1, column=0)
        cbx_udp.grid(row=1, column=1)
        cbx_icmp.grid(row=1, column=2)

        tk.Label(master, text="Source IP").grid(row=2, column=0, sticky="W", padx=5)
        self.src_ip = tk.Entry(master)
        self.src_ip.grid(row=2, column=1, sticky="W", padx=5)

        tk.Label(master, text="Destination IP").grid(row=2, column=2, sticky="W", padx=5)
        self.destination_ip = tk.Entry(master)
        self.destination_ip.grid(row=2, column=3, sticky="W", padx=5)

        self.start = tk.Button(master, text='Start Sniffing', command=start_command)
        self.stop = tk.Button(master, text='Stop Sniffing', command=end_command)
        self.start.grid(row=3, column=1, columnspan=2, pady=2)


class ThreadedClient:
    running = None
    protocols = None
    data_length = None

    bar_graph = None
    line_graphs = []

    def __init__(self, master):
        self.master = master
        self.gui = GuiPart(master, self.start_application,
                           self.stop_sniffing)

    def start_application(self):
        self.running = 1
        self.protocols = {"TCP": 0, "UDP": 0, "ICMP": 0}
        self.data_length = defaultdict(list)
        self.gui.src_ip_count = 0
        self.gui.destination_ip_count = 0

        sniffing_thread = threading.Thread(target=self.sniff_all,
                                           kwargs=dict(sniff_tcp=self.gui.tcp.get(), sniff_udp=self.gui.udp.get(),
                                                       sniff_icmp=self.gui.icmp.get(), src_ip=self.gui.src_ip.get(),
                                                       destination_ip=self.gui.destination_ip.get()))
        self.gui.start.grid_forget()
        self.gui.stop.grid(row=3, column=1, columnspan=2, pady=2)
        if self.bar_graph is not None:
            self.bar_graph.grid_forget()

        i = 0
        while i < len(self.line_graphs):
            self.line_graphs[i].grid_forget()
            i += 1

        sniffing_thread.start()

    def sniff_all(self, sniff_tcp, sniff_udp, sniff_icmp, src_ip, destination_ip):
        print("Connecting socket...")
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.ntohs(constants.ETH_P_ALL))
        except socket.error as msg:
            print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()

        s.setblocking(False)

        inputs = [s]
        outputs = []
        print("Sniffing started!")
        while self.running:
            readable, writable, exceptional = select.select(inputs, outputs, inputs)
            for sock in readable:
                packet = sock.recv(65565)
                if packet:
                    eth_header = packet[:ETH_LENGTH]
                    eth = unpack(constants.ETH_HEADER_FORMAT, eth_header)
                    eth_protocol = socket.ntohs(eth[2])

                    if eth_protocol == constants.EXTERIOR_GATEWAY_PROTOCOL:
                        ip_header = packet[ETH_LENGTH:20 + ETH_LENGTH]
                        iph = unpack(constants.IP_HEADER_FORMAT, ip_header)

                        version_ihl = iph[0]
                        version = version_ihl >> 4
                        ihl = version_ihl & 0xF

                        iph_length = ihl * 4

                        ttl = iph[5]
                        protocol = iph[6]
                        s_address = socket.inet_ntoa(iph[8])
                        d_address = socket.inet_ntoa(iph[9])

                        print('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(
                                ttl) + ' Protocol : ' + constants.get_protocol_name(
                                protocol) + ' Source Address : ' + str(s_address) + ' Destination Address : ' + str(
                                d_address))

                        # TCP
                        if protocol == constants.TCP_PROTOCOL and sniff_tcp == 1 and (
                                src_ip == s_address or src_ip == "" or destination_ip == d_address
                                or destination_ip == ""):
                            self.protocols["TCP"] = self.protocols["TCP"] + 1
                            t = iph_length + ETH_LENGTH
                            tcp_header = packet[t:t + 20]

                            tcp_h = unpack(constants.TCP_HEADER_FORMAT, tcp_header)

                            source_port = tcp_h[0]
                            destination_port = tcp_h[1]
                            sequence = tcp_h[2]
                            acknowledgement = tcp_h[3]
                            doff_reserved = tcp_h[4]
                            tcp_h_length = doff_reserved >> 4

                            print('Source Port : ' + str(source_port) + ' Destination Port : ' + str(
                                    destination_port) + ' Sequence Number : ' + str(
                                    sequence) + ' Acknowledgement : ' + str(
                                    acknowledgement) + ' TCP header length : ' + str(
                                    tcp_h_length))

                            h_size = ETH_LENGTH + iph_length + tcp_h_length * 4
                            data_size = len(packet) - h_size
                            self.data_length["TCP"].append(data_size)
                            data = packet[h_size:]

                            print('Data : ' + str(data))

                        # ICMP
                        elif protocol == constants.ICMP_PROTOCOL and sniff_icmp == 1 and (
                                src_ip == s_address or src_ip == "" or destination_ip == d_address
                                or destination_ip == ""):
                            self.protocols["ICMP"] = self.protocols["ICMP"] + 1
                            u = iph_length + ETH_LENGTH
                            icmp_header_length = 4
                            icmp_header = packet[u:u + 4]
                            icmp_h = unpack(constants.ICMP_HEADER_FORMAT, icmp_header)

                            icmp_type = icmp_h[0]
                            code = icmp_h[1]
                            checksum = icmp_h[2]

                            print('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(
                                    checksum))

                            h_size = ETH_LENGTH + iph_length + icmp_header_length
                            data_size = len(packet) - h_size
                            self.data_length["ICMP"].append(data_size)
                            data = packet[h_size:]

                            print('Data : ' + str(data))

                        # UDP
                        elif protocol == constants.UDP_PROTOCOL and sniff_udp == 1 and (
                                src_ip == s_address or src_ip == "" or destination_ip == d_address
                                or destination_ip == ""):
                            self.protocols["UDP"] = self.protocols["UDP"] + 1
                            u = iph_length + ETH_LENGTH
                            udp_header_length = 8
                            udp_header = packet[u:u + 8]

                            udp_h = unpack(constants.UDP_HEADER_FORMAT, udp_header)

                            source_port = udp_h[0]
                            destination_port = udp_h[1]
                            length = udp_h[2]
                            checksum = udp_h[3]

                            print('Source Port : ' + str(source_port) + ' Destination Port : ' + str(
                                    destination_port) + ' Length : ' + str(
                                    length) + ' Checksum : ' + str(checksum))

                            h_size = ETH_LENGTH + iph_length + udp_header_length
                            data_size = len(packet) - h_size
                            self.data_length["UDP"].append(data_size)
                            data = packet[h_size:]

                            print('Data : ' + str(data))

                    else:
                        print("Sniffing Stopped!")

    def stop_sniffing(self):
        self.running = 0
        self.gui.stop.grid_forget()
        self.gui.start.grid(row=3, column=1, columnspan=2, pady=2)
        self.bar_graph = plot_bar_graph(self.protocols, "Protocols", "Occurrences", "Protocol Occurrences")
        self.line_graphs = plot_line_graph(self.data_length)


root = tk.Tk()
root.title("Apply filters and start sniffing!")
client = ThreadedClient(root)
root.mainloop()
