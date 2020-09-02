TCP_PROTOCOL = 6
ICMP_PROTOCOL = 1
UDP_PROTOCOL = 17
EXTERIOR_GATEWAY_PROTOCOL = 8
ETH_P_ALL = 0x0003
ETH_P_EXTERIOR = 0X08
ETH_P_INTERIOR = 0x09


ETH_LENGTH = 14
# struct format
# ! - network
# H - unsigned short
# B - unsigned char
# s - char[]
# 4s - 4 chars
# L - unsigned long
ETH_HEADER_FORMAT = '!6s6sH'
IP_HEADER_FORMAT = '!BBHHHBBH4s4s'
TCP_HEADER_FORMAT = '!HHLLBBHHH'
ICMP_HEADER_FORMAT = '!BBH'
UDP_HEADER_FORMAT = '!HHHH'


def get_protocol_name(protocol):
    if protocol == TCP_PROTOCOL:
        return "TCP"
    if protocol == ICMP_PROTOCOL:
        return "ICMP"
    if protocol == UDP_PROTOCOL:
        return "UDP"
