#!/usr/bin/env python3
import binascii
import netifaces

from scapy.all import *
from socket import gethostname

conf.checkIPaddr=False

# obtain interface info
def net_info():
    netinfo = []
    for iface in netifaces.interfaces():
        addresses = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addresses.keys():
            for link in addresses[netifaces.AF_INET]:
                if 'addr' in link.keys() and 'peer' not in link.keys():
                    netinfo.append({
                        'addr': link['addr'],
                        'netmask': link['netmask'],
                        'broadcast': link['broadcast'],
                        'localiface': iface,
                        'hwaddr': get_if_hwaddr(iface),
                        'hwaddrraw': binascii.unhexlify(
                            get_if_hwaddr(iface).replace(':','')),
                        'hostname': gethostname()
                    })
    return netinfo

# craft DHCP DISCOVER
def craft_dhcp_discover(netinfo):
    ether = Ether(src=netinfo['hwaddr'], dst='ff:ff:ff:ff:ff:ff:ff')
    ip = IP(src='0.0.0.0', dst='255.255.255.255')
    udp = UDP(dport=67, sport=68)
    bootp = BOOTP(chaddr=netinfo['hwaddrraw'], xid=RandInt())
    dhcp = DHCP(options=[('message-type', 'discover'), 'end'])
    packet = ether/ip/udp/bootp/dhcp
    print(packet.display())
    return packet

# send DHCP DISCOVER, wait for reply
def send_dhcp_discover(netinfo):
    dhcp_offer = srp1(craft_dhcp_discover(netinfo), iface=netinfo['localiface'])
    print(dhcp_offer.show())

def main():
    netinfo = net_info()[0]
    print(netinfo)
    send_dhcp_discover(netinfo)

main()
