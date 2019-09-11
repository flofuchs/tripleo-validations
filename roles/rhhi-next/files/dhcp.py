#!/usr/bin/env python
# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import fcntl
import random
import six
import socket
import struct
import sys
import threading
import time

ETH_P_IP = 0x0800
SIOCGIFHWADDR = 0x8927

dhcp_servers = []
interfaces_addresses = {}
transaction_id = None


def get_hw_address(interface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(),
                       SIOCGIFHWADDR,
                       struct.pack('256s', interface[:15].encode('utf-8')))
    s.close()
    return info[18:24]


def create_transaction_id():
    transaction_id = b''
    for i in range(4):
        transaction_id += struct.pack('!B', random.randint(0, 255)) 
    return transaction_id


def create_discover_payload(transaction_id, mac):
    packet = b''
    packet += b'\x01'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet (1)
    packet += b'\x06'   #Hardware address length: (6)
    packet += b'\x00'   #Hops: (0) 
    packet += transaction_id       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: (0)
    packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += mac
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  #Server host name not given
    packet += b'\x00' * 125 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x3d\x06' + mac
    packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\xff'   #End Option
    return packet


def read_offer_payload(data):
    return (
        '.'.join(["%s" % ord(x) for x in data[16:20]]),
        '.'.join(["%s" % ord(x) for x in data[245:249]])
    )


def wait_for_dhcp_offers(transaction_id, mac, timeout):
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Added to share port we bind  
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast

    end_of_time = time.time() + timeout
    try:
        dhcps.bind(('', 68))
    except Exception as e:
        print('Cannot bind to port 68 for some reason')
        dhcps.close()
        exit()

    dhcps.sendto(create_discover_payload(transaction_id, mac), ('<broadcast>', 67))
    dhcps.settimeout(timeout)

    try:
        while True:
            data = dhcps.recv(1024)
            if data[4:8] == transaction_id:
                offer_ip, dhcp_server = read_offer_payload(data)
                print("Offered IP Address: %s" % offer_ip)
                print("DHCP Server: %s" % dhcp_server)
                break
    except socket.timeout as e:
        print('Socket timed out with no response\n')
    dhcps.close()   
    exit()


def main():
    interface = sys.argv[1]
    timeout = 5

    mac = get_hw_address(interface)
    transaction_id = create_transaction_id()

    listening_thread = threading.Thread(target=wait_for_dhcp_offers,
                                        args=[transaction_id, mac, timeout])
    listening_thread.start()
    listening_thread.join()


if __name__ == '__main__':
    main()
