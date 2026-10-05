#!/usr/bin/env python3

import socket
import ipaddress
import uuid

# send-lldp.py: send LLDP packet on an interface
#  requires: Linux, Python >= 3.12


OUTGOING_INTERFACE_NAME = 'ens5'


LLDP_DST_MAC_ADDR = b'\x01\x80\xc2\x00\x00\x0e'
LLDP_ETHERTYPE = b'\x88\xcc'


def build_tlv(type_, value):
    if type_ < 0 or type_ > 127:
        raise ValueError(f"type out of range: {type_}")
    if not isinstance(value, bytes):
        raise ValueError(f"value is not bytes")
    length = len(value)
    if length > 511:
        raise ValueError(f"length out of range: {length}")
    type_and_length = (type_ << 9) + length
    return bytes([
        *type_and_length.to_bytes(2, byteorder='big'),
        *value,
    ])


def main():
    src_mac_addr = uuid.getnode().to_bytes(6, byteorder='big')

    port_id = OUTGOING_INTERFACE_NAME
    ttl = 120
    system_name = 'send.lldp.test.example'
    system_description = 'TEST description of this_system TEST'
    software_revision = 'TEST some software, version 09.12_16 (stable) rel. 10-1 TEST'
    model_name = 'TEST some cool hardware TEST'

    lldp_frame = bytes([
        # subtype 0x04 = MAC address
        *build_tlv(0x01, b'\x04' + src_mac_addr),
        # subtype 0x05 = port ID
        *build_tlv(0x02, b'\x05' + port_id.encode('US-ASCII')),
        *build_tlv(0x03, ttl.to_bytes(2, byteorder='big')),
        *build_tlv(0x04, f"Description of {port_id} (test)".encode('US-ASCII')),
        *build_tlv(0x05, system_name.encode('US-ASCII')),
        *build_tlv(0x06, system_description.encode('US-ASCII')),
        *build_tlv(0x07, b'\x03\x14\x01\x14'),
        *build_tlv(0x7f, b'\x00\x80\xc2' + b'\x01' + b'\x00\x01'),
        *build_tlv(0x7f, b'\x00\x12\xbb' + b'\x01' + b'\x00\x21\x04'),
        *build_tlv(0x7f, b'\x00\x12\xbb' + b'\x07' + software_revision.encode('US-ASCII')),
        *build_tlv(0x7f, b'\x00\x12\xbb' + b'\x0a' + model_name.encode('US-ASCII')),
        0x00, 0x00
    ])
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETH_P_ALL)) as raw_sock:
        raw_sock.bind((OUTGOING_INTERFACE_NAME, 0))
        raw_sock.sendall(LLDP_DST_MAC_ADDR + src_mac_addr + LLDP_ETHERTYPE + lldp_frame)


if __name__ == '__main__':
    main()

