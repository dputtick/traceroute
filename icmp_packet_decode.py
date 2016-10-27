import binascii
import struct


def ones_comp_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


packet1 = b'4500240033370000400123150a0000010a0010790b00bdaf0000000045001c008c7c0000011164bf0a001079acd90144c8fd829a0008ebaf'
packet2 = b'45c0240048a60000fe0121bdcffb672d0a0010790b00da600000000045001c0081df000001116f5c0a001079acd90144c586829a0008d275'
packet3 = b'4500240000000000fd013ca9c620a0820a0010790b00da600000000045001c00d0ce00000111206d0a001079acd90144f25b829a0008a5a0'
packet4 = b'4500240000000000fc01da43d155f8b20a0010790b00da600000000045801c00f3b400000111fd060a001079acd90144d658829a0008c1a3'
packet5 = b'45c024009f520000fb013e2ed155f5b50a0010790b00da600000000045801c00707d00000111803e0a001079acd90144c4db829a0008d320'

packet1_header_altered = b'4500240033370000400100000a0000010a001079'
packet1_header_orig = b'4500003833370000400100000a0000010a001079'


def checksum(header):
    ip_header = bytearray(header)
    ip_word_list = [int(bytearray(reversed(ip_header[i:i+2])), base=16) 
                    for i in range(0, len(ip_header), 2)]
    checksum = 0
    for word in ip_word_list:
        checksum = ones_comp_add(checksum, word)
    checksum = (~checksum) & 0xffff
    print(hex(checksum))

checksum(packet1_header_altered)
checksum(packet1_header_orig)

#print(hex(ones_comp_add(0xffff, 0x1050)))
