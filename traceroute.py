import sys
import socket as s
import binascii


def compose_IP_info(hostname):
    host_ip = s.getaddrinfo(host=hostname,
                            port=33434,
                            family=s.AF_INET,
                            type=0,
                            proto=s.IPPROTO_TCP,
                            flags=0)
    return host_ip[0][-1]


def output_printer(curr_addr, ttl):
    print(ttl, end='\t')
    try:
        curr_name = s.gethostbyaddr(curr_addr)
        print(curr_name)
    except s.error:
        if curr_addr:
            print(curr_addr)


def decode_packet(packet_data_list):
    packet_data_hex = [binascii.hexlify(packet) for packet in packet_data_list]
    print(len(packet_data_hex))
    for packet in packet_data_hex:
        print(packet)


def main(destination_hostname):
    # resolve hostname to IP
    dest_ip, port = compose_IP_info(destination_hostname)
    # get the values for the protocols we want to use
    icmp_info = s.getprotobyname('icmp')
    udp_info = s.getprotobyname('udp')
    # initialize the time to live to 1, which we will then increment
    ttl = 1
    MAX_HOPS = 5
    packet_data_list = []
    while True:
        # open the receiving socket, type is UDP using the ICMP protocol
        recv_socket = s.socket(s.AF_INET, s.SOCK_DGRAM, icmp_info)
        # open the sending socket, using UDP
        send_socket = s.socket(s.AF_INET, s.SOCK_DGRAM, udp_info)
        # configure the sending socket to use our time to live value
        send_socket.setsockopt(s.SOL_IP, s.IP_TTL, ttl)
        # allow reusing our receiving socket (don't think I need this)
        #recv_socket.setsockopt(s.SOL_IP, s.SO_REUSEADDR, 1)
        # open the socket connections
        recv_socket.bind((b"", port))
        send_socket.sendto(b"", (dest_ip, port))
        curr_addr = None
        try:
            packet_data, curr_addr = recv_socket.recvfrom(512)
            packet_length = len(packet_data)
            packet_data_list.append(packet_data)
            curr_addr = curr_addr[0]
        except s.error:
            pass
        finally:
            recv_socket.close()
            send_socket.close()
        # print data
        output_printer(curr_addr, ttl)

        # increment time to live by 1
        ttl += 1

        # break if finished
        if curr_addr == dest_ip or ttl > MAX_HOPS:
            break
    decode_packet(packet_data_list)


if __name__ == '__main__':
    destination_hostname = sys.argv[1]
    main(destination_hostname)
