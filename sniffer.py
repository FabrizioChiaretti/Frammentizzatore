
from log import log
from ipaddress import ip_address, IPv6Address 
from scapy.all import IPv6, sniff, wrpcap, ICMPv6EchoRequest, ICMPv6EchoReply


def main ():
    
    logs_handler = log("sniffer")
    logs_handler.logger.info("ICMPv6 sniffer started")
    
    interface = input("Capture interface: ")
    interface = interface.strip()
    
    icmpv6_type = 0
    while icmpv6_type != 1 and icmpv6_type != 2:
        icmpv6_type = input("Options:\n1: echo-request\n2: echo reply\n")
        icmpv6_type = int(icmpv6_type)
        if icmpv6_type != 1 and icmpv6_type != 2:
            logs_handler.logger.error("Invalid option")
            
    if icmpv6_type == 1:
        icmpv6_type = "icmp6[icmp6type]==icmp6-echo and icmp6[icmp6type]!=icmp6-echoreply"
    else:
        icmpv6_type = "icmp6[icmp6type]==icmp6-echoreply"
        
    ipv6_src = ""
    while ipv6_src == "":
        ipv6_src = input("IPv6 source address: ")
        try: 
            address = type(ip_address(ipv6_src)) is IPv6Address
        except ValueError: 
            logs_handler.logger.error("Invalid IPv6 address")
            ipv6_src = ""
    
    pcapFile = ""
    while pcapFile.strip() == "":
        pcapFile = input("Name of pcap file: ").strip()
    
    if ".pcap" not in pcapFile:
        pcapFile = pcapFile + ".pcap"
            
    filter_expr = "src " + ipv6_src + " and " + icmpv6_type
    logs_handler.logger.info("filter expression = %s", filter_expr)
    
    packets = (0,0)
    packets = sniff(iface=interface, filter=filter_expr)
    
    logs_handler.logger.info("Capture stopped")
    logs_handler.logger.info("Number of captured packets= %d", len(packets))
    
    pcapFile = "./pcaps/" + pcapFile
    wrpcap(pcapFile, packets)
    
    icmpv6_id = input("type icmpv6 echo id: ").strip()
    icmpv6_id = int(icmpv6_id)
    
    icmpv6_seq = input("type icmpv6 echo seq: ").strip()
    icmpv6_seq = int(icmpv6_seq)
    
    if icmpv6_id != "" and icmpv6_seq != "":
        counter = 0
        for packet in packets:
            if icmpv6_type == 1:
                if ICMPv6EchoRequest in packet and packet[ICMPv6EchoRequest].id == icmpv6_id \
                    and packet[ICMPv6EchoRequest].seq == icmpv6_seq:
                        counter += 1
            else:
                if ICMPv6EchoReply in packet and packet[ICMPv6EchoReply].id == icmpv6_id \
                    and packet[ICMPv6EchoReply].seq == icmpv6_seq:
                        counter += 1
        
        logs_handler.logger.info("number of icmpv6 packets with id %d and seq %d = %d", icmpv6_id, icmpv6_seq, counter)
        
if __name__ == "__main__":
    main()