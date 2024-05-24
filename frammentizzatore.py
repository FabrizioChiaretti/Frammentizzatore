from scapy.all import IPv6, IPv6ExtHdrFragment, raw
from random import getrandbits

class frammentizzatore:
    
    def __init__(self, max_fragment_lenght = 1280):
        self.max_fragment_leght = max_fragment_lenght
    
    
    def fragment(self, input_packet, num_of_fragments):
        
        packet = IPv6(input_packet.get_payload())
        
        if IPv6ExtHdrFragment in packet:
            print("IPv6ExtHdrFragment already present")
            return packet
        if IPv6 not in packet:
            print("Can not found IP header")
            return packet
        
        basic_header = packet.copy()
        basic_header.remove_payload()
        
        first_fragment = basic_header.copy()
        headers_to_skip = [0,60,43] # Hop-by-Hop Options, Destination Options, Routing Header
        i = 0
        
        while (int(packet[i].nh) in headers_to_skip):
            first_fragment = first_fragment / packet[i+1]
            i +=1
            continue
        
        first_fragment[i].nh = 44
        random_value = getrandbits(32)
        first_fragment = first_fragment / IPv6ExtHdrFragment(nh = packet[i].nh, m=1, id = random_value)
        #first_fragment.show()
        
        input_payload = packet[i].payload.copy() # fragmentable part
        #input_payload.show()
        
        first_fragment = first_fragment / input_payload
        first_fragment.plen = len(raw(first_fragment.payload))
        #first_fragment.show()
        
        
        
        
        return first_fragment