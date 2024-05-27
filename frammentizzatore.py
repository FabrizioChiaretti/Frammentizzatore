from scapy.all import IPv6, IPv6ExtHdrFragment, raw
from random import getrandbits
from scapy.config import conf

class frammentizzatore:
    
    def __init__(self, max_fragment_lenght = 1280):
        self.max_fragment_leght = max_fragment_lenght
    
    
    def fragment(self, input_packet, input_num_of_fragments = 1, fragment_size = 1280):
        
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
        
        first_fragment[i].nh = 44 # netx header = fragment header
        packet_id = getrandbits(32)
        
        first_fragment = first_fragment / IPv6ExtHdrFragment(nh = packet[i].nh, m=1, id = packet_id)
        fragHeader = first_fragment[IPv6ExtHdrFragment].copy()
        del fragHeader.payload
        
        input_payload = packet[i].payload.copy() # fragmentable part
        #input_payload.show()
        
        first_fragment = first_fragment / input_payload
        first_fragment.plen = len(raw(first_fragment.payload))
        #first_fragment.show()
        
        if input_num_of_fragments == 1 or len(raw(first_fragment)) <= fragment_size:
            first_fragment[IPv6ExtHdrFragment].m = 0
            return first_fragment
        
        ##### num_of_fragments > 1 #####
        
        fragPart_len = len(raw(first_fragment[IPv6ExtHdrFragment].payload)) # len of the payload to fragment
        fragPartStr = raw(first_fragment[IPv6ExtHdrFragment].payload)
        UnfragPartLen = len(raw(first_fragment)) - fragPart_len - 8 # 8 = fragment header lenght
        UnfragPart = first_fragment.copy()
        del UnfragPart[IPv6ExtHdrFragment].underlayer.payload # take the part of the packet before the IPv6ExtHdrFragment
        #UnfragPart.show()
        
        if (fragment_size > self.max_fragment_leght) or (fragment_size -8 -UnfragPartLen) % 8 != 0:
            print("Invalid input fragment size")
            return packet
    
        innerFragSize = fragment_size -8 -UnfragPartLen
        
        remain = fragPartStr
        res = []
        fragOffset = 0 
        
        while True:
            if (len(remain) > innerFragSize):
                tmp = remain[:innerFragSize]
                remain = remain[innerFragSize:]
                fragHeader.offset = fragOffset    
                fragOffset += (innerFragSize // 8)  
                if IPv6 in UnfragPart:
                    UnfragPart[IPv6].plen = None
                segment = UnfragPart / fragHeader / conf.raw_layer(load=tmp)
                res.append(segment)
                #segment.show()
            else:
                fragHeader.offset = fragOffset    # update offSet
                fragHeader.m = 0
                if IPv6 in UnfragPart:
                    UnfragPart[IPv6].plen = None
                segment = UnfragPart / fragHeader / conf.raw_layer(load=remain)
                res.append(segment)
                #segment.show()
                break
        
        return res
        