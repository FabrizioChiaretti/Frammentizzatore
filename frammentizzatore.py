from scapy.all import IPv6, IPv6ExtHdrFragment,  TCP, UDP, ICMPv6EchoRequest, raw, Packet
from random import getrandbits
from scapy.config import conf


class frammentizzatore:
    
    def __init__(self, logs_handler, input_handler, max_fragment_lenght = 1280, min_payload_lenght = 8):
        
        self.max_fragment_lenght = max_fragment_lenght
        self.min_payload_lenght = min_payload_lenght
        self.logs_handler = logs_handler  
        self.input_handler = input_handler       
    
    
    def headerCheck(self, packet):
        
        if self.input_handler.fragmentSize > self.max_fragment_lenght:
            self.logs_handler.logger.error("The maximum fragment size is %d", self.max_fragment_lenght)
            return False
        
        if IPv6ExtHdrFragment in packet:
            self.logs_handler.logger.error("IPv6ExtHdrFragment already present")
            return False
        
        if IPv6 not in packet:
            self.logs_handler.logger.error("Can not found IPv6 header")
            return False
        
        return True
    
    
    def checksum_computation(self, basic_header, fragments):
        
        tmp = fragments.copy()
        segments = []
        while len(tmp) > 0:
            min_pos = 0
            min_offset = tmp[0][IPv6ExtHdrFragment].offset
            for p in tmp:
                cur_offset = p[IPv6ExtHdrFragment].offset
                if cur_offset < min_offset:
                    min_pos = 0
                    min_offset = cur_offset
                    
            pkt = IPv6(tmp[min_pos])
            fragment_header = pkt[IPv6ExtHdrFragment].copy()
            new_pkt = fragment_header.copy()
            del new_pkt[IPv6ExtHdrFragment].payload
            nh = fragment_header.nh
            fragment_payload = fragment_header.payload
            while nh not in [59, 58, 6, 17] and len(fragment_payload > 0):
                nh = fragment_payload.nh
                fragment_payload =  fragment_payload.payload
            
            new_pkt = new_pkt / fragment_payload.copy()
            segments.append(new_pkt)
            #self.logs_handler.logger.info("////////////////////////////")
            #new_pkt.show()
            del tmp[min_pos]
        
        final_packets = []
        final_packets.append(basic_header)
        upper_layer_header = None
        protocol = None
        j = 0
        for frag in segments:
            if TCP in frag:
                upper_layer_header = j
                protocol = 6
            if UDP in frag:
                upper_layer_header = j
                protocol = 17
            if ICMPv6EchoRequest in frag: 
                upper_layer_header = j
                protocol = 58
            j+=1
        
        if protocol == None:
            self.logs_handler.logger.error("Can not find upper layer protocol, can not compute upper layer checksum")
            return fragments
        
        if upper_layer_header == None:
            self.logs_handler.logger.error("Can not find upper layer header, can not compute upper layer checksum")
            return fragments
        
        i = 0
        for frag in segments:
            #frag.show()
            fragment_header = frag[IPv6ExtHdrFragment]
            fragment_payload = fragment_header.payload
            #fragment_payload.show()
            fragment_raw_payload = raw(fragment_payload)
            first_byte_index = fragment_header.offset * 8
            #last_byte_index = len(fragment_raw_payload) + first_byte_index
            #self.logs_handler.logger.info("len = %d, offset = %d", pkt_len, first_byte_index)
            if len(fragment_raw_payload) > 0:
                j = 0
                while j < len(final_packets):
                    pkt = final_packets[j]
                    final_payload_len = len(pkt.payload)
                    #pkt.payload.show()
                    if first_byte_index == final_payload_len:
                        new_pkt = pkt.copy()
                        new_pkt = new_pkt / conf.raw_layer(load=fragment_raw_payload)
                        final_packets.append(new_pkt) 
                        if i+1 < len(segments): 
                            subsequent_fragment = segments[i+1] 
                            subsequent_fragment_offset = subsequent_fragment[IPv6ExtHdrFragment].offset * 8
                            if subsequent_fragment_offset != final_payload_len:
                                final_packets.remove(pkt)
                                j-=1
                        else:
                            final_packets.remove(pkt)
                            j-=1
                    j+=1
                        
            i+=1
        
        final_packets[0].plen = len(raw(final_packets[0].payload))
        #self.logs_handler.logger.info("len = %d", len(final_packets))
        #for packet in final_packets:
            #packet.plen = len(raw(packet.payload))
            #packet.show()
        
        #return final_packets    
        return final_packets[0], protocol, upper_layer_header
    
    
    def fragmentation(self, packet):
        
        res = None
        if self.input_handler.type == "regular":
            res = self.fragment(packet, self.input_handler.fragmentSize)
        elif self.input_handler.type == "overlapping":
            res = self.overlapping_fragmentation(packet)
        return res
    
    
    def overlapping_fragmentation(self, input_packet):
        
        packet = IPv6(input_packet.get_payload())
        #packet.show()
        #self.logs_handler.logger.debug("/////////////////// original packet")
        
        tmp = self.headerCheck(packet)
        if tmp == False:
            return None
        
        # take the basic header
        basic_header = packet.copy()
        basic_header.remove_payload()
        
        first_fragment = basic_header.copy()
        headers_to_skip = [0,60,43] # Hop-by-Hop Options, Destination Options, Routing Header
        i = 0
        
        while (int(packet[i].nh) in headers_to_skip):
            first_fragment = first_fragment / packet[i+1]
            i +=1
        
        input_payload = packet[i].payload.copy()
        next_header_chain = [] # header chain placed after the fragment header IPv6ExtHdrDestOpt(nh = 58, len = len(raw(IPv6ExtHdrDestOpt())))
        j = i
        while (packet[j].nh not in [59, 6, 17, 58]): # no next header, udp, tcp, icmpv6
            input_payload[j].remove_payload()
            next_header_chain.append(input_payload[j])
            input_payload = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6 or int(packet[j].nh) == 17: # udp or tcp
            #input_payload[j].show()
            input_payload[j].remove_payload()
            next_header_chain.append(input_payload[j])
        
        if int(packet[j].nh) == 58:
            del input_payload[j].data
            next_header_chain.append(input_payload[j])
            
        #for h in next_header_chain:
        #    h.show()
        input_payload =  packet[i].payload.copy() # payload coming next to the fragment header
        #input_payload.show()
        first_fragment[i].nh = 44 # netx header = fragment header
        packet_id = getrandbits(32)
        UnfragPart = first_fragment.copy()
        UnfragPartLen = len(raw(UnfragPart))
        #UnfragPart.show()
        first_fragment = first_fragment / IPv6ExtHdrFragment(id = packet_id)  
        #first_fragment.show()
        fragHeader = first_fragment[IPv6ExtHdrFragment].copy()
        fragPartLen = len(raw(input_payload)) # len of the payload to fragment
        fragPartStr = raw(input_payload.copy())
        #self.logs_handler.logger.info("UnfragPartLen %d, FragHeaderLen %d, fragPartLen %d", \
        #    UnfragPartLen, FragHeaderLen, fragPartLen)
        
        res = [] 
        j = 0
        nh = packet[i].nh
        fragments = self.input_handler.fragments
        for frag in fragments:
            fragment_offset = frag["FO"]
            last_byte = frag["PayloadLenght"] + fragment_offset if frag["PayloadLenght"] >= 0 else len(input_payload)
            hop_limit = frag["HopLimit"]
            if (fragPartLen >= last_byte):
                #self.logs_handler.logger.debug("last byte %d, fragment offset %d", last_byte, fragment_offset)
                raw_payload = fragPartStr[fragment_offset:last_byte]
                #self.logs_handler.logger.debug("len raw payload %d", len(raw_payload))
                #payload = input_payload[fragment_offset:last_byte]
                #payload.show()
                if len(raw_payload) > 0 and len(next_header_chain) > 0:
                    #payload.show()
                    fragHeader.nh = nh
                    raw_payload_len = len(raw_payload) 
                    while nh not in [59, 6, 17, 58] and raw_payload_len > 0:
                        header = next_header_chain.pop(0)
                        if raw_payload_len < len(raw(header)):
                            self.logs_handler.logger.error("Something goes wrong while creating fragment %d, payload lenght should be at least %d bytes higher", j+1, len(raw(header)) - raw_payload_len)
                            return None

                        raw_payload_len -= len(raw(header))
                        nh = header.nh
                        
                    if nh in [59, 6, 17, 58] and len(next_header_chain) > 0:
                        header = next_header_chain.pop(0)
                        if raw_payload_len < len(raw(header)):
                            self.logs_handler.logger.error("Something goes wrong while creating fragment %d, payload lenght should be at least %d bytes higher", j+1, len(raw(header))-raw_payload_len)   
                            return None
                        
                else:
                    fragHeader.nh = 59 # no next header
                
                fragHeader.offset = fragment_offset // 8
                fragHeader.m = frag["M"]
                #if j > 0:
                #    fragHeader.nh = 58 # no next header for all segments except the first
                segment = UnfragPart / fragHeader / raw_payload
                segment.plen = len(raw(segment.payload))
                
                if hop_limit >= 0:
                    segment.hlim = hop_limit
                
                if len(raw(segment)) > self.max_fragment_lenght:
                    self.logs_handler.logger.error("The lenght of the fragment %d is greater than the maximum fragment lenght (1280)", j+1)
                    return None
                
                res.append(segment)
                #self.logs_handler.logger.debug("######################## segment %d", j+1)
                #segment.show()
            else: # something goes wrong
                self.logs_handler.logger.error("Something goes wrong while creating fragment %d, check payload lenght and fragment offset inserted", j+1)
                return None
            
            j+=1
        
        #for frag in res:
        #    frag.show()
        
        #orginal_packet = self.checksum_computation(basic_header, res)
        original_packet, protocol, upper_layer_header = self.checksum_computation(basic_header, res)  
        #out = self.checksum_computation(basic_header, res)  
        #return original_packet
        #packet.show()
        #upper_layer_header.show()
        #original_packet.show()
        input_packet.set_payload(bytes(original_packet))
        original_packet = IPv6(input_packet.get_payload())
        if protocol == 58:
            #upper_layer_header.cksum = 0
            del original_packet[ICMPv6EchoRequest].cksum
            input_packet.set_payload(bytes(original_packet))
            original_packet = IPv6(input_packet.get_payload())
            frag = res[upper_layer_header]
            input_packet.set_payload(bytes(frag))
            frag = IPv6(input_packet.get_payload())
            del frag[ICMPv6EchoRequest].cksum
            frag[ICMPv6EchoRequest].cksum = original_packet[ICMPv6EchoRequest].cksum
            res[upper_layer_header] = frag
            #res[upper_layer_header].show()
            
        if protocol == 6:
            del original_packet[TCP].chksum
            input_packet.set_payload(bytes(original_packet))
            original_packet = IPv6(input_packet.get_payload())
            frag = res[upper_layer_header]
            input_packet.set_payload(bytes(frag))
            frag = IPv6(input_packet.get_payload())
            del frag[TCP].chksum
            frag[TCP].chksum = original_packet[TCP].chksum
            res[upper_layer_header] = frag
            #res[upper_layer_header].show()
            #frag.show()
        
        if protocol == 17:
            del original_packet[UDP].chksum
            input_packet.set_payload(bytes(original_packet))
            original_packet = IPv6(input_packet.get_payload())
            frag = res[upper_layer_header]
            input_packet.set_payload(bytes(frag))
            frag = IPv6(input_packet.get_payload())
            del frag[UDP].chksum
            frag[UDP].chksum = original_packet[UDP].chksum
            res[upper_layer_header] = frag
            #res[upper_layer_header].show()
            #frag.show()
        
        self.logs_handler.logger.info("Fragmentation ends, returning %d fragments", len(res))
        #original_packet.show()
        #for frag in res:
        #    input_packet.set_payload(bytes(frag))
        #    frag = IPv6(input_packet.get_payload())
        #    frag.show()
        
        return res #[original_packet]
    
    
    def fragment(self, input_packet, fragment_size = 1280):
        
        packet = IPv6(input_packet.get_payload())
        packet.show()
        
        tmp = self.headerCheck(packet)
        if tmp == False:
            return None
        
        # take the basic header
        basic_header = packet.copy()
        basic_header.remove_payload()
        #basic_header.show()
        
        first_fragment = basic_header.copy()
        headers_to_skip = [0,60,43] # Hop-by-Hop Options, Destination Options, Routing Header
        i = 0
        
        while (int(packet[i].nh) in headers_to_skip):
            first_fragment = first_fragment / packet[i+1]
            i +=1
            
        first_fragment[i].nh = 44 # next header = fragment header
        packet_id = getrandbits(32)
        
        first_fragment = first_fragment / IPv6ExtHdrFragment(nh = packet[i].nh, m=1, id = packet_id)
        #first_fragment.show()
        fragHeader = first_fragment[IPv6ExtHdrFragment].copy()
        FragHeaderLen = len(raw(first_fragment[IPv6ExtHdrFragment]))
        #fragHeader.show()
        
        input_payload = packet[i].payload.copy() # fragmentable part
        payload_check = packet[i].payload.copy() # packet[i+1].payload.show()
        #payload_check.show()
        next_header_chain_lenght = 0        
        j = i     
        #packet[j].show()   
        while (packet[j].nh not in [59, 6, 17, 58]): # no next header, udp, tcp, icmpv6
            payload_check[j].remove_payload()
            next_header_chain_lenght += len(raw(payload_check[j]))
            payload_check = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6 or int(packet[j].nh) == 17: # udp or tcp
            payload_check[j].remove_payload()
            next_header_chain_lenght += len(raw(payload_check[j]))
        
        if int(packet[j].nh) == 58:
            del payload_check[j].data
            next_header_chain_lenght += len(raw(payload_check[j]))
        
        first_fragment = first_fragment / input_payload
        first_fragment.plen = len(raw(first_fragment.payload))
        #print(first_fragment.plen)
        #print(len(raw(first_fragment)), len(raw(packet)))
        #print(len(raw(first_fragment.payload)), packet.plen)
        #first_fragment.show()
        
        if len(raw(first_fragment)) <= fragment_size:
            self.logs_handler.logger.warning("Input fragment size is greater or equal to the first fragment size")
            first_fragment[IPv6ExtHdrFragment].m = 0
            self.logs_handler.logger.info("Fragmentation ends, returning one fragment")
            return [first_fragment]
        
        ##### num_of_fragments > 1 #####
        fragPart_len = len(raw(first_fragment[IPv6ExtHdrFragment].payload)) # len of the payload to fragment
        #if fragPart_len < self.min_payload_lenght:
            #return [first_fragment]
        
        fragPartStr = raw(first_fragment[IPv6ExtHdrFragment].payload)
        UnfragPartLen = len(raw(first_fragment)) - fragPart_len - FragHeaderLen 
        UnfragPart = first_fragment.copy()
        del UnfragPart[IPv6ExtHdrFragment].underlayer.payload # take the part of the packet before the IPv6ExtHdrFragment
        #UnfragPart.show()
        
        if (fragment_size -FragHeaderLen -UnfragPartLen) % 8 != 0:
            self.logs_handler.logger.error("Fragment size not valid, it must be a multiple of 8-octets")
            return None
        
        if fragment_size < FragHeaderLen + UnfragPartLen + next_header_chain_lenght:
            self.logs_handler.logger.error("Fragment size not valid, it must be at least %d and a multiple of 8-octets", FragHeaderLen + UnfragPartLen + next_header_chain_lenght)
            return None
    
        innerFragSize = fragment_size -FragHeaderLen -UnfragPartLen
        
        remain = fragPartStr
        res = []
        fragOffset = 0 
        j = 0
        
        while True:
            if (len(remain) > innerFragSize):
                tmp = remain[:innerFragSize]
                remain = remain[innerFragSize:]
                fragHeader.offset = fragOffset    
                fragOffset += (innerFragSize // 8)  
                if j > 0:
                    fragHeader.nh = 59 # 59 = No next header
                segment = UnfragPart / fragHeader / conf.raw_layer(load=tmp)
                segment.plen = len(raw(segment.payload))
                res.append(segment)
                #segment.show()
                j+=1
            else: # last fragment
                fragHeader.offset = fragOffset   
                fragHeader.m = 0
                fragHeader.nh = 59 # 59 = No next header
                segment = UnfragPart / fragHeader / conf.raw_layer(load=remain)
                segment.plen = len(raw(segment.payload))
                res.append(segment)
                #segment.show()
                break
            
        self.logs_handler.logger.info("Fragmentation ends, returning %d fragments", len(res))
        return res
        
        
          