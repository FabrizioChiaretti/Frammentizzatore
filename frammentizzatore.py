from scapy.all import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, PadN, TCP, UDP, ICMPv6EchoRequest, raw, Packet
from random import getrandbits
from scapy.config import conf


class frammentizzatore:
    
    def __init__(self, logs_handler, input_handler, max_fragment_lenght = 1280):
        
        self.max_fragment_lenght = max_fragment_lenght
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
    
    
    def fragmentation(self, packet):  
        res = None
        if "regular" in self.input_handler.type:
            res = self.fragment(packet, self.input_handler.fragmentSize)
            if "headerchain" in self.input_handler.type:
                res = self.header_chain_processor(res)
        if "overlapping" in self.input_handler.type:
            res = self.overlapping_fragmentation(packet)
            if "headerchain" in self.input_handler.type:
                res = self.header_chain_processor(res)
        
        k = 0
        while k < len(res):
            self.logs_handler.logger.info("///////////////// FRAGMENT %d", k+1)
            res[k].show()
            k += 1
            
        return res
    
    
    def payload_defragment(self, basic_header, Ext_header_chain_len, fragments):
        
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
            return fragments, -1, -1
        
        if upper_layer_header == None:
            self.logs_handler.logger.error("Can not find upper layer header, can not compute upper layer checksum")
            return fragments, -1, -1
        
        i = 0
        #sequences = []
        for frag in segments:
            #frag.show()
            fragment_header = frag[IPv6ExtHdrFragment]
            fragment_payload = fragment_header.payload
            #fragment_payload.show()
            fragment_raw_payload = raw(fragment_payload)
            first_byte_index = (fragment_header.offset * 8) - Ext_header_chain_len
            #last_byte_index = len(fragment_raw_payload) + first_byte_index
            #self.logs_handler.logger.info("len = %d, offset = %d", pkt_len, first_byte_index)
            if len(fragment_raw_payload) > 0:
                j = 0
                while j < len(final_packets):
                    pkt = final_packets[j]
                    final_payload_len = len(pkt.payload)
                    #pkt.payload.show()
                    if first_byte_index >= final_payload_len:
                        new_pkt = pkt.copy()
                        new_pkt = new_pkt / conf.raw_layer(load=fragment_raw_payload)
                        final_packets.append(new_pkt) 
                        #sequences.append(i)
                        if i+1 < len(segments): 
                            subsequent_fragment = segments[i+1] 
                            subsequent_fragment_offset = (subsequent_fragment[IPv6ExtHdrFragment].offset * 8) - Ext_header_chain_len
                            if subsequent_fragment_offset != final_payload_len:
                                final_packets.remove(pkt)
                                j-=1
                        else:
                            final_packets.remove(pkt)
                            j-=1    
                            
                    j+=1
                        
            i+=1
        
        #self.logs_handler.logger.info("len = %d", len(final_packets))
        for packet in final_packets:
            packet.plen = len(raw(packet.payload))
            #packet.show()
        
        #print(sequences)
        #return final_packets    
        #self.logs_handler.logger.info("protocol %d, upper layer %d", protocol, upper_layer_header)
        return final_packets, protocol, upper_layer_header
    
    
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
        while (packet[j].nh not in [59, 6, 17, 58]): # no next header, udp, UDP, icmpv6
            input_payload[j].remove_payload()
            next_header_chain.append(input_payload[j])
            input_payload = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6 or int(packet[j].nh) == 17: # udp or UDP
            #input_payload[j].show()
            input_payload[j].remove_payload()
            next_header_chain.append(input_payload[j])
        
        if int(packet[j].nh) == 58:
            del input_payload[j].data
            next_header_chain.append(input_payload[j])
            
        #for h in next_header_chain:
            #h.show()
        Ext_header_chain_len = 0
        Ext_header_chain = next_header_chain.copy()
        Ext_header_chain.pop()
        for header in Ext_header_chain:
            Ext_header_chain_len += len(header)
        #self.logs_handler.logger.error("chain len %d", Ext_header_chain_len)   
        input_payload =  packet[i].payload.copy() # payload coming next to the fragment header
        #input_payload.show()
        first_fragment[i].nh = 44 # netx header = fragment header
        UnfragPart = first_fragment.copy()
        UnfragPartLen = len(raw(UnfragPart))
        #UnfragPart.show()
        first_fragment = first_fragment / IPv6ExtHdrFragment()  
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
        
        
        original_packets, protocol, upper_layer_header = self.payload_defragment(basic_header, Ext_header_chain_len, res)  
        if protocol == -1:
            return None
        
        final_segments = []
        if protocol == 58:
            i = 0
            while i < len(original_packets):    
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                #original_packets[i][ICMPv6EchoRequest].id = 0xffff
                #original_packets[i][ICMPv6EchoRequest].seq = 0xffff
                del original_packets[i][ICMPv6EchoRequest].cksum
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                frag = res[upper_layer_header]
                input_packet.set_payload(bytes(frag))
                frag = IPv6(input_packet.get_payload())
                #frag[ICMPv6EchoRequest].id = 0xffff
                #frag[ICMPv6EchoRequest].seq = 0xffff
                del frag[ICMPv6EchoRequest].cksum
                frag[ICMPv6EchoRequest].cksum = original_packets[i][ICMPv6EchoRequest].cksum
                res[upper_layer_header] = frag
                j = 0
                packet_id = getrandbits(32)
                while j < len(res):
                    input_packet.set_payload(bytes(res[j]))
                    res[j] = IPv6(input_packet.get_payload())
                    res[j][IPv6ExtHdrFragment].id = packet_id
                    j += 1
                final_segments = final_segments + res.copy()
                i+=1
            #final_segments[0].show()
            
        if protocol == 6:
            i = 0
            while i < len(original_packets):    
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                del original_packets[i][TCP].chksum
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                frag = res[upper_layer_header]
                input_packet.set_payload(bytes(frag))
                frag = IPv6(input_packet.get_payload())
                del frag[TCP].chksum
                frag[TCP].chksum = original_packets[i][TCP].chksum
                res[upper_layer_header] = frag
                j = 0
                packet_id = getrandbits(32)
                while j < len(res):
                    input_packet.set_payload(bytes(res[j]))
                    res[j] = IPv6(input_packet.get_payload())
                    res[j][IPv6ExtHdrFragment].id = packet_id
                    j += 1
                final_segments = final_segments + res.copy()
                i+=1
        
        if protocol == 17:
            i = 0
            while i < len(original_packets):    
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                del original_packets[i][UDP].chksum
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                frag = res[upper_layer_header]
                input_packet.set_payload(bytes(frag))
                frag = IPv6(input_packet.get_payload())
                del frag[UDP].chksum
                frag[UDP].chksum = original_packets[i][UDP].chksum
                res[upper_layer_header] = frag
                j = 0
                packet_id = getrandbits(32)
                while j < len(res):
                    input_packet.set_payload(bytes(res[j]))
                    res[j] = IPv6(input_packet.get_payload())
                    res[j][IPv6ExtHdrFragment].id = packet_id
                    j += 1
                final_segments = final_segments + res.copy()
                i+=1
        
        self.logs_handler.logger.info("Fragmentation ends, returning %d fragments", len(final_segments))
        #original_packet.show()
        #for frag in final_segments:
        #    frag.show()
        return final_segments 
    
    
    def fragment(self, input_packet, fragment_size = 1280):
        
        packet = IPv6(input_packet.get_payload())
        #packet.show()
        
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
        while (packet[j].nh not in [59, 6, 17, 58]): # no next header, udp, UDP, icmpv6
            payload_check[j].remove_payload()
            next_header_chain_lenght += len(raw(payload_check[j]))
            payload_check = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6 or int(packet[j].nh) == 17: # udp or UDP
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


    def _destination_header(self):
        opt = ""
        opt_len = len(opt)
        pad = PadN(otype=1, optlen=opt_len, optdata=opt)
        header = IPv6ExtHdrDestOpt(len=(2 + opt_len + 7) // 8 - 1, autopad=1, options=pad) # len=(2 + opt_len + 7) // 8 - 1
        #header.len = len(raw(header))
        #self.logs_handler.logger.info("destnation len %d", len(raw(header)))
        #header.show()
        return header


    def _hopByHop_header(self):
        opt = ""
        opt_len = len(opt)
        pad = PadN(otype=1, optlen=opt_len, optdata=opt) 
        header = IPv6ExtHdrHopByHop(len=(2 + opt_len + 7) // 8 - 1, autopad=1, options=pad) # len=(2 + opt_len + 7) // 8 - 1
        #header.len = len(raw(header))
        #self.logs_handler.logger.info("hop by hop len %d", len(raw(header)))
        #header.show()
        return header
        
        
    def _routing_header(self):
        header = IPv6ExtHdrRouting(len=(8 // 8 ) - 1, type=0, segleft=0, addresses=[])   #len=(8 // 8 ) - 1
        #header.len = len(raw(header))
        #self.logs_handler.logger.info("routing len %d", len(raw(header)))
        #header.show()
        return header
        
    
    def _extension_header_builder(self, packet, header):
        res = None

        if header == 0:
            if IPv6ExtHdrHopByHop in packet:
                res = packet[IPv6ExtHdrHopByHop].copy()
                del res.payload
            else:
                res = self._hopByHop_header()
                
        if header == 60:
            if IPv6ExtHdrDestOpt in packet:
                res = packet[IPv6ExtHdrDestOpt].copy()
                del res.payload
            else:
                res = self._destination_header()
                
        if header == 43:
            if IPv6ExtHdrRouting in packet:
                res = packet[IPv6ExtHdrRouting].copy()
                del res.payload
            else:
                res = self._routing_header()
        
        if header == 44:
            if IPv6ExtHdrFragment in packet:
                res = packet[IPv6ExtHdrFragment].copy()
                del res.payload
                
        #if header == 51:
        #    res = 51
        #if header == 50:
        #    res = 50
        #if header == 135:
        #    res = 135 
        
        if header == 58:
            if ICMPv6EchoRequest in packet:
                res = packet[ICMPv6EchoRequest].copy()
                del res.data
                
        if header == 6:
            if TCP in packet:
                res = packet[TCP].copy()
                del res.payload
                
        if header == 17:
            if UDP in packet:
                res = packet[UDP].copy()
                del res.payload

        return res
    
    
    def header_chain_processor(self, input_fragments):
        
        fragments_headerchain = self.input_handler.headerchain
        if len(fragments_headerchain) != len(input_fragments):
            self.logs_handler.logger.warning("Can not find all the header chain of the fragments")
            return input_fragments
        
        i = 0
        new_fragments = []
        while i < len(fragments_headerchain):
            headerchain = fragments_headerchain[i]
            if len(headerchain) > 0 and 44 not in headerchain:
                self.logs_handler.logger.error("Fragment header not found in the header chain of fragment %d", i+1)
                return input_fragments
            fragment = input_fragments[i]
            #fragPart.show()
            #unfragPart.show()
            
            new_fragment = fragment.copy()
            new_fragment.remove_payload() # new_fragment = basic header of the current fragment
            new_fragment.nh = 59
            #new_fragment.show()
            payload = fragment.copy() # payload of the current fragment
            k = 0
            while (int(payload.nh) not in [59, 6, 17, 58]): # no next header, udp, UDP, icmpv6
                #payload.show()
                payload = payload.payload
                k+=1
            
            #self.logs_handler.logger.error("////////////// FRAGMENT %d", i+1)
            #payload.show()
            
            if int(payload.nh) == 6: # tcp
                payload = payload[TCP].payload
        
            elif int(payload.nh) == 17: # udp
                payload = payload[TCP].payload
        
            elif int(payload.nh) == 58: # icmpv6
                payload = payload[ICMPv6EchoRequest]
            
            elif int(payload.nh) == 59: # no next header
                payload = payload.payload
                
            j = 0
            while j < len(headerchain):
                header = headerchain[j]
                if j == 0:
                    new_fragment.nh = header
                new_header = self._extension_header_builder(fragment, header)
                if header not in [58, 6, 17] and j+1 < len(headerchain):
                    new_header.nh = headerchain[j+1]
                if j == len(headerchain)-1 and (header not in [58, 6, 17]):
                    new_header.nh = 59
                     
                new_fragment = new_fragment / new_header
                j += 1
            
            if payload != None:
                new_fragment = new_fragment / payload
                
            new_fragment.plen = len(raw(new_fragment.payload))
            new_fragments.append(new_fragment)
            
            i += 1
            
        return new_fragments