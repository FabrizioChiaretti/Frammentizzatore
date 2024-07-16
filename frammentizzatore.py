from scapy.all import fuzz, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, AH, ESP, MIP6MH_BRR, PadN, TCP, UDP, ICMPv6EchoRequest, raw, Packet, in6_chksum
from random import getrandbits
from scapy.config import conf
from random import randint


class frammentizzatore:
    
    
    def __init__(self, logs_handler, input_handler, max_fragment_lenght = 1280):
        
        self.max_fragment_lenght = max_fragment_lenght
        self.logs_handler = logs_handler  
        self.input_handler = input_handler
        self.AH_seq = {}       
        self.ESP_seq = {}
    
    
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
                
        if "overlapping" in self.input_handler.type:
            res = self.overlapping_fragmentation(packet)
        
        if "headerchain" in self.input_handler.type:
                if "regular" not in self.input_handler.type and "overlapping" not in self.input_handler.type:
                    pkt = []
                    tmp = IPv6(packet.get_payload())
                    pkt.append([tmp])
                    hc = []
                    hc.append(self.input_handler.headerchain[0])
                    self.input_handler.headerchain = hc
                    #print(hc)
                    res = self.header_chain_processor(pkt)
                else:
                    res = self.header_chain_processor(res)
        
        if res != None:
            k = 0
            while k < len(res):
                i = 0
                while i < len(res[k]):
                    #del res[k][i].cksum
                    #packet.set_payload(bytes(res[k][i]))
                    #res[k][i] = IPv6(packet.get_payload())
                    self.logs_handler.logger.info("///////////////// FRAGMENT %d", i+1)
                    res[k][i].show()
                    i+=1
                k += 1
            
        return res
    
    
    def payload_defragment(self, basic_header, Ext_header_chain_len, fragments):
        
        i = 0
        segments = []
        while i < len(fragments):
            pkt = fragments[i]
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
            i += 1

        #for frag in segments:
        #    frag.show()
            
        final_packets = []
        final_packets.append(basic_header)
        upper_layer_header = None
        protocol = None
        j = 0
        for frag in segments:
            #frag.show()
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
        sequences = []
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
                    if first_byte_index == final_payload_len:
                        new_pkt = pkt.copy()
                        new_pkt = new_pkt / conf.raw_layer(load=fragment_raw_payload)
                        final_packets.append(new_pkt) 
                        sequences.append(i)
                        if i+1 < len(segments): 
                            subsequent_fragments = segments[i+1:] 
                            k = 0
                            flag = False
                            while k < len(subsequent_fragments):
                                subsequent_fragment_offset = (subsequent_fragments[k][IPv6ExtHdrFragment].offset * 8) - Ext_header_chain_len
                                if subsequent_fragment_offset == final_payload_len:
                                    flag = True
                                    break
                                k += 1
                            if not flag:
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
        self.logs_handler.logger.info("protocol %d, number of final packets %d", protocol, len(final_packets))
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
            if len(frag["indexes"]) > 0:
                fragment_offset = frag["indexes"][0]
                last_byte = frag["indexes"][1] if frag["indexes"][1] >= 0 else len(input_payload)
            else:
                fragment_offset = frag["FO"]
                last_byte = frag["PayloadLenght"] + fragment_offset if frag["PayloadLenght"] >= 0 else len(input_payload)
            
            if (fragPartLen >= last_byte):
                #self.logs_handler.logger.debug("last byte %d, fragment offset %d", last_byte, fragment_offset)
                raw_payload = fragPartStr[fragment_offset:last_byte]
                #self.logs_handler.logger.debug("len raw payload %d", len(raw_payload))
                #payload = input_payload[fragment_offset:last_byte]
                #payload.show()
                if len(raw_payload) > 0 and len(next_header_chain) > 0 and frag["FO"]  == 0:
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
                
                fragHeader.offset = frag["FO"]  // 8
                fragHeader.m = frag["M"]
                #if j > 0:
                #    fragHeader.nh = 58 # no next header for all segments except the first
                segment = UnfragPart / fragHeader / raw_payload
                segment.plen = len(raw(segment.payload))
                
                if frag["HopLimit"] >= 0:
                    segment.hlim = frag["HopLimit"]
                
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
        
        tmp = res
        new_res = []
        while tmp:
            min_pos = 0
            min_offset = tmp[0][IPv6ExtHdrFragment].offset
            i = 0
            while i < len(tmp):
                cur_offset = tmp[i][IPv6ExtHdrFragment].offset
                if cur_offset < min_offset:
                    min_pos = i
                    min_offset = cur_offset
                i += 1
                
            input_packet.set_payload(bytes(tmp[min_pos]))
            tmp[min_pos] = IPv6(input_packet.get_payload())
            new_res.append(tmp[min_pos])
            #tmp[min_pos].show()
            del tmp[min_pos]
        
        res = new_res
        original_packets, protocol, upper_layer_header = self.payload_defragment(basic_header, Ext_header_chain_len, res)  
        if protocol == -1:
            return None
        
        final_segments = []
        if protocol == 58: # ICMPv6
            i = 0
            while i < len(original_packets): 
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                #original_packets[i].show()
                if ICMPv6EchoRequest in original_packets[i]:
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
                    segments = res.copy()
                    final_segments.append(segments)
                i+=1
            
            #for frag in final_segments:
                #frag.show()
            
        if protocol == 6: # TCP
            i = 0
            while i < len(original_packets): 
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                #original_packets[i].show()
                if TCP in original_packets[i]:
                    #original_packets[i][TCP].id = 0xffff
                    #original_packets[i][TCP].seq = 0xffff
                    del original_packets[i][TCP].chksum
                    input_packet.set_payload(bytes(original_packets[i]))
                    original_packets[i] = IPv6(input_packet.get_payload())
                    frag = res[upper_layer_header]
                    input_packet.set_payload(bytes(frag))
                    frag = IPv6(input_packet.get_payload())
                    #frag[TCP].id = 0xffff
                    #frag[TCP].seq = 0xffff
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
                    segments = res.copy()
                    final_segments.append(segments)
                i+=1
        
        if protocol == 17: # UDP
            i = 0
            while i < len(original_packets): 
                input_packet.set_payload(bytes(original_packets[i]))
                original_packets[i] = IPv6(input_packet.get_payload())
                #original_packets[i].show()
                if UDP in original_packets[i]:
                    #original_packets[i][UDP].id = 0xffff
                    #original_packets[i][UDP].seq = 0xffff
                    del original_packets[i][UDP].chksum
                    input_packet.set_payload(bytes(original_packets[i]))
                    original_packets[i] = IPv6(input_packet.get_payload())
                    frag = res[upper_layer_header]
                    input_packet.set_payload(bytes(frag))
                    frag = IPv6(input_packet.get_payload())
                    #frag[UDP].id = 0xffff
                    #frag[UDP].seq = 0xffff
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
                    segments = res.copy()
                    final_segments.append(segments)
                i+=1
        
        lenght = 0
        if len(final_segments) > 0:
            lenght = len(final_segments)*len(final_segments[0])
        self.logs_handler.logger.info("Fragmentation ends, returning %d fragments", lenght)
        #original_packet.show()
        #for frag in final_segments:
        #    frag.show()
        return final_segments if len(final_segments) > 0 else res
    
    
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
        
        i = 0
        while i < len(res):
            input_packet.set_payload(bytes(res[i]))
            res[i] = IPv6(input_packet.get_payload())
            i += 1
        new_res = []
        new_res.append(res)
        res = new_res
        
        return res


    def _destination_header(self):
        opt = ""
        opt_len = len(opt)
        pad = PadN(otype=1, optlen=opt_len, optdata=opt)
        header = IPv6ExtHdrDestOpt(len=(2 + opt_len + 7) // 8 - 1, autopad=1, options=pad) # len=(2 + opt_len + 7) // 8 - 1
        #header.len = len(raw(header))
        #self.logs_handler.logger.info("destination len %d", len(raw(header)))
        #header.show()
        return header


    def _hopByHop_header(self):
        opt = ""
        opt_len = len(opt)
        pad = PadN(otype=1, optlen=opt_len, optdata=opt) 
        header = IPv6ExtHdrHopByHop(len=(2 + opt_len + 7) // 8 - 1, autopad=1, options=pad) # len=(2 + opt_len + 7) // 8 - 1
        #self.logs_handler.logger.info("hop by hop len %d", len(raw(header)))
        #header.show()
        return header
        
        
    def _routing_header(self):
        header = IPv6ExtHdrRouting(len=(8 // 8 ) - 1, type=0, segleft=0, addresses=[])   #len=(8 // 8 ) - 1
        #self.logs_handler.logger.info("routing len %d", len(raw(header)))
        #header.show()
        return header


    def _ah_header(self):
        icv = "AA"
        opt_len = len(icv)
        pad = PadN(otype=1, optlen=opt_len, optdata=icv)
        header = AH(payloadlen=((12 + len(pad)) // 4 - 2), seq=0, spi=1, icv=pad, padding=b'', reserved=0) #payloadlen=((12 + len(icv)) // 4 - 2),
        #header = fuzz(AH())
        #header.payloadlen = (len(raw(header))//4 -2)
        #self.logs_handler.logger.info("AH header len %d", header.payloadlen)
        #self.logs_handler.logger.info("AH len %d", len(raw(header)))
        #self.logs_handler.logger.info("AH payloadlen %d", header.payloadlen)
        #self.logs_handler.logger.info("ICV len %d", len(raw(header.icv)))
        return header  
    
    
    def _esp_header(self):
        header = ESP(spi=None, seq=0, data=None)
        #self.logs_handler.logger.info("ESP len %d", len(raw(header)))
        #header.show()
        return header
    
    
    def _mobility_header(self):
        opt = "MH"
        opt_len = len(opt)
        pad = PadN(otype=1, optlen=opt_len, optdata=opt)
        header = MIP6MH_BRR(len=1, res=0, cksum=0, res2=0, options=pad)
        #self.logs_handler.logger.info("Mobility len %d", len(raw(header)))
        return header
    
    
    def _fragment_header(self):
        header = IPv6ExtHdrFragment(res1=0, offset=0, res2=0, m=0, id=getrandbits(32))
        #self.logs_handler.logger.info("fragment header len %d", len(raw(header)))
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
            else:
                res = self._fragment_header()
                
        if header == 51:
            if AH in packet:
                res = packet[AH]
                del res.payload
            else:
                res = self._ah_header()
                
        if header == 50:
            if ESP in packet:
                res = packet[ESP]
                del res.payload
            else:
                res = self._esp_header()
                
        if header == 135:
            res = self._mobility_header()
                
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
        
        if input_fragments == None:
            self.logs_handler.logger.error("Can not handle header chain of the fragments")
            return input_fragments
            
        fragments_headerchain = self.input_handler.headerchain
        n = 0
        new_res = []
        while n < len(input_fragments):
            if len(fragments_headerchain) != len(input_fragments[n]):
                self.logs_handler.logger.error("Can not find the header chain of all the fragments")
                return input_fragments
        
            i = 0
            new_fragments = []
            new_fragment_offset = 0
            while i < len(fragments_headerchain):
                headerchain = fragments_headerchain[i]
                if len(headerchain) > 0 and (44 not in headerchain and ("overlapping" in self.input_handler.type or "regular" in self.input_handler.type)):
                    self.logs_handler.logger.error("Fragment header not found in the header chain of fragment %d", i+1)
                    return input_fragments
                fragment = input_fragments[n][i]
                #fragment.show()
                #fragPart.show()
                #unfragPart.show()
            
                basic_header = fragment.copy()
                basic_header.remove_payload() # new_fragment = basic header of the current fragment
                new_fragment = basic_header
                #new_fragment.nh = 59
                #new_fragment.show()
                payload = fragment.copy() # payload of the current fragment
                k = 0
                while (payload.nh not in [59, 6, 17, 58]): # no next header, udp, UDP, icmpv6
                    #payload.show()
                    payload = payload.payload
                    k+=1
            
                last_header = None
                if payload.nh == 6: # tcpù
                    payload = payload[TCP]
                    last_header = 6
        
                elif payload.nh == 17: # udp
                    payload = payload[UDP]
                    last_header = 17
        
                elif payload.nh == 58: # icmpv6
                    payload = payload[ICMPv6EchoRequest]
                    last_header = 58
            
                elif payload.nh == 59: # no next header
                    payload = payload.payload
                    last_header = 59
                
                if len(headerchain) == 0 and ("overlapping" in self.input_handler.type or "regular" in self.input_handler.type):
                    frag_header = self._extension_header_builder(fragment, 44)
                    new_fragment = new_fragment / frag_header    
                
                j = 0
                while j < len(headerchain):
                    header = headerchain[j]
                    if j == 0:
                        new_fragment.nh = header
                    new_header = self._extension_header_builder(fragment, header)
                    if header not in [58, 6, 17] and j+1 < len(headerchain):
                        new_header.nh = headerchain[j+1]
                    if j == len(headerchain)-1 and (header not in [58, 6, 17]):
                        new_header.nh = last_header

                    if new_header != None:
                        new_fragment = new_fragment / new_header
                    j += 1
            
                if payload != None:
                    new_fragment = new_fragment / payload
                
                new_fragment.plen = len(raw(new_fragment.payload))
                
                if IPv6ExtHdrFragment in new_fragment:
                    new_fragment[IPv6ExtHdrFragment].offset = new_fragment_offset
                    new_fragment_offset += len(raw(new_fragment[IPv6ExtHdrFragment].payload)) // 8
            
                if MIP6MH_BRR in new_fragment:
                    aux = new_fragment[MIP6MH_BRR].copy()
                    del aux.payload
                    #aux.show()
                    csum = in6_chksum(135, basic_header, raw(aux))
                    new_fragment[MIP6MH_BRR].cksum = csum
                    #new_fragment[MIP6MH_BRR].show()
                
                if AH in new_fragment:
                    if str(basic_header.dst) not in self.AH_seq:
                        self.AH_seq[str(basic_header.dst)] = 1
                    new_fragment[AH].seq = self.AH_seq[str(basic_header.dst)]
                    self.AH_seq[str(basic_header.dst)] = self.AH_seq[str(basic_header.dst)] +1
            
                if ESP in new_fragment:
                    if str(basic_header.dst) not in self.ESP_seq:
                        self.ESP_seq[str(basic_header.dst)] = 1
                    new_fragment[ESP].seq = self.ESP_seq[str(basic_header.dst)] 
                    self.ESP_seq[str(basic_header.dst)] = self.ESP_seq[str(basic_header.dst)] +1
                    new_payload = new_fragment[ESP].payload.copy()
                    del new_fragment[ESP].payload
                    new_fragment[ESP].data = new_payload

                new_fragments.append(new_fragment)
                i += 1
                
            new_res.append(new_fragments)
            n += 1
        
        self.logs_handler.logger.info("header chain of the fragments processed, returning %d fragments", len(new_res)*len(new_res[0]))
        return new_res