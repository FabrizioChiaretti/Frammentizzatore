from scapy.all import fuzz, IPv6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, AH, ESP, MIP6MH_BRR, PadN, TCP, UDP, ICMPv6EchoRequest, ICMPv6EchoReply, raw, Packet, in6_chksum
from random import getrandbits
from scapy.config import conf
from random import randint
from time import sleep


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
    
    
    def _get_layers(self, packet):
        layers = []
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            layers.append(layer.name.lower().strip().replace("-", ""))
            counter += 1  
        return layers
    
    
    def fragmentation(self, packet):  
        res = None
        pkt= IPv6(packet.get_payload())
        #layers = self._get_layers(pkt)
        #print(layers)
        self.logs_handler.logger.info("\n########## INTERCEPTED PACKET ##########")
        pkt.show()
        
        # tcp handshake 
        if TCP in pkt:
            frame = pkt[TCP]
            if len(raw(frame.payload)) == 0:
                res = self.fragment(packet, self.max_fragment_lenght)
                res = [res]
                return res
        
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
                res = self.header_chain_processor(res, input_packet=packet)
        
        return res
    
    
    def payload_defragment(self, basic_header, Ext_header_chain_len, fragments):
        
        i = 0
        tmp = fragments.copy()
        res = []
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
            
            res.append(tmp[min_pos].copy())
            #tmp[min_pos].show()
            del tmp[min_pos]
        
        segments = []
        i = 0
        while i < len(res):
            pkt = res[i]
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
            
        final_packets = []
        final_packets.append(basic_header)
        upper_layer_header = None
        protocol = None
        j = 0
        for frag in segments:
            #frag.show()
            nh = frag[IPv6ExtHdrFragment].nh
            while nh not in [6, 17, 58, 59]: # tcp, udp, icmpv6, no next header
                frag = frag.payload
                nh = frag.nh
                
            if nh == 6:
                upper_layer_header = j
                protocol = 6
            if nh == 17:
                upper_layer_header = j
                protocol = 17
            if nh == 58: 
                upper_layer_header = j
                protocol = 58
            '''if nh == 59:
                protocol = 59
                upper_layer_header = j'''
            j+=1
            
            '''if TCP in frag:
                upper_layer_header = j
                protocol = 6
            if UDP in frag:
                upper_layer_header = j
                protocol = 17
            if ICMPv6EchoRequest in frag: 
                upper_layer_header = j
                protocol = 58
            j+=1'''
        
        '''if protocol == 59:
            return res[upper_layer_header], protocol, upper_layer_header'''
        
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
                    if first_byte_index == final_payload_len:
                        new_pkt = pkt.copy()
                        new_pkt = new_pkt / conf.raw_layer(load=fragment_raw_payload)
                        final_packets.append(new_pkt) 
                        #sequences.append(i)
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
        self.logs_handler.logger.info("protocol %d, number of final packets %d", protocol, len(final_packets))
        return final_packets, protocol, upper_layer_header
    
    
    def overlapping_fragmentation(self, input_packet):
        
        packet = IPv6(input_packet.get_payload())
        #packet.show()
        
        tmp = self.headerCheck(packet)
        if tmp == False:
            return None
        
        # take the basic header
        basic_header = packet.copy()
        basic_header.remove_payload()
        
        first_fragment = basic_header.copy()
        headers_to_skip = [0,60,43] # Hop-by-Hop Options, Destination Options, Routing Header
        
        i = 0
        nh = basic_header.nh
        while (nh in headers_to_skip):
            header = packet[i+1].copy()
            del header.payload
            first_fragment = first_fragment / header
            i +=1
            nh = header.nh
        
        upper_layer_payload = None
        input_payload = packet[i].payload.copy()
        next_header_chain = [] # header chain placed after the fragment header
        j = i
        while (packet[j].nh not in [59, 6, 17, 58]): # no next header, udp, UDP, icmpv6
            input_payload[j].remove_payload()
            next_header_chain.append(input_payload[j])
            input_payload = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6: # tcp
            upper_layer_payload = packet[TCP].copy()
            input_payload[j].remove_payload()
            next_header_chain.append(input_payload[j])
            
        if int(packet[j].nh) == 17: # udp
            upper_layer_payload = packet[UDP].copy()
            input_payload[j].remove_payload()
            next_header_chain.append(input_payload[j])
        
        if int(packet[j].nh) == 58:
            if ICMPv6EchoRequest in packet[j]:
                upper_layer_payload = packet[ICMPv6EchoRequest].copy()
                del input_payload[j].data
                next_header_chain.append(input_payload[j])
            elif ICMPv6EchoReply in packet[j]:
                upper_layer_payload = packet[ICMPv6EchoReply].copy()
                del input_payload[j].data
                next_header_chain.append(input_payload[j])
            else:
                self.logs_handler.logger.warning("Can not find upper layer payload, returning the original packet...")
                return [packet]
                
        #for h in next_header_chain:
            #print("|||||||||||")
            #h.show()
        Ext_header_chain_len = 0
        Ext_header_chain = next_header_chain.copy()
        Ext_header_chain.pop() # remove the upper layer header
        for header in Ext_header_chain:
            Ext_header_chain_len += len(header)
        #self.logs_handler.logger.error("chain len %d", Ext_header_chain_len)   
        input_payload =  packet[i].payload.copy() # payload coming next to the fragment header
        #input_payload.show()
        first_fragment[i].nh = 44 # next header = fragment header
        UnfragPart = first_fragment.copy()
        #UnfragPartLen = len(raw(UnfragPart))
        #UnfragPart.show()
        packet_id = getrandbits(32)
        first_fragment = first_fragment / IPv6ExtHdrFragment(id=packet_id)  
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
                if len(raw_payload) > 0 and len(next_header_chain) > 0 and frag["FO"] == 0:
                    #payload.show()
                    fragHeader.nh = nh 
                    raw_payload_len = len(raw_payload) 
                    
                    # checking whether an extension header is splitted, if yes an error is returned
                    while nh not in [59, 6, 17, 58] and raw_payload_len > 0:
                        header = next_header_chain.pop(0)
                        if raw_payload_len < len(raw(header)):
                            self.logs_handler.logger.error("Something goes wrong while creating fragment %d, payload lenght should be at least %d bytes higher", j+1, len(raw(header)) - raw_payload_len)
                            return None

                        raw_payload_len -= len(raw(header))
                        nh = header.nh
                    
                    # checking whether the upper layer header is splitted, if yes an error is returned
                    if nh in [59, 6, 17, 58] and len(next_header_chain) > 0:
                        header = next_header_chain.pop(0)
                        for f in fragments[j+1:]:
                            if f["FO"] == 0:
                                next_header_chain.append(header)
                        #if raw_payload_len < len(raw(header)):
                            #self.logs_handler.logger.error("Something goes wrong while creating fragment %d, payload lenght should be at least %d bytes higher", j+1, len(raw(header))-raw_payload_len)   
                            #return None
                        
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
                    self.logs_handler.logger.error("The lenght of the fragment %d is greater than the maximum fragment lenght (%d)", j+1, self.max_fragment_lenght)
                    return None
                
                segment = IPv6(segment)
                res.append(segment)
                
                #self.logs_handler.logger.debug("######################## segment %d", j+1)
                #segment.show()
            else: # something goes wrong
                self.logs_handler.logger.error("Something goes wrong while creating fragment %d, check payload lenght and fragment offset inserted", j+1)
                return None
            
            j+=1
        
        original_fragments = res.copy()
        aux = res.copy()
        first_fragments = []
        k = 0
        while k < len(aux):
            frag = aux[k]
            if frag[IPv6ExtHdrFragment].offset == 0:
                pkt = aux.pop(k)
                k -= 1
                if len(pkt[IPv6ExtHdrFragment].payload) > 0:
                    first_fragments.append(pkt)
            k += 1
            
        '''for f in first_fragments:
            f.show()'''
            
        k = 0
        final_segments = []
        while k < len(first_fragments):
            first_fragment = []
            first_fragment.append(first_fragments[k])
            res = first_fragment + aux
            #for f in res:
                #f.show()
            original_packets, protocol, upper_layer_header = self.payload_defragment(basic_header, Ext_header_chain_len, res)  
            if protocol == -1:
                return None
            
            pkts = []
            for original_packet in original_packets:
                raw_p = raw(original_packet.payload)
                if raw_p != raw(upper_layer_payload):
                    pkts.append(original_packet)
                
            if protocol == 58: # ICMPv6
                tmp = []
                i = 0
                while i < len(original_packets): 
                    original_packets[i] = IPv6(original_packets[i])
                    #original_packets[i].show()
                    if ICMPv6EchoRequest or ICMPv6EchoReply in original_packets[i]:
                        #original_packets[i][ICMPv6EchoRequest].id = 0xffff
                        #original_packets[i][ICMPv6EchoRequest].seq = 0xffff
                        if ICMPv6EchoRequest in original_packets[i]:
                            del original_packets[i][ICMPv6EchoRequest].cksum 
                        else:
                            del original_packets[i][ICMPv6EchoReply].cksum 
                        input_packet.set_payload(bytes(original_packets[i]))
                        original_packets[i] = IPv6(input_packet.get_payload())
                        frag_pos = original_fragments.index(res[upper_layer_header])
                        frag = res[upper_layer_header].copy()
                        #frag[ICMPv6EchoRequest].id = 0xffff
                        #frag[ICMPv6EchoRequest].seq = 0xffff
                        if ICMPv6EchoRequest in frag:
                            del frag[ICMPv6EchoRequest].cksum
                            frag[ICMPv6EchoRequest].cksum = original_packets[i][ICMPv6EchoRequest].cksum
                        if ICMPv6EchoReply in frag:
                            del frag[ICMPv6EchoReply].cksum
                            frag[ICMPv6EchoReply].cksum = original_packets[i][ICMPv6EchoReply].cksum
                        #res[upper_layer_header] = frag
                        if len(final_segments) == 0:
                            tmp.append(frag_pos)
                            segments = original_fragments.copy()
                            segments[frag_pos] = frag
                            final_segments.append(segments)
                        elif frag_pos not in tmp:
                            tmp.append(frag_pos)
                            for seq in final_segments:
                                seq[frag_pos] = frag
                        else:
                            end = len(final_segments)
                            start = 0
                            while start < end:
                                seq = final_segments[start]
                                segments = seq.copy()
                                segments[frag_pos] = frag
                                final_segments.append(segments)
                                start += 1
                        
                    i+=1
                
            if protocol == 6: # TCP
                i = 0
                while i < len(original_packets): 
                    original_packets[i] = IPv6(original_packets[i])
                    #original_packets[i].show()
                    if TCP in original_packets[i]:
                        frag_pos = original_fragments.index(res[upper_layer_header])
                        del original_packets[i][TCP].chksum
                        input_packet.set_payload(bytes(original_packets[i]))
                        original_packets[i] = IPv6(input_packet.get_payload())
                        res[upper_layer_header].chksum = original_packets[i].chksum
                        segments = original_fragments.copy()
                        segments[frag_pos] = res[upper_layer_header]
                        final_segments.append(segments)
                    
                    i+=1
            
            if protocol == 17: # UDP
                i = 0
                while i < len(original_packets): 
                    original_packets[i] = IPv6(original_packets[i])
                    #original_packets[i].show()
                    if UDP in original_packets[i]:
                        #original_packets[i][UDP].id = 0xffff
                        #original_packets[i][UDP].seq = 0xffff
                        frag_pos = original_fragments.index(res[upper_layer_header])
                        del original_packets[i][UDP].chksum
                        del original_packets[i][UDP].len
                        input_packet.set_payload(bytes(original_packets[i]))
                        original_packets[i] = IPv6(input_packet.get_payload())
                        frag = res[upper_layer_header]
                        #frag[UDP].id = 0xffff
                        #frag[UDP].seq = 0xffff
                        del frag[UDP].chksum
                        del frag[UDP].len
                        frag[UDP].chksum = original_packets[i][UDP].chksum
                        frag[UDP].len = original_packets[i][UDP].len
                        res[upper_layer_header] = frag
                        segments = original_fragments.copy()
                        segments[frag_pos] = res[upper_layer_header]
                        final_segments.append(segments)
                    
                    i+=1

            k += 1
        
        if len(final_segments) == 0:
            final_segments = [original_fragments]
        
        lenght = len(final_segments)*len(final_segments[0])
        self.logs_handler.logger.info("Fragmentation ends, returning %d fragments", lenght)
        #for frag in final_segments:
        #    for f in frag:
        #        f.show()
        
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
        nh = basic_header.nh
        while (nh in headers_to_skip):
            headers_to_skip.pop()
            header = packet[i+1].copy()
            del header.payload
            first_fragment = first_fragment / header
            i +=1
            nh = header.nh
            
        first_fragment[i].nh = 44 # next header = fragment header
        packet_id = getrandbits(32)
        
        first_fragment = first_fragment / IPv6ExtHdrFragment(nh = packet[i].nh, m=1, id = packet_id)
        #first_fragment.show()
        fragHeader = first_fragment[IPv6ExtHdrFragment].copy()
        FragHeaderLen = len(raw(first_fragment[IPv6ExtHdrFragment]))
        #fragHeader.show()
        
        input_payload = packet[i].payload.copy() # fragmentable part
        payload_check = packet[i].payload.copy()
        #payload_check.show()
        next_header_chain_lenght = 0        
        j = i     
        #packet[j].show()   
        while (packet[j].nh not in [59, 6, 17, 58]): # no next header, tcp, udp, icmpv6
            payload_check[j].remove_payload()
            next_header_chain_lenght += len(raw(payload_check[j]))
            payload_check = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6 or int(packet[j].nh) == 17: # udp or UDP
            payload_check[j].remove_payload()
            next_header_chain_lenght += len(raw(payload_check[j]))
        
        if int(packet[j].nh) == 58:
            if ICMPv6EchoRequest in packet[j] or ICMPv6EchoReply in packet[j]:
                del payload_check[j].data
                next_header_chain_lenght += len(raw(payload_check[j]))
            else:
                self.logs_handler.logger.warning("Can not find upper layer payload, returning the original packet...")
                return packet
        
        first_fragment = first_fragment / input_payload
        first_fragment.plen = len(raw(first_fragment.payload))
        #print(first_fragment.plen)
        #print(len(raw(first_fragment)))
        #print(len(raw(first_fragment.payload)), packet.plen)
        #first_fragment.show()
        
        if len(raw(first_fragment)) <= fragment_size:
            first_fragment[IPv6ExtHdrFragment].m = 0
            self.logs_handler.logger.info("Fragmentation ends, returning one fragment")
            first_fragment = [first_fragment]
            return first_fragment
        
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
            self.logs_handler.logger.error("Invalid fragment size, it must be a multiple of 8-octets")
            return None
        
        if fragment_size < FragHeaderLen + UnfragPartLen + next_header_chain_lenght:
            self.logs_handler.logger.error("Invalid fragment size, it must be at least %d and a multiple of 8-octets", FragHeaderLen + UnfragPartLen + next_header_chain_lenght)
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
                res.append(IPv6(segment))
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
        res = [res]
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
        header = ESP(spi=1, seq=0, data=None)
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
                
        return res
    
    
    def upper_layer_header_builder(self, fragment, last_header):
        upper_layer_header = None
        if last_header == 6 and TCP in fragment: # tcp
            upper_layer_header = fragment[TCP].copy()
            del upper_layer_header.payload
            if self.input_handler.tcp_sport != None:
                upper_layer_header.sport = self.input_handler.tcp_sport
            if self.input_handler.tcp_dport != None:
                upper_layer_header.dport = self.input_handler.tcp_dport
            if self.input_handler.tcp_flags != None:
                upper_layer_header.flags = self.input_handler.tcp_flags
                
        if last_header == 17 and UDP in fragment: # udp
            upper_layer_header = fragment[UDP].copy()
            del upper_layer_header.payload
            if self.input_handler.udp_sport != None:
                upper_layer_header.sport = self.input_handler.udp_sport
            if self.input_handler.udp_dport != None:
                upper_layer_header.dport = self.input_handler.udp_dport
        
        return upper_layer_header
    
    
    def header_chain_processor(self, input_fragments, input_packet=None):
        
        if input_fragments == None:
            self.logs_handler.logger.error("Can not handle header chain of the fragments")
            return input_fragments
                
        fragments_headerchain = self.input_handler.headerchain
        n = 0
        new_res = []
        upper_layer_header = None
        new_offset = 0
        while n < len(input_fragments):
            if len(fragments_headerchain) != len(input_fragments[n]):
                self.logs_handler.logger.error("Can not find the header chain of all the fragments")
                return input_fragments
        
            i = 0
            new_fragments = []
            while i < len(fragments_headerchain):
                headerchain = fragments_headerchain[i]
                if len(headerchain) > 0 and (44 not in headerchain and ("overlapping" in self.input_handler.type or "regular" in self.input_handler.type)):
                    self.logs_handler.logger.error("Fragment header not found in the header chain of fragment %d", i+1)
                    return input_fragments
                if len(headerchain) == 0 and ("overlapping" in self.input_handler.type or "regular" in self.input_handler.type):
                    headerchain.append(44)
                fragment = input_fragments[n][i]
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
                if payload.nh == 6: # tcp
                    last_header = 6
                    upper_layer_header = payload[TCP].copy()
                    del upper_layer_header.payload
                    if 6 not in headerchain:
                        payload = payload.payload
                    else:
                        payload = payload.payload.payload
        
                elif payload.nh == 17: # udp
                    last_header = 17
                    upper_layer_header = payload[UDP].copy()
                    del upper_layer_header.payload
                    if 17 not in headerchain:
                        payload = payload.payload
                    else:
                        payload = payload.payload.payload
        
                elif payload.nh == 58: # icmpv6
                    last_header = 58
                    if ICMPv6EchoRequest in payload:
                        payload = payload[ICMPv6EchoRequest]
                    elif ICMPv6EchoReply in payload:
                        payload = payload[ICMPv6EchoReply]
                    else:
                        self.logs_handler.logger.warning("Can not find upper layer payload, returning input fragments")
                        return input_fragments
            
                elif payload.nh == 59: # no next header
                    payload = payload.payload
                    last_header = 59
                    
                else:
                    self.logs_handler.logger.error("Can not handle header chain of the fragments, unknown next header encountered")
                    return input_fragments
                
                if "payload" not in headerchain or headerchain[len(headerchain)-1] == "payload":
                    queued_headers_len = 0
                    if "payload" in headerchain:
                        headerchain.remove("payload")
                    j = 0
                    while j < len(headerchain):
                        header = headerchain[j]
                        if j == 0:
                            new_fragment.nh = header
                        if header in [58, 6, 17] and last_header in [58, 6, 17] and header != last_header:
                            self.logs_handler.logger.error("Can not handle header chain of the fragment %d, invalid upper layer header", i+1)
                            return input_fragments
                        if header == last_header:
                            new_header = self.upper_layer_header_builder(fragment, last_header)
                            if input_packet == None:
                                self.logs_handler.logger.error("Can not handle header chain of the fragments")
                                return input_fragments
                            if new_header == None:
                                self.logs_handler.logger.error("Can not handle header chain of the fragment %d, upper layer header not found", i+1)
                                return input_fragments
                            original_packet = IPv6(input_packet.get_payload())
                            #print("!!!!!!!!!!!!!!!!!!!!!!!!1")
                            #original_packet.show()
                            raw_packet = raw(original_packet)
                            raw_packet = raw_packet.replace(raw(upper_layer_header), raw(new_header))
                            original_packet = IPv6(raw_packet)
                            del original_packet.chksum
                            input_packet.set_payload(bytes(original_packet))
                            original_packet = IPv6(input_packet.get_payload())
                            #print("!!!!!!!!!!!!!!!!!!!!!!!!2")
                            #original_packet.show()
                            new_header.chksum = original_packet.chksum
                            new_offset -= len(new_header)
                            raw_frag = raw(fragment)
                            raw_frag = raw_frag.replace(raw(upper_layer_header), raw(new_header))
                            input_fragments[n][i] = IPv6(raw_frag)
                            #new_header.show()
                        else:
                            new_header = self._extension_header_builder(fragment, header)

                        if header != last_header and j+1 < len(headerchain):
                            new_header.nh = headerchain[j+1]
                        if j == len(headerchain)-1 and (header != last_header):
                            new_header.nh = last_header
                        if new_header != None:
                            if header == 44:
                                new_header.offset = new_header.offset + (new_offset // 8) \
                                    if IPv6ExtHdrFragment not in new_fragment else new_fragment[IPv6ExtHdrFragment].offset
                            if new_header not in fragment and IPv6ExtHdrFragment in new_fragment:
                                new_offset += len(new_header) 
                            new_fragment = new_fragment / new_header
                        j += 1
            
                    if payload != None:
                        new_fragment = new_fragment / payload
                        
                else:
                    j = 0
                    new_fragment.nh = headerchain[0] if headerchain[0] != "payload" else last_header
                    queued_headers_len = None
                    while j < len(headerchain):
                        header = headerchain[j]
                        new_header = None
                        if header == "payload":
                            if payload != None:
                                new_fragment = new_fragment / payload
                                queued_headers_len = 0
                        else:
                            if header in [58, 6, 17] and last_header in [58, 6, 17] and header != last_header:
                                self.logs_handler.logger.error("Can not handle header chain of the fragment %d, invalid upper layer header", i+1)
                                return input_fragments
                            if header == last_header:
                                new_header = self.upper_layer_header_builder(fragment, last_header)
                                if input_packet == None:
                                    self.logs_handler.logger.error("Can not handle header chain of the fragments")
                                    return input_fragments
                                if new_header == None:
                                    self.logs_handler.logger.error("Can not handle header chain of the fragment %d, upper layer header not found", i+1)
                                    return input_fragments
                                original_packet = IPv6(input_packet.get_payload())
                                raw_packet = raw(original_packet)
                                raw_packet = raw_packet.replace(raw(upper_layer_header), raw(new_header))
                                original_packet = IPv6(raw_packet)
                                del original_packet.chksum
                                input_packet.set_payload(bytes(original_packet))
                                original_packet = IPv6(input_packet.get_payload())
                                new_header.chksum = original_packet.chksum
                                new_offset -= len(new_header)
                                raw_frag = raw(fragment)
                                raw_frag = raw_frag.replace(raw(upper_layer_header), raw(new_header))
                                input_fragments[n][i] = IPv6(raw_frag)
                                #new_header.show()
                            else:    
                                new_header = self._extension_header_builder(fragment, header)
                            if header != last_header and j+1 < len(headerchain):
                                if headerchain[j+1] != "payload":
                                    new_header.nh = headerchain[j+1]
                                else:
                                    new_header.nh = last_header
                            if j == len(headerchain)-1 and (header != last_header):
                                new_header.nh = 59
                            if new_header != None:
                                if header == 44:
                                    new_header.offset = new_header.offset + (new_offset // 8) \
                                    if IPv6ExtHdrFragment not in new_fragment else new_fragment[IPv6ExtHdrFragment].offset
                                if new_header not in fragment and IPv6ExtHdrFragment in new_fragment:
                                    new_offset += len(new_header) if "payload" not in headerchain[:j] else 0
                                new_fragment = new_fragment / new_header
                                if queued_headers_len != None:
                                    queued_headers_len += len(new_header)
                        j+=1
                
                new_fragment.plen = len(raw(new_fragment.payload)) - queued_headers_len
                
                '''if IPv6ExtHdrFragment in new_fragment:
                    new_fragment[IPv6ExtHdrFragment].offset = new_fragment_offset
                    new_fragment_offset += len(raw(new_fragment[IPv6ExtHdrFragment].payload)) // 8'''
            
                if MIP6MH_BRR in new_fragment:
                    aux = new_fragment[MIP6MH_BRR].copy()
                    del aux.payload
                    #aux.show()
                    csum = in6_chksum(135, basic_header, raw(aux))
                    new_fragment[MIP6MH_BRR].cksum = csum
                    #new_fragment[MIP6MH_BRR].show()

                new_fragments.append(new_fragment)
                i += 1
            
            new_res.append(new_fragments)
            n += 1
        
        self.logs_handler.logger.info("header chain of the fragments processed, returning %d fragments", len(new_res)*len(new_res[0]))
        return new_res