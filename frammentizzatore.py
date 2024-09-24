
from scapy.all import IPv6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt, IPv6ExtHdrHopByHop, IPv6ExtHdrRouting, AH, ESP, PadN, TCP, UDP, ICMPv6EchoRequest, ICMPv6EchoReply, raw, Packet, Raw
from random import getrandbits
from scapy.config import conf
from time import sleep


class frammentizzatore:
    
    
    def __init__(self, logs_handler, input_handler, max_fragment_lenght = 1280):
        
        self.max_fragment_lenght = max_fragment_lenght
        self.logs_handler = logs_handler  
        self.input_handler = input_handler

    
    def packetCheck(self, packet):
        
        if self.input_handler.fragmentSize > self.max_fragment_lenght:
            self.logs_handler.logger.error("The maximum fragment size is %d", self.max_fragment_lenght)
            return False
        
        if IPv6ExtHdrFragment in packet:
            self.logs_handler.logger.error("IPv6ExtHdrFragment already present")
            return False
        
        if IPv6 not in packet:
            self.logs_handler.logger.error("Can not found IPv6 header")
            return False
        
        if AH in packet:
            ah = packet[AH].copy()
            del ah.payload
            payload = packet[AH].payload.copy()
            new_packet = packet.copy()
            new_packet.remove_payload()
            new_packet.nh = ah.nh
            new_packet = IPv6(new_packet / payload)
            payload = new_packet.payload
            packet_cp = packet.copy()
            del packet_cp[AH].underlayer.payload
            new_packet = packet_cp / ah / payload
            return new_packet
                    
        return packet
    
    
    def fragmentation(self, packet):  
        
        res = None
        matching_fragments = None
        pkt = IPv6(packet.get_payload())
        packet_check = self.packetCheck(pkt)
        
        if packet_check == False:
            return None
        else:
            pkt = packet_check
        
        #layers = self._get_layers(pkt)
        #print(layers)
        self.logs_handler.logger.info("\n########## INTERCEPTED PACKET ##########")
        pkt.show()
        
        # tcp handshake 
        if TCP in pkt:
            frame = pkt[TCP]
            if len(raw(frame.payload)) == 0:
                if AH in pkt:
                    return None
                else:
                    if "headerchain" in self.input_handler.type:
                        input_pkt = [[pkt]]
                        tmp = self.input_handler.fragments_headerchain
                        self.input_handler.fragments_headerchain = self.input_handler.tcp_handshake_headerchain
                        matching_fragments = [[0]]
                        res = self.header_chain_processor(input_pkt, matching_fragments, input_packet=packet)
                        self.input_handler.fragments_headerchain = tmp
                        matching_fragments = None
                    else:
                        res = self.fragment(packet, new_input_packet=None, fragment_size=self.max_fragment_lenght)
                    return res
        
        if "regular" in self.input_handler.type:
            res = self.fragment(packet, new_input_packet=pkt, fragment_size=self.input_handler.fragmentSize)
                
        if "overlapping" in self.input_handler.type:
            res, matching_fragments = self.overlapping_fragmentation(packet, new_input_packet=pkt)
        
        if "headerchain" in self.input_handler.type:
            if ("regular" not in self.input_handler.type) and ("overlapping" not in self.input_handler.type):
                pkt = [[pkt]]
                hc = []
                hc.append(self.input_handler.fragments_headerchain[0])
                self.input_handler.fragments_headerchain = hc
                res = self.header_chain_processor(pkt, matching_fragments, input_packet=packet)
            else:
                res = self.header_chain_processor(res, matching_fragments, input_packet=packet)
        
        return res
    
    
    def payload_defragment(self, basic_header, fragments):
        
        upper_layer_header = None
        protocol = None
        j = 0
        for frag in fragments:
            #frag.show()
            nh = frag[IPv6ExtHdrFragment].nh
            while nh not in [6, 17, 58, 59, 41, 50]: # tcp, udp, icmpv6, no next header, encapsulation
                frag = frag.payload
                nh = frag.nh
                
            if nh == 6:
                upper_layer_header = j
                if protocol == None:
                    protocol = 6
                    
            if nh == 17:
                upper_layer_header = j
                if protocol == None:
                    protocol = 17
                    
            if nh == 58: 
                upper_layer_header = j
                if protocol == None:
                    protocol = 58
                    
            if nh == 41:
                protocol = 41
                encapsulated_packet = frag.payload
                while encapsulated_packet:
                    if encapsulated_packet.nh in [58,6,17]:
                        upper_layer_header = j
                        break
                    encapsulated_packet = encapsulated_packet.payload
                    
            if nh == 50:
                protocol = 50
                upper_layer_header = j
            
        if protocol == None:
            self.logs_handler.logger.error("Can not find upper layer protocol, can not check upper layer checksum")
            return fragments, -1, -1
        
        if upper_layer_header == None:
            self.logs_handler.logger.error("Can not find upper layer header, can not check upper layer checksum")
            return fragments, -1, -1
        
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
        
        segments = res
        
        #for seg in segments:
        #    seg.show()
        
        aux = []
        final_packets = []
        new_plen = 0
        for frag in fragments:
            if frag[IPv6ExtHdrFragment].offset == 0:
                if frag.src != basic_header.src:
                    basic_header.src = frag.src
                if frag.dst != basic_header.dst:
                    basic_header.dst = frag.dst
            new_plen += frag.plen - 8
                
        final_packets.append(basic_header)
        matching_fragments = []
        i = 0
        #sequences = []
        for frag in segments:
            #frag.show()
            fragment_header = frag[IPv6ExtHdrFragment]
            fragment_payload = fragment_header.payload
            #fragment_payload.show()
            fragment_raw_payload = raw(fragment_payload)
            first_byte_index = (fragment_header.offset * 8)
            #last_byte_index = len(fragment_raw_payload) + first_byte_index
            #self.logs_handler.logger.info("len = %d, offset = %d", pkt_len, first_byte_index)
            if len(fragment_raw_payload) > 0:
                j = 0
                while j < len(final_packets):
                    pkt = final_packets[j]
                    final_payload_len = len(pkt.payload)
                    #pkt.payload.show()
                    if first_byte_index == final_payload_len:
                        matching_fragments.append(fragments.index(frag))
                        new_pkt = pkt.copy()
                        new_pkt = new_pkt / conf.raw_layer(load=fragment_raw_payload)
                        if frag[IPv6ExtHdrFragment].m == 1:
                            final_packets.append(new_pkt)
                        else:
                            aux.append(new_pkt)
                        #sequences.append(i)
                        if i+1 < len(segments): 
                            subsequent_fragments = segments[i+1:] 
                            k = 0
                            flag = False
                            while k < len(subsequent_fragments):
                                subsequent_fragment_offset = (subsequent_fragments[k][IPv6ExtHdrFragment].offset * 8)
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
        
        final_packets = aux
        i = 0
        while i < len(final_packets):
            final_packets[i] = IPv6(final_packets[i])
            if fragments[0].plen != len(raw(fragments[0].payload)):
                final_packets[i].plen = new_plen
            else:
                final_packets[i].plen = len(raw(final_packets[i].payload))
            #final_packets[i].show()
            #print(final_packets[i].plen, new_plen)
            #sleep(5)
            i += 1
        
        #print(sequences) 
        #print(upper_layer_header)   
        #self.logs_handler.logger.info("protocol %d, number of final packets %d", protocol, len(final_packets))
        return final_packets, matching_fragments, protocol, upper_layer_header
    
    
    def overlapping_fragmentation(self, input_packet, new_input_packet=None):
        packet = None
        if new_input_packet != None:
            packet = new_input_packet
        else:
            packet = IPv6(input_packet.get_payload())
        #packet.show()

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
        while (packet[j].nh not in [59, 6, 17, 58, 41, 50]): # no next header, tcp, udp, icmpv6
            input_payload.remove_payload()
            next_header_chain.append(input_payload)
            input_payload = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6: # tcp
            upper_layer_payload = packet[TCP].copy()
            input_payload.remove_payload()
            next_header_chain.append(input_payload)
            
        if int(packet[j].nh) == 17: # udp
            upper_layer_payload = packet[UDP].copy()
            input_payload.remove_payload()
            next_header_chain.append(input_payload)
        
        if int(packet[j].nh) == 58:
            if ICMPv6EchoRequest in packet[j]:
                upper_layer_payload = packet[ICMPv6EchoRequest].copy()
                del input_payload.data
                next_header_chain.append(input_payload)
            elif ICMPv6EchoReply in packet[j]:
                upper_layer_payload = packet[ICMPv6EchoReply].copy()
                del input_payload.data
                next_header_chain.append(input_payload)
            else:
                upper_layer_payload = packet[j].payload.copy()
                input_payload.remove_payload()
                next_header_chain.append(input_payload)
                #sleep(2)
        
        if int(packet[j].nh) == 41: # encapsulation
            upper_layer_payload = packet[j].payload.copy() # encapsulated packet
            encapsulated_data = upper_layer_payload.copy()
            pld = encapsulated_data.copy()
            del pld.payload
            next_header_chain.append(pld)
            while encapsulated_data.nh not in [59, 6, 17, 58]:
                pld = encapsulated_data.copy()
                del pld.payload
                next_header_chain.append(pld)
                encapsulated_data = encapsulated_data.payload
                
            # repeating the same code for finding upper layer header
            if int(encapsulated_data.nh) == 6: # tcp
                pld = encapsulated_data[TCP].copy()
                pld.remove_payload()
                next_header_chain.append(pld)
            
            if int(encapsulated_data.nh) == 17: # udp
                pld = encapsulated_data[UDP].copy()
                pld.remove_payload()
                next_header_chain.append(pld)
            
            if int(encapsulated_data.nh) == 58:
                if ICMPv6EchoRequest in encapsulated_data[j]:
                    pld = encapsulated_data[ICMPv6EchoRequest].copy()
                    del pld.data
                    next_header_chain.append(pld)
                elif ICMPv6EchoReply in encapsulated_data[j]:
                    pld = encapsulated_data[ICMPv6EchoReply].copy()
                    del pld.data
                    next_header_chain.append(pld)
                else:
                    pld = encapsulated_data.payload.copy()
                    pld.remove_payload()
                    next_header_chain.append(pld)

        if int(packet[j].nh) == 50: # esp
            upper_layer_payload = packet[ESP].copy()
            del input_payload.data
            next_header_chain.append(input_payload)
        
        #upper_layer_payload.show()      
        #for h in next_header_chain:
        #    h.show()
        next_header_chain_len = 0
        for header in next_header_chain:
            next_header_chain_len += len(header)
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
        #input_payload.show()
        #self.logs_handler.logger.info("UnfragPartLen %d, FragHeaderLen %d, fragPartLen %d", \
        #    UnfragPartLen, FragHeaderLen, fragPartLen)
        
        res = [] 
        j = 0
        first_header = packet[i].nh
        fragments = self.input_handler.fragments
        
        if len(fragments) == 1 and AH in packet:
            self.logs_handler.logger.warning("Authentication header not supported for atomic fragments")
            return None, None
        
        for frag in fragments:
            if len(frag["indexes"]) > 0:
                fragment_offset = frag["indexes"][0]
                last_byte = frag["indexes"][1] if frag["indexes"][1] >= 0 else len(input_payload)
            else:
                fragment_offset = frag["FO"]
                last_byte = frag["PayloadLenght"] + fragment_offset if frag["PayloadLenght"] >= 0 else len(input_payload)
            
            if (fragPartLen >= last_byte):
                raw_payload = fragPartStr[fragment_offset:last_byte]
                if len(raw_payload) > 0 and (fragment_offset >= 0 and fragment_offset < next_header_chain_len):
                    k = 0
                    offs = 0
                    headers_to_insert = []
                    while k < len(next_header_chain):
                        if fragment_offset == offs:
                            #next_header_chain[k].show()
                            if fragment_offset + last_byte < offs + len(raw(next_header_chain[k])):
                                self.logs_handler.logger.error("Something goes wrong while creating fragment %d, payload lenght should be at least %d bytes higher", j+1, (offs + len(raw(next_header_chain[k]))) - (fragment_offset + last_byte))
                                return None, None
                            headers_to_insert.append(next_header_chain[k])
                            offs += len(raw(next_header_chain[k]))
                            chain = next_header_chain[k+1:].copy()
                            while offs < last_byte:
                                if len(chain) == 0:
                                    break
                                h = chain.pop(0)
                                if offs + len(raw(h)) > fragment_offset + last_byte:
                                    self.logs_handler.logger.error("Something goes wrong while creating fragment %d, payload lenght should be at least %d bytes higher", j+1, (offs + len(raw(h))) - (fragment_offset + last_byte))
                                    return None, None
                                offs += len(raw(h))
                                headers_to_insert.append(h)
                        else:
                            offs += len(raw(next_header_chain[k]))        
                            
                        k += 1
                            
                    if len(headers_to_insert) == 0:
                        self.logs_handler.logger.error("Something goes wrong while creating fragment %d, extension headers can not be fragmented", j+1)
                        return None, None
                    
                    h = headers_to_insert.pop(0)
                    pos = next_header_chain.index(h)
                    if pos == 0:
                        fragHeader.nh = first_header
                    else:
                        p = pos-1
                        fragHeader.nh = next_header_chain[p].nh
                        
                else:
                    fragHeader.nh = 59 # no next header
                
                fragHeader.offset = frag["FO"]  // 8
                fragHeader.m = frag["M"]
                segment = UnfragPart / fragHeader / raw_payload
                #new_payload = b'A'*len(raw_payload)
                #new_payload = Raw(new_payload)
                #prova = UnfragPart / fragHeader / new_payload
                segment.plen = len(raw(segment.payload))
                if frag["HopLimit"] >= 0:
                    segment.hlim = frag["HopLimit"]
                
                if len(raw(segment)) > self.max_fragment_lenght:
                    self.logs_handler.logger.error("The lenght of the fragment %d is greater than the maximum fragment lenght (%d)", j+1, self.max_fragment_lenght)
                    return None, None
                
                segment = IPv6(segment)

                
                if (ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet):
                    payload = None
                    if ICMPv6EchoRequest in segment:
                        payload = segment[ICMPv6EchoRequest]
                        if frag["payload"] != "":
                            if payload.data != "":
                                payload.data = frag["payload"]*(len(raw(segment[ICMPv6EchoRequest])) - 8)
                    elif ICMPv6EchoReply in segment:
                        payload = segment[ICMPv6EchoReply]
                        if frag["payload"] != "":
                            if payload.data != "":
                                payload.data = frag["payload"]*(len(raw(segment[ICMPv6EchoReply])) - 8)
                    else:
                        if frag["payload"] != "":
                            if segment[IPv6ExtHdrFragment].nh == 59 and len(raw(segment[IPv6ExtHdrFragment].payload)) > 0:
                                segment = UnfragPart / fragHeader / bytes(Raw(frag["payload"]*(len(segment[IPv6ExtHdrFragment].payload))))
                    
                    if "headerchain" in self.input_handler.type and payload != None:
                        if self.input_handler.icmpv6_id != None:
                            payload.id = self.input_handler.icmpv6_id
                        if self.input_handler.icmpv6_seq != None:
                            payload.seq = self.input_handler.icmpv6_seq
                
                if (TCP in packet or UDP in packet) and "headerchain" in self.input_handler.type:
                    if TCP in segment:
                        payload = segment[TCP]
                        if self.input_handler.tcp_sport != None:
                            payload.sport = self.input_handler.tcp_sport
                        if self.input_handler.tcp_dport != None:
                            payload.dport = self.input_handler.tcp_dport
                        if self.input_handler.tcp_flags != None:
                            payload.flags = self.input_handler.tcp_flags
                    elif UDP in segment:
                        payload = segment[UDP]
                        if self.input_handler.udp_sport != None:
                            payload.sport = self.input_handler.udp_sport
                        if self.input_handler.udp_dport != None:
                            payload.dport = self.input_handler.udp_dport
                                     
                if frag["plen"] < 0:
                    segment.plen = len(raw(segment.payload))
                else:
                    segment.plen = frag["plen"]
                        
                if frag["src"] != "":
                    segment.src = frag["src"]
                if frag["dst"] != "":
                    segment.dst = frag["dst"]
                    
                res.append(segment)
                #segment.show()
                
            else: # something goes wrong
                self.logs_handler.logger.error("Something goes wrong while creating fragment %d, check payload lenght and fragment offset inserted", j+1)
                return None, None
            
            j+=1
        
        #for frag in res:
        #    frag.show()
        
        original_fragments = res.copy()
        #original_fragments[3][IPv6ExtHdrFragment].id += 1
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
        final_matching_fragments = []
        final_packets_found = 0
        new_packets_found = 0
        while k < len(first_fragments):
            first_fragment = []
            first_fragment.append(first_fragments[k])
            res = first_fragment + aux
            original_packets, matching_fragments, protocol, upper_layer_header = self.payload_defragment(basic_header, res)
            final_packets_found += len(original_packets)
            original_indexes = []
            for index in matching_fragments:
                original_indexes.append(original_fragments.index(res[index]))
            final_matching_fragments.append(original_indexes)
            if protocol == -1:
                return None, None
            
            tmp = []
            pkts = []
            for original_packet in original_packets:
                original_packet_payload = original_packet
                #original_packet_payload.show()
                #sleep(5)
                while original_packet_payload.nh not in [58, 6, 17, 41, 50]:
                    original_packet_payload = original_packet_payload.payload
                original_packet_payload = original_packet_payload.payload
                raw_p = raw(original_packet_payload)
                if raw_p != raw(upper_layer_payload):
                    pkts.append(original_packet)
                else:
                    if upper_layer_header not in tmp:
                        if len(final_segments) == 0:
                            final_segments.append(original_fragments)
                        frag_pos = original_fragments.index(res[upper_layer_header])
                        tmp.append(frag_pos)
        
                if protocol == 41:
                    while original_packet_payload.nh not in [58, 6, 17]:
                        original_packet_payload = original_packet_payload.payload
                    protocol = original_packet_payload.nh
            
            original_packets = pkts
            new_packets_found += len(original_packets)
            #self.logs_handler.logger.info("%d new packets found", len(original_packets))
            
            if protocol == 58: # ICMPv6
                i = 0
                while i < len(original_packets): 
                    #original_packets[i].show()
                    if ICMPv6EchoRequest or ICMPv6EchoReply in original_packets[i]:
                        #original_packets[i][ICMPv6EchoRequest].id = 0xffff
                        #original_packets[i][ICMPv6EchoRequest].seq = 0xffff
                        if ICMPv6EchoRequest in original_packets[i]:
                            del original_packets[i][ICMPv6EchoRequest].cksum 
                        if ICMPv6EchoReply in original_packets[i]:
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
                            if len(tmp) < 2: # len(tmp) == 1
                                segments = final_segments[end-1].copy()
                                segments[frag_pos] = frag
                                final_segments.append(segments)
                            else:
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
                    #original_packets[i].show()
                    if TCP in original_packets[i]:
                        del original_packets[i][TCP].chksum
                        input_packet.set_payload(bytes(original_packets[i]))
                        original_packets[i] = IPv6(input_packet.get_payload())
                        frag_pos = original_fragments.index(res[upper_layer_header])
                        frag = res[upper_layer_header].copy()
                        frag[TCP].chksum = original_packets[i][TCP].chksum
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
            
            if protocol == 17: # UDP
                i = 0
                while i < len(original_packets): 
                    #original_packets[i].show()
                    if UDP in original_packets[i]:
                        del original_packets[i][UDP].chksum
                        input_packet.set_payload(bytes(original_packets[i]))
                        original_packets[i] = IPv6(input_packet.get_payload())
                        frag_pos = original_fragments.index(res[upper_layer_header])
                        frag = res[upper_layer_header].copy()
                        frag[UDP].chksum = original_packets[i][UDP].chksum
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
            
            k += 1
        
        if len(final_segments) == 0:
            final_segments = [original_fragments]
        
        lenght = len(final_segments)*len(final_segments[0])
        
        if protocol == 6:
            protocol = "tcp"
        elif protocol == 17:
            protocol = "udp"
        elif protocol == 58:
            protocol = "icmpv6"
        else:
            protocol = ""
        
        self.logs_handler.logger.info("protocol %s, number of new packets %d, number of final packets %d", protocol, new_packets_found, final_packets_found)
        self.logs_handler.logger.info("Overlapping fragmentation ends, returning %d fragments", lenght)
        
        # reset the input packet
        input_packet.set_payload(bytes(packet))
        
        return final_segments, final_matching_fragments
    
    
    def fragment(self, input_packet, new_input_packet=None, fragment_size = 1280):
        
        packet = None
        if new_input_packet != None:
            packet = new_input_packet
        else:
            packet = IPv6(input_packet.get_payload())
        #packet.show()
        
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
        while (packet[j].nh not in [59, 6, 17, 58, 41, 50]): # no next header, tcp, udp, icmpv6
            payload_check.remove_payload()
            next_header_chain_lenght += len(raw(payload_check))
            payload_check = packet[j+1].payload.copy()
            j+=1
        
        if int(packet[j].nh) == 6 or int(packet[j].nh) == 17: # udp or UDP
            payload_check.remove_payload()
            next_header_chain_lenght += len(raw(payload_check))
        
        if int(packet[j].nh) == 58:
            if ICMPv6EchoRequest in packet[j] or ICMPv6EchoReply in packet[j]:
                del payload_check.data
                next_header_chain_lenght += len(raw(payload_check))
            else:
                payload_check.remove_payload()
                next_header_chain_lenght += len(raw(payload_check))
        
        if int(packet[j].nh) == 41: # encapsulation
            encapsulated_data = payload_check.copy()
            pld = encapsulated_data.copy()
            del pld.payload
            next_header_chain_lenght += len(pld)
            while encapsulated_data.nh not in [59, 6, 17, 58]:
                pld = encapsulated_data.copy()
                del pld.payload
                next_header_chain_lenght += len(pld)
                encapsulated_data = encapsulated_data.payload
                
            # repeating the same code for finding upper layer header
            if int(encapsulated_data.nh) == 6: # tcp
                pld = encapsulated_data[TCP].copy()
                pld.remove_payload()
                next_header_chain_lenght += len(pld)
            
            if int(encapsulated_data.nh) == 17: # udp
                pld = encapsulated_data[UDP].copy()
                pld.remove_payload()
                next_header_chain_lenght += len(pld)
            
            if int(encapsulated_data.nh) == 58:
                if ICMPv6EchoRequest in encapsulated_data[j]:
                    pld = encapsulated_data[ICMPv6EchoRequest].copy()
                    del pld.data
                    next_header_chain_lenght += len(pld)
                elif ICMPv6EchoReply in encapsulated_data[j]:
                    pld = encapsulated_data[ICMPv6EchoReply].copy()
                    del pld.data
                    next_header_chain_lenght += len(pld)
                else:
                    pld = encapsulated_data.payload.copy()
                    pld.remove_payload()
                    next_header_chain_lenght += len(pld)

        if int(packet[j].nh) == 50: # esp
            del payload_check.data
            next_header_chain_lenght += len(payload_check)
        
        first_fragment = first_fragment / input_payload
        first_fragment.plen = len(raw(first_fragment.payload))
        #print(first_fragment.plen)
        #print(len(raw(first_fragment)))
        #print(len(raw(first_fragment.payload)), packet.plen)
        #first_fragment.show()
        
        if len(raw(first_fragment)) <= fragment_size:
            if AH in packet:
                self.logs_handler.logger.warning("Authentication header not supported for atomic fragments")
                return None
            first_fragment[IPv6ExtHdrFragment].m = 0
            self.logs_handler.logger.info("Regular fragmentation ends, returning one fragment")
            first_fragment = [[first_fragment]]
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
        
        self.logs_handler.logger.info("Regular fragmentation ends, returning %d fragments", len(res))
        res = [res]
        return res


    def _destination_header(self):
        opt = ""
        opt_len = len(opt)
        pad = PadN(otype=1, optlen=opt_len, optdata=opt)
        header = IPv6ExtHdrDestOpt(len=(2 + opt_len + 7) // 8 - 1, autopad=1, options=pad) # len=(2 + opt_len + 7) // 8 - 1
        #header.len = len(raw(header))
        #self.logs_handler.logger.info("destination len %d", len(raw(header)))
        #sleep(5)
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
    
    
    def _fragment_header(self):
        header = IPv6ExtHdrFragment(res1=0, offset=0, res2=0, m=0, id=getrandbits(32))
        #self.logs_handler.logger.info("fragment header len %d", len(raw(header)))
        return header
    
    
    def _extension_header_builder(self, input_packet, packet, header):
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
                
        if header == 50:
            if ESP in packet:
                res = packet[ESP].copy()
                del res.data
                
        if header == 51:
            if AH in packet:
                res = packet[AH].copy()
                del res.payload
            elif AH in input_packet:
                res = input_packet[AH].copy()
                del res.payload
                res.show()
                
        '''if header == 135:
            res = self._mobility_header()'''
                
        return res
    
    
    '''def upper_layer_header_builder(self, fragment, last_header):
        print("dentro")
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
                
        if last_header == 58:
            if ICMPv6EchoRequest in fragment:
                upper_layer_header = fragment[ICMPv6EchoRequest].copy()
                del upper_layer_header[ICMPv6EchoRequest].data
                if self.input_handler.icmpv6_id != None: 
                    upper_layer_header.id = self.input_handler.icmpv6_id
                if self.input_handler.icmpv6_seq != None:
                    upper_layer_header.seq = self.input_handler.icmpv6_seq
                    
            if ICMPv6EchoReply in fragment:
                upper_layer_header = fragment[ICMPv6EchoReply].copy()
                del upper_layer_header[ICMPv6EchoReply].data
                if self.input_handler.icmpv6_id != None: 
                    upper_layer_header.id = self.input_handler.icmpv6_id
                if self.input_handler.icmpv6_seq != None:
                    upper_layer_header.seq = self.input_handler.icmpv6_seq
        
        return upper_layer_header'''
    
        
    def header_chain_processor(self, input_fragments, matching_fragments, input_packet=None):
        
        packet = None
        if input_packet != None:
            packet = IPv6(input_packet.get_payload())
        #packet.show()
        
        if input_fragments == None:
            self.logs_handler.logger.error("Can not handle header chain of the fragments")
            return input_fragments
        
        i = 0
        while i < len(input_fragments):
            j = 0
            while j < len(input_fragments[i]):
                if AH in input_fragments[i][j] and len(input_fragments[i][j][AH].payload) > 0:
                    ah = input_fragments[i][j][AH].copy()
                    del ah.payload
                    payload = input_fragments[i][j][AH].payload.copy()
                    new_packet = input_fragments[i][j].copy()
                    new_packet.remove_payload()
                    new_packet.nh = ah.nh
                    new_packet = IPv6(new_packet / payload)
                    payload = new_packet.payload
                    #payload.show()
                    packet_cp = input_fragments[i][j].copy()
                    del packet_cp[AH].underlayer.payload
                    input_fragments[i][j] = packet_cp / ah / payload
                    
                j += 1
                
            i += 1
        
        '''for frag in input_fragments:
            for f in frag:
                f.show()'''
                
        fragments_headerchain = self.input_handler.fragments_headerchain
        n = 0
        new_res = []
        new_offset = {}
        upper_layer_header = None
        while n < len(input_fragments):
            if len(fragments_headerchain) != len(input_fragments[n]):
                self.logs_handler.logger.error("Can not find the header chain of all the fragments")
                return input_fragments
        
            i = 0
            new_fragments = []
            random_plen = False
            #fragment_header_found = False
            while i < len(fragments_headerchain):
                headerchain = fragments_headerchain[i]
                '''if len(headerchain) > 0:
                    if "overlapping" in self.input_handler.type or "regular" in self.input_handler.type:
                        for header in headerchain:
                            if header[0] == 44:
                                fragment_header_found = True
                                break
                        if fragment_header_found == False:
                            self.logs_handler.logger.error("Fragment header not found in the header chain of fragment %d", i+1)
                            return input_fragments'''
                        
                fragment = input_fragments[n][i]
                if IPv6ExtHdrFragment in fragment:
                    if fragment[IPv6ExtHdrFragment].offset == 0 and i not in new_offset:
                        new_offset[i] = 0
                else :
                    new_offset[0] = 0
                
                #fragPart.show()
                #unfragPart.show()
                if fragment.plen != len(raw(fragment.payload)):
                    random_plen = True
            
                basic_header = fragment.copy()
                basic_header.remove_payload() # new_fragment = basic header of the current fragment
                new_fragment = basic_header
                #new_fragment.nh = 59
                #new_fragment.show()
                payload = fragment.copy() # payload of the current fragment
                k = 0
                fragment_ext_headers = []
                while (payload.nh not in [59, 6, 17, 58, 41, 50]): # no next header, udp, UDP, icmpv6, encapsulation
                    #payload.show()
                    fragment_ext_headers.append(payload.nh)
                    payload = payload.payload
                    k+=1
                
                input_headers = [row[0] for row in headerchain]
                original_upper_layer_header = None
                last_header = None
                if payload.nh == 6: # tcp
                    last_header = 6
                    fragment_ext_headers.append(6)
                    upper_layer_header = payload[TCP].copy()
                    del upper_layer_header.payload
                    original_upper_layer_header = packet[TCP].copy()
                    del original_upper_layer_header.payload
                    payload = payload.payload
        
                elif payload.nh == 17: # udp
                    last_header = 17
                    fragment_ext_headers.append(17)
                    upper_layer_header = payload[UDP].copy()
                    del upper_layer_header.payload
                    original_upper_layer_header = packet[UDP].copy()
                    del original_upper_layer_header.payload
                    payload = payload.payload
        
                elif payload.nh == 58: # icmpv6
                    last_header = 58
                    if ICMPv6EchoRequest in payload:
                        if 58 in input_headers:
                            payload = payload[ICMPv6EchoRequest]
                            fragment_ext_headers.append(58)
                        else:
                            payload = payload[ICMPv6EchoRequest]
                    elif ICMPv6EchoReply in payload:
                        if 58 in input_headers:
                            payload = payload[ICMPv6EchoReply]
                            fragment_ext_headers.append(58)
                        else:
                            payload = payload[ICMPv6EchoReply]
                    else:
                        payload = payload.payload
            
                elif payload.nh == 59: # no next header
                    payload = payload.payload
                    last_header = 59
                    
                elif payload.nh == 41:
                    payload = payload.payload
                    last_header = 41
                
                elif payload.nh == 50:
                    payload = payload[ESP].data
                    last_header = 50
                    fragment_ext_headers.append(50)
                    
                else:
                    self.logs_handler.logger.error("Can not handle header chain of the fragments, unknown next header encountered")
                    return input_fragments
                
                if "payload" not in headerchain or headerchain[len(headerchain)-1] == "payload":
                    queued_headers_len = 0
                    if "payload" in headerchain:
                        headerchain.remove("payload")
                    j = 0
                    while j < len(headerchain):
                        new_header = None
                        header = headerchain[j][0]
                        if j == 0:
                            new_fragment.nh = header
                            
                        '''if header in [58, 6, 17] and last_header in [58, 6, 17] and header != last_header:
                            self.logs_handler.logger.error("Can not handle header chain of the fragment %d, invalid upper layer header", i+1)
                            return input_fragments
                                
                        if header == last_header and header != 50:
                            if input_packet == None:
                                self.logs_handler.logger.error("Can not handle header chain of the fragments")
                                return input_fragments
                            
                            original_packet = packet.copy()
                            if last_header == 6:
                                if TCP not in original_packet or TCP not in fragment:
                                    self.logs_handler.logger.error("Can not handle header chain of the fragment %d, upper layer header not found", i+1)
                                    return input_fragments
                                else:
                                    new_header = original_packet[TCP]
                                    if self.input_handler.tcp_sport != None:
                                        new_header.sport = self.input_handler.tcp_sport
                                    if self.input_handler.tcp_dport != None:
                                        new_header.dport = self.input_handler.tcp_dport
                                    if self.input_handler.tcp_flags != None:
                                        new_header.flags = self.input_handler.tcp_flags 
                                
                                del new_header.chksum
                                        
                            if last_header == 17:
                                if UDP not in original_packet or UDP not in fragment:
                                    self.logs_handler.logger.error("Can not handle header chain of the fragment %d, upper layer header not found", i+1)
                                    return input_fragments
                                else:
                                    new_header = original_packet[UDP]
                                    if self.input_handler.udp_sport != None:
                                        new_header.sport = self.input_handler.udp_sport
                                    if self.input_handler.udp_dport != None:
                                        new_header.dport = self.input_handler.udp_dport
                                
                                del new_header.chksum
                            
                            if last_header == 58:
                                if (ICMPv6EchoRequest not in fragment or ICMPv6EchoRequest not in original_packet) \
                                    and (ICMPv6EchoReply not in fragment or ICMPv6EchoReply not in original_packet):
                                        self.logs_handler.logger.error("Can not handle header chain of the fragment %d, upper layer header not found", i+1)
                                        return input_fragments
                                if ICMPv6EchoRequest in original_packet:
                                    new_header = original_packet[ICMPv6EchoRequest]
                                if ICMPv6EchoReply in original_packet:
                                    new_header = original_packet[ICMPv6EchoReply]
                                
                                if self.input_handler.icmpv6_id != None:
                                    new_header.id = self.input_handler.icmpv6_id
                                if self.input_handler.icmpv6_seq != None:
                                    new_header.seq = self.input_handler.icmpv6_seq
                                
                                del new_header.cksum
                            
                            input_packet.set_payload(bytes(original_packet))
                            original_packet = IPv6(input_packet.get_payload())
                            
                            if TCP in original_packet:
                                new_header = original_packet[TCP].copy()
                                del new_header.payload
                            if UDP in original_packet:
                                new_header = original_packet[UDP].copy()
                                del new_header.payload
                            if ICMPv6EchoRequest in original_packet:
                                new_header = original_packet[ICMPv6EchoRequest].copy()
                                del new_header.data
                            if ICMPv6EchoReply in original_packet:
                                new_header = original_packet[ICMPv6EchoReply].copy()
                                del new_header.data
                            #new_offset[i] -= len(new_header)
                            input_packet.set_payload(bytes(packet))'''
               
                        
                        new_header = self._extension_header_builder(IPv6(input_packet.get_payload()), fragment, header)
                        if new_header == None:
                            self.logs_handler.logger.error("Can not handle header chain of the fragment %d, extension header %d not found", i+1, header)
                            return input_fragments

                        if headerchain[j][1] != -1:
                            if header != last_header:
                                new_header.nh = headerchain[j][1]
                        else:   
                            if header != last_header and j+1 < len(headerchain):
                                new_header.nh = headerchain[j+1][0]
                            if j == len(headerchain)-1 and (header != last_header):
                                new_header.nh = last_header    
                                
                        if new_header != None:
                            if header == 44 and IPv6ExtHdrFragment in new_fragment:
                                new_header.id = new_fragment[IPv6ExtHdrFragment].id
                            if header not in fragment_ext_headers and IPv6ExtHdrFragment in new_fragment:
                                new_offset[i] += len(new_header) 
                            new_fragment = new_fragment / new_header
                            
                        j += 1
            
                    if payload != None:
                        new_fragment = new_fragment / payload
                        
                else:
                    j = 0
                    new_fragment.nh = headerchain[0] if headerchain[0] != "payload" else last_header
                    queued_headers_len = None
                    while j < len(headerchain):
                        header = headerchain[j][0]
                        new_header = None
                        if header == "payload":
                            if payload != None:
                                new_fragment = new_fragment / payload
                                queued_headers_len = 0
                        else:
                            if header in [58, 6, 17] and last_header in [58, 6, 17] and header != last_header:
                                self.logs_handler.logger.error("Can not handle header chain of the fragment %d, invalid upper layer header", i+1)
                                return input_fragments
                            '''if header == last_header and header != 50:
                                new_header = self.upper_layer_header_builder(fragment, last_header)
                                if input_packet == None:
                                    self.logs_handler.logger.error("Can not handle header chain of the fragments")
                                    return input_fragments
                                if new_header == None:
                                    self.logs_handler.logger.error("Can not handle header chain of the fragment %d, upper layer header not found", i+1)
                                    return input_fragments
                                original_packet = packet.copy()
                                #original_packet.show()
                                raw_packet = raw(original_packet)
                                raw_packet = raw_packet.replace(raw(original_upper_layer_header), raw(new_header))
                                original_packet = IPv6(raw_packet)
                                #original_packet.show()
                                if TCP in original_packet:
                                    del original_packet[TCP].chksum
                                if UDP in original_packet:
                                    del original_packet[UDP].chksum
                                if ICMPv6EchoRequest in original_packet:
                                    del original_packet[ICMPv6EchoRequest].cksum
                                if ICMPv6EchoReply in original_packet:
                                    del original_packet[ICMPv6EchoReply].cksum
                                input_packet.set_payload(bytes(original_packet))
                                original_packet = IPv6(input_packet.get_payload())
                                #original_packet.show()
                                if TCP in original_packet:
                                    new_header.chksum = original_packet[TCP].chksum
                                if UDP in original_packet:
                                    new_header.chksum = original_packet[UDP].chksum
                                if ICMPv6EchoRequest in original_packet:
                                    new_header.cksum = original_packet[ICMPv6EchoRequest].cksum
                                if ICMPv6EchoReply in original_packet:
                                    new_header.cksum = original_packet[ICMPv6EchoReply].cksum
                                #new_offset[i] -= len(new_header)
                                raw_frag = raw(fragment)
                                #input_fragments[n][i].show()
                                raw_frag = raw_frag.replace(raw(upper_layer_header), raw(new_header))
                                input_fragments[n][i] = IPv6(raw_frag)
                                #input_fragments[n][i].show()
                                #new_header.show()
                                input_packet.set_payload(bytes(packet))'''
                              
                            new_header = self._extension_header_builder(IPv6(input_packet.get_payload()), fragment, header)
                            if new_header == None:
                                self.logs_handler.logger.error("Can not handle header chain of the fragment %d, extension header %d not found", i+1, header)
                                return input_fragments
                                
                            if headerchain[j][1] != -1:
                                if header != last_header:
                                    new_header.nh = headerchain[j][1]
                            else:   
                                if header != last_header and j+1 < len(headerchain):
                                    new_header.nh = headerchain[j+1][0]
                                if j == len(headerchain)-1 and (header != last_header):
                                    new_header.nh = last_header
                           
                            if new_header != None:
                                if header == 44 and IPv6ExtHdrFragment in new_fragment:
                                    new_header.id = new_fragment[IPv6ExtHdrFragment].id
                                if header not in fragment_ext_headers and IPv6ExtHdrFragment in new_fragment:
                                    new_offset[i] += len(new_header) if "payload" not in headerchain[:j] else 0
                                new_fragment = new_fragment / new_header
                                if queued_headers_len != None:
                                    queued_headers_len += len(new_header)
                        j+=1
                
                if not random_plen:
                    new_fragment.plen = len(raw(new_fragment.payload)) - queued_headers_len
                    random_plen = False

                new_fragments.append(new_fragment)
                i += 1
            
            new_fragments_len = len(new_fragments)
            ind = 0
            while ind <  new_fragments_len:
                frag = new_fragments[ind]
                if IPv6ExtHdrFragment in frag:
                    if frag[IPv6ExtHdrFragment].offset != 0:
                        seq_res = None
                        for seq in matching_fragments:
                            if ind in seq:
                                seq_res = seq
                                break
                        if seq_res != None:
                            first_fragment = seq_res[0]
                            frag[IPv6ExtHdrFragment].offset = frag[IPv6ExtHdrFragment].offset + (new_offset[first_fragment] // 8)
                ind += 1
                    
            new_res.append(new_fragments)
            n += 1
        
        self.logs_handler.logger.info("header chain of the fragments processed, returning %d fragments", len(new_res)*len(new_res[0]))
        return new_res