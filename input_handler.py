
from json import load
from re import match
from ipaddress import ip_address, IPv6Address 
from log import log
from time import sleep

# fare dei test per verificare le ultime modifiche
# pusha il codice
# dare la possibilità di modificare l'headerchain dei frammenti prendendo in input una sola headerchain nel caso regular
# dare la possibilità di eseguire più istanze del tool con configurazioni diverse (input1.json, input2.json ecc...)

class inputHandler:
    
    
    def __init__(self, file, logs_handler):
        
        self.file = file
        self.logs_handler = logs_handler
        self.table = ""
        self.chain = ""
        self.protocol = ""    
        self.dstPort = ""
        self.ipv6Dest = "" 
        self.type = "regular" 
        self.singleTest = 0
        self.max_fragmentSize = 1280
        self.regular_fragmentSize = 1280
        self.fragments = None
        self.fragments_headerchain = []
        self.tcp_handshake = []
        self.tcp_handshake_headerchain = []
        self.udp_sport = None
        self.udp_dport = None
        self.tcp_sport = None
        self.tcp_dport = None
        self.tcp_flags = None
        self.icmpv6_id = None
        self.icmpv6_seq = None


    def header_value(self, name):
        
        res = None
        
        if name == "hopbyhop":
            res = 0
        if name == "destination":
            res = 60
        if name == "routing":
            res = 43
        if name == "fragment":
            res = 44
        if name == "ah":
            res = 51
        if name == "esp":
            res = 50
        if name == "mobility":
            res = 135
        if name == "icmpv6":
            res = 58
        if name == "tcp":
            res = 6
        if name == "udp":
            res = 17
        
        return res
   
    
    def parse_input(self):
        
        try:
            obj = load(self.file)
        except:
            self.logs_handler.logger.error("json decoding error")
            return False
        keys = list(obj.keys())
        keys_len = len(keys)
        
        if keys_len > 11:
            self.logs_handler.logger.error("input.json file contains unexpected fileds")
            return False
        elif keys_len < 11:
            self.logs_handler.logger.error("input.json file does not contain all the expected fileds")
            return False
        
        # table check
        if "table" not in keys:
            self.logs_handler.logger.error("'table' field not found")
            return False
        if type(obj["table"]) != str:
            self.logs_handler.logger.error("'table' must be a string in input.json")
            return False
        self.table = obj["table"].lower()
        if self.table != "":
            if self.table != "mangle" and self.table != "filter":
                self.logs_handler.logger.error("Invalid table")
                return False
        
        # chain check
        if "chain" not in keys:
            self.logs_handler.logger.error("'chain' field not found")
            return False
        if type(obj["chain"]) != str:
            self.logs_handler.logger.error("'chain' must be a string in input.json")
            return False
        self.chain = obj["chain"].upper()
        if self.table == "":
            self.chain = ""
        if self.chain == "" and self.table != "":
            self.logs_handler.logger.error("Invalid chain")
            return False
        if self.chain != "": 
            if self.table == "mangle" and (self.chain != "OUTPUT" and self.chain != "POSTROUTING"):
                self.logs_handler.logger.error("Invalid chain")
                return False
            if self.table == "filter" and (self.chain != "OUTPUT"):
                self.logs_handler.logger.error("Invalid chain")
                return False
        
        # protocol check
        if "protocol" not in keys:
            self.logs_handler.logger.error("'protocol' field not found")
            return False
        if type(obj["protocol"]) != str:
            self.logs_handler.logger.error("'protocol' must be a string in input.json")
            return False
        obj["protocol"] = obj["protocol"].lower().strip()
        if obj["protocol"] == "":
            self.protocol = ["tcp", "udp", "icmpv6"]
        else:
            pattern = '[a-zA-Z0-9]*\s*[a-zA-Z0-9]*\s*[a-zA-Z0-9]*\s*[a-zA-Z0-9]*\s*[a-zA-Z0-9]*'
            m = match(pattern, obj["protocol"])
            if not m:
                self.logs_handler.logger.error("Invalid protocol")
                return False
            else:
                protocol = m.group()
                protocol = " ".join(protocol.split()) 
                protocol = protocol.split(" ")
                for proto in protocol:
                    if proto != "udp" and proto != "tcp" and proto != "icmpv6" and proto != "esp" and proto != "ah":
                        self.logs_handler.logger.error("Invalid protocol")
                        return False
                self.protocol = protocol
        
        #dstPort check
        if "dstPort" not in keys:
            self.logs_handler.logger.error("'dstPort' field not found in input.json")
            return False
        if type(obj["dstPort"]) != int:
            self.logs_handler.logger.error("'dstPort' must be a positive integer input.json")
            return False
        if "udp" not in self.protocol and "tcp" not in self.protocol:
            self.dstPort = -1
        else:
            self.dstPort = obj["dstPort"]
        if self.dstPort < 0 and ("udp" in self.protocol or "tcp" in self.protocol):
            self.logs_handler.logger.warning("dst port not specified")
        
        # ipv6Dest check
        if "ipv6Dest" not in keys:
            self.logs_handler.logger.error("'ipv6Dest' field not found in input.json")
            return False
        if type(obj["ipv6Dest"]) != str:
            self.logs_handler.logger.error("'ipv6Dest' must be a string in input.json")
            return False
        if obj["ipv6Dest"] != "":
            try: 
                addr = type(ip_address(obj["ipv6Dest"])) is IPv6Address
            except ValueError: 
                self.logs_handler.logger.error("Invalid ipv6Dest")
                return False
        self.ipv6Dest = obj["ipv6Dest"]
        
        # type check
        if "type" not in keys:
            self.logs_handler.logger.error("'type' field not found in input.json")
            return False
        if type(obj["type"]) != str:
            self.logs_handler.logger.error("'type' must be a string in input.json")
            return False
        obj["type"] = obj["type"].lower()
        if obj["type"] == "regular" or obj["type"] == "overlapping" or obj["type"] == "headerchain" \
            or obj["type"] == "overlapping-headerchain" or obj["type"] == "regular-headerchain":
            self.type = obj["type"]
        else:
            self.logs_handler.logger.error("Invalid fragmentation type")
            return False
        
        # singleTest check
        if "singleTest" not in keys:
            self.logs_handler.logger.error("'singleTest' field not found in input.json")
            return False
        if "overlapping" in self.type:
            if type(obj["singleTest"]) != int or (obj["singleTest"] != 0 and obj["singleTest"] != 1):
                self.logs_handler.logger.error("'singleTest' field must be 0 or 1 in input.json")
                return False
            self.singleTest = obj["singleTest"]
        else:
            self.singleTest = 1
        
        # fragment size check   
        if "regular-fragmentSize" not in keys:
            self.logs_handler.logger.error("'regular-fragmentSize' field not found in input.json")
            return False
        if "regular" in self.type:
            if type(obj["regular-fragmentSize"]) == int and obj["regular-fragmentSize"] >= 0:#and obj["fragmentSize"] >= 56:
                self.regular_fragmentSize = obj["regular-fragmentSize"]
            #else:
            #    self.logs_handler.logger.warning("fragmentSize not specified, default is 1280")
        
        # max_fragmentSize check   
        if "max_fragmentSize" not in keys:
            self.logs_handler.logger.error("'max_fragmentSize' field not found in input.json")
            return False
        if type(obj["max_fragmentSize"]) == int and obj["max_fragmentSize"] > 48:#and obj["fragmentSize"] >= 56:
            self.max_fragmentSize = obj["max_fragmentSize"]
        
        # tcp_handshake check
        if "tcp_handshake" not in keys:
            self.logs_handler.logger.error("'tcp_handshake' field not found in input.json")
            return False
        if type(obj["tcp_handshake"]) != list:
            self.logs_handler.logger.error("'tcp_handshake' field must be a list in input.json")
            return False
        
        # fragments check
        if "fragments" not in keys:
            self.logs_handler.logger.error("'fragments' field not found in input.json")
            return False
        if "overlapping" in self.type or "headerchain" in self.type:
            if type(obj["fragments"]) != list or len(obj["fragments"]) == 0:
                self.logs_handler.logger.error("fragments filed must be a non-empty list")
                return False
        
        # fragments' fields check
        fragments = obj["fragments"]
        tcp_handshake_len = 0
        tcp_handshake = []
        if "tcp" in protocol:
            tcp_handshake = obj["tcp_handshake"]
            tcp_handshake_len = len(tcp_handshake)
            for frag in reversed(tcp_handshake):
                fragments.insert(0, frag)
                
        if "overlapping" in self.type:
            k = 1
            for frag in fragments:
                frag_keys = frag.keys()
                if len(frag_keys) > 10:
                    self.logs_handler.logger.error("Fragment %d contains unexpected fileds", k)
                    return False
                elif len(frag_keys) < 10:
                    self.logs_handler.logger.error("Fragment %d does not contain all the expected fileds", k)
                    return False
            
                # src check
                if "src" not in frag_keys:
                    self.logs_handler.logger.error("'src' field misses in fragment %d ", k)
                    return False
                if type(frag["src"]) != str:
                    self.logs_handler.logger.error("'src' must be a string in fragment %d ", k)
                    return False
                if frag["src"] != "":
                    try: 
                        addr =  type(ip_address(frag["src"])) is IPv6Address 
                    except ValueError: 
                        self.logs_handler.logger.error("Invalid src in fragment %d", k)
                        return False
                
                # dst check
                if "dst" not in frag_keys:
                    self.logs_handler.logger.error("'dst' field misses in fragment %d ", k)
                    return False
                if type(frag["dst"]) != str:
                    self.logs_handler.logger.error("'dst' must be a string in fragment %d", k)
                    return False
                if frag["dst"] != "":
                    try: 
                        addr =  type(ip_address(frag["dst"])) is IPv6Address 
                    except ValueError: 
                        self.logs_handler.logger.error("Invalid dst in fragment %d", k)
                        return False
                
                # plen check
                if "plen" not in frag_keys:
                    self.logs_handler.logger.error("'plen' field misses in fragment %d ", k)
                    return False
                if type(frag["plen"]) != int or frag["plen"] > 65535:
                    self.logs_handler.logger.error("'plen' must be an integer between [0, 65535] in fragment %d ", k)
                    return False
                if frag["plen"] < 0:
                    frag["plen"] = -1
            
                # payload lenght check
                if "PayloadLenght" not in frag_keys:
                    self.logs_handler.logger.error("'PayloadLenght' field misses in fragment %d ", k)
                    return False
                if type(frag["PayloadLenght"]) != int:
                    self.logs_handler.logger.error("'PayloadLenght' must be a positive integer and a multiple number of 8 in fragment %d ", k)
                    return False

                # hop limit check
                if "HopLimit" not in frag_keys:
                    self.logs_handler.logger.error("'HopLimit' field misses in fragment %d ", k)
                    return False
                if type(frag["HopLimit"]) != int:
                    self.logs_handler.logger.error("'HopLimit' must be an integer in fragment %d ", k)
                    return False
                if frag["HopLimit"] < 0:
                    frag["HopLimit"] = -1
                if frag["HopLimit"] > 255:
                    self.logs_handler.logger.error("'HopLimit' must be an integer between [0,255] in fragment %d", k)
                    return False

                # fragment offset check
                if "FO" not in frag_keys:
                    self.logs_handler.logger.error("'FO' field misses in fragment %d ", k)
                    return False
                if type(frag["FO"]) != int or frag["FO"] < 0:
                    self.logs_handler.logger.error("'FO' must be a positive integer in fragment %d ", k)
                    return False
                if frag["FO"] % 8 != 0:
                    self.logs_handler.logger.error("'FO' must be a positive integer and a multiple number of 8 in fragment %d ", k)
                    return False
                
                if "M" not in frag_keys:
                    self.logs_handler.logger.error("'M' field misses in fragment %d ", k)
                    return False
                if type(frag["M"]) != int or (frag["M"] != 0 and frag["M"] != 1):
                    self.logs_handler.logger.error("'M' must be either 0 or 1 in fragment %d ", k)
                    return False
                if (frag["PayloadLenght"] % 8 != 0 and frag["M"] == 1) or (frag["PayloadLenght"] < 0 and frag["M"] == 1):
                    self.logs_handler.logger.error("'PayloadLenght' must be a positive integer and a multiple number of 8 in fragment %d ", k)
                    return False
                
                # indexes check
                if "indexes" not in frag_keys:
                    self.logs_handler.logger.error("'indexes' field misses in fragment %d ", k)
                    return False
                if type(frag["indexes"]) != list or (len(frag["indexes"]) != 2 and len(frag["indexes"]) != 0) or \
                    (len(frag["indexes"]) == 2 and (type(frag["indexes"][0]) != int or type(frag["indexes"][1]) != int)):
                    self.logs_handler.logger.error("'indexes' field must be an empty list or a list of two integers in fragment %d ", k)
                    return False
                if len(frag["indexes"]) == 2 and (frag["indexes"][0] < 0 or (frag["indexes"][1] < 0 and frag["PayloadLenght"] > 0) or\
                    (frag["indexes"][1] > 0 and frag["PayloadLenght"] < 0)):
                    self.logs_handler.logger.error("The two indexes and PayloadLeght must be positives numbers in fragment %d", k)
                    return False
                
                # PayloadLenght and indexes check
                if len(frag["indexes"]) == 2 and (frag["indexes"][1] > 0 and frag["PayloadLenght"] > 0) and (frag["indexes"][1] - frag["indexes"][0] != frag["PayloadLenght"]):
                    self.logs_handler.logger.error("Invalid indexes and PayloadLeght in fragment %d", k)
                    return False
                
                # payload check
                if "payload" not in frag_keys:
                    self.logs_handler.logger.error("'payload' field misses in fragment %d", k)
                    return False
                if type(frag["payload"]) != str or len(frag["payload"]) > 1:
                    self.logs_handler.logger.error("'payload' must be a string containing one letter %d", k)
                    return False
                if len(frag["payload"]) == 1:
                    frag["payload"] = frag["payload"].upper()
                    expected_digit = "[A-Z]"
                    m = match(expected_digit, frag["payload"])
                    if not m:
                        self.logs_handler.logger.error("Invalid payload in fragment %d", k)
                        return False

                k+=1
            
        self.fragments = fragments
                
        # fragments headerchain processing and tcp_handshake processing
        fragments_printable_headers = []
        tcp_handshake_printable_headers = []
        k = 1    
        for frag in self.fragments:
            frag_keys = frag.keys()
            if "HeaderChain" not in frag_keys:
                self.logs_handler.logger.error("'HeaderChain' field misses in fragment %d ", k)
                return False
            if type(frag["HeaderChain"]) != list:
                self.logs_handler.logger.error("'HeaderChain' field must be a list in fragment %d ", k)
                return False
            headers = []
            printable_headers = []
            for header in frag["HeaderChain"]:
                if type(header) == str and header.lower() == "payload":
                    headers.append(header.lower())
                    printable_headers.append(header.lower())
                elif type(header) == dict:
                    key = list(header.keys())
                    key = key[0].lower()
                    nh = None
                    if key not in ["tcp", "udp", "icmpv6", "esp"]:
                        nh = list(header.values())
                        nh = nh[0]
                    else:
                        nh = -1
                            
                    if nh not in [0, 60, 43, 44, 50, 51, 135, 6, 17, 58, 59, -1]:
                        self.logs_handler.logger.error("Invalid next header value in fragment %d ", k)
                        return False
                    if key not in ["hopbyhop", "destination", "routing", "ah", "esp", "fragment", "mobility", "tcp", "udp", "icmpv6"]:
                        self.logs_handler.logger.error("Invalid extension header in fragment %d ", k)
                        return False
                    if key == "udp" and len(header["udp"]) > 0 and len(header["udp"]) <= 2:
                        new_header = [17, -1, -1]
                        if "sport" in header["udp"]:
                            sport = header["udp"]["sport"]
                            if type(sport) != int or sport < 0 or sport > 65535:
                                self.logs_handler.logger.error("udp sport must be an integer between [0, 65535] in fragment %d ", k)
                                return False
                            #if self.udp_sport == None:
                            new_header[1] = sport
                                
                        if "dport" in header["udp"]:
                            dport = header["udp"]["dport"]
                            if type(dport) != int or dport < 0 or dport > 65535:
                                self.logs_handler.logger.error("udp dport must be an integer between [0, 65535] in fragment %d ", k)
                                return False
                            #if self.udp_dport == None:
                            new_header[2] = dport
                            
                        headers.append(new_header)  
                        printable_headers.append(new_header)
                        
                    if key == "tcp" and len(header["tcp"]) > 0 and len(header["tcp"]) <= 3:
                        new_header = [6, -1, -1, ""]
                        if "sport" in header["tcp"]:
                            sport = header["tcp"]["sport"]
                            if type(sport) != int or sport < 0 or sport > 65535:
                                self.logs_handler.logger.error("tcp sport must be an integer between [0, 65535] in fragment %d ", k)
                                return False
                            #if self.tcp_sport == None:
                            new_header[1] = sport
                                        
                        if "dport" in header["tcp"]:
                            dport = header["tcp"]["dport"]
                            if type(dport) != int or dport < 0 or dport > 65535:
                                self.logs_handler.logger.error("tcp dport must be an integer between [0, 65535] in fragment %d ", k)
                                return False
                            #if self.tcp_dport == None:
                            new_header[2] = dport
                                    
                        if "flags" in header["tcp"]:
                            flags = header["tcp"]["flags"]
                            if type(flags) != str:
                                self.logs_handler.logger.error("tcp flags must be a string in fragment %d", k)
                                return False
                            for flag in flags:
                                if flag not in "FSRPAUEC":
                                    self.logs_handler.logger.error("Unknown tcp flags in fragment %d, supported flags are FSRPAUEC", k)
                                    return False
                            #if self.tcp_flags == None:
                            new_header[3] = flags
                        headers.append(new_header)  
                        printable_headers.append(new_header)
                        
                    if key == "icmpv6" and len(header["icmpv6"]) > 0 and len(header["icmpv6"]) <= 2:
                        new_header = [58, -1, -1]
                        if "id" in header["icmpv6"]:
                            id = header["icmpv6"]["id"]  
                            if type(id) != int or id < 0 or id > 65535:
                                self.logs_handler.logger.error("icmpv6 id must be an integer between [0, 65535] in fragment %d ", k)
                                return False
                            #if self.icmpv6_id == None:
                            new_header[1] = id 
                        if "seq" in header["icmpv6"]:
                            seq = header["icmpv6"]["seq"]  
                            if type(seq) != int or seq < 0 or seq > 65535:
                                self.logs_handler.logger.error("icmpv6 seq must be an integer between [0, 65535] in fragment %d ", k)
                                return False
                            #if self.icmpv6_seq == None:
                            new_header[2] = seq
                                
                        headers.append(new_header)  
                        printable_headers.append(new_header)
                        
                    if key != "tcp" and key != "udp" and key != "icmpv6":
                        header_value = self.header_value(key)
                        headers.append([header_value, nh])  
                        printable_headers.append([key, nh])
                    
                else:
                    self.logs_handler.logger.error("Can not process 'HeaderChain' field in fragment %d ", k)
                    return False
            
            if k-1 < tcp_handshake_len:
                self.tcp_handshake_headerchain.append(headers) 
                tcp_handshake_printable_headers.append(printable_headers)
            else:
                self.fragments_headerchain.append(headers)
                fragments_printable_headers.append(printable_headers)
            k += 1
        
        if "tcp" in protocol:
            for frag in tcp_handshake:
                self.fragments.remove(frag)    
            self.tcp_handshake = tcp_handshake
        
        # show the input on command line
        if self.dstPort < 0:
            self.logs_handler.logger.info("table=%s, chain=%s, protocol=%s, dstPort=%s, ipv6Dest=%s, max_framentSize=%s, type=%s", \
            "filter" if self.table == "" else self.table, "OUTPUT" if self.chain == "" else self.chain, \
            "any" if self.protocol == "" else self.protocol, "any", "any" if self.ipv6Dest == "" else self.ipv6Dest, self.max_fragmentSize, self.type)
        else:
             self.logs_handler.logger.info("table=%s, chain=%s, protocol=%s, dstPort=%d, ipv6Dest=%s, max_framentSize=%s, type=%s", \
            "filter" if self.table == "" else self.table, "OUTPUT" if self.chain == "" else self.chain, \
            "any" if self.protocol == "" else self.protocol, self.dstPort, "any" if self.ipv6Dest == "" else self.ipv6Dest, self.max_fragmentSize, self.type)
        
        if "regular" in self.type:
            self.logs_handler.logger.info("regular_fragmentSize=%d", self.regular_fragmentSize)
        
        if "overlapping" in self.type:
            self.logs_handler.logger.info("singleTest=%d", self.singleTest)
            k = 1
            if "tcp" in self.protocol and len(self.tcp_handshake) > 0:
                for frag in self.tcp_handshake:
                    self.logs_handler.logger.info("TCP handshake packet %d\n src=%s, dst=%s, plen=%d, PayloadLenght=%d, HopLimit=%d, FO=%d, M=%d, indexes=%s, payload=%s", \
                        k, frag["src"], frag["dst"],  frag["plen"], frag["PayloadLenght"], frag["HopLimit"], frag["FO"], frag["M"], frag["indexes"], frag["payload"])
                    k+=1
            k =1 
            for frag in self.fragments:
                self.logs_handler.logger.info("Fragment %d\n src=%s, dst=%s, plen=%d, PayloadLenght=%d, HopLimit=%d, FO=%d, M=%d, indexes=%s, payload=%s", \
                    k, frag["src"], frag["dst"],  frag["plen"], frag["PayloadLenght"], frag["HopLimit"], frag["FO"], frag["M"], frag["indexes"], frag["payload"])
                k+=1
        
        if "headerchain" in self.type:
            if "tcp" in self.protocol:
                k = 1
                for chain in tcp_handshake_printable_headers:
                    self.logs_handler.logger.info("Headerchain of tcp handshake packet %d\n%s", k, chain)
                    k += 1
            k = 1
            for chain in fragments_printable_headers:
                self.logs_handler.logger.info("Headerchain of fragment %d\n%s", k, chain)
                k += 1
                
    
        return True
    
    
    
    
    
    