
from json import load
from re import match
from ipaddress import ip_address, IPv6Address 
from log import log


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
        self.fragmentSize = 1280
        self.fragments = None
        self.tcp_handshake_headerchain = []
        self.fragments_headerchain = []
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
        
        if keys_len > 10:
            self.logs_handler.logger.error("input.json file contains unexpected fileds")
            return False
        elif keys_len < 10:
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
        if "fragmentSize" not in keys:
            self.logs_handler.logger.error("'fragmentSize' field not found in input.json")
            return False
        if "regular" in self.type:
            if type(obj["fragmentSize"]) == int and obj["fragmentSize"] >= 56:
                self.fragmentSize = obj["fragmentSize"]
            else:
                self.logs_handler.logger.warning("fragmentSize not specified, default is 1280")
        
        # tcp_handshake_headerchain check
        if "tcp_handshake_headerchain" not in keys:
            self.logs_handler.logger.error("'tcp_handshake_headerchain' field not found in input.json")
            return False
        if type(obj["tcp_handshake_headerchain"]) != list:
            self.logs_handler.logger.error("'tcp_handshake_headerchain' field must be a list in input.json")
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

        # tcp_handshake_headerchain processing
        fragments_printable_headers = []
        if "headerchain" in self.type:
            if "tcp" in self.protocol:
                tcp_handshake_headerchain = obj["tcp_handshake_headerchain"]
                new_chain = []
                for elem in tcp_handshake_headerchain:
                    header = list(elem.keys())
                    header = header[0]
                    header_value = self.header_value(header)  
                    if header_value == None or header_value == 58 or header_value == 6 or header_value == 17:
                        self.logs_handler.logger.error("Invalid extension header in tcp_handshake_headerchain")
                        return False
                    nh = list(elem.values())
                    nh = nh[0]  
                    new_chain.append([header_value, nh])
                    
                self.tcp_handshake_headerchain.append(new_chain)
            
            # fragments headerchain processing
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
                               if "sport" in header["udp"]:
                                sport = header["udp"]["sport"]
                                if type(sport) != int or sport < 0 or sport > 65535:
                                    self.logs_handler.logger.error("udp sport must be an integer between [0, 65535] in fragment %d ", k)
                                    return False
                                self.udp_sport = sport
                                
                               if "dport" in header["udp"]:
                                dport = header["udp"]["dport"]
                                if type(dport) != int or dport < 0 or dport > 65535:
                                    self.logs_handler.logger.error("udp dport must be an integer between [0, 65535] in fragment %d ", k)
                                    return False
                                self.udp_dport = dport
                        
                        if key == "tcp" and len(header["tcp"]) > 0 and len(header["tcp"]) <= 3:
                            if "sport" in header["tcp"]:
                                sport = header["tcp"]["sport"]
                                if type(sport) != int or sport < 0 or sport > 65535:
                                    self.logs_handler.logger.error("tcp sport must be an integer between [0, 65535] in fragment %d ", k)
                                    return False
                                self.tcp_sport = sport
                                        
                            if "dport" in header["tcp"]:
                                dport = header["tcp"]["dport"]
                                if type(dport) != int or dport < 0 or dport > 65535:
                                    self.logs_handler.logger.error("tcp dport must be an integer between [0, 65535] in fragment %d ", k)
                                    return False
                                self.tcp_dport = dport
                                    
                            if "flags" in header["tcp"]:
                                flags = header["tcp"]["flags"]
                                if type(flags) != str:
                                    self.logs_handler.logger.error("tcp flags must be a string in fragment %d", k)
                                    return False
                                for flag in flags:
                                    if flag not in "FSRPAUEC":
                                        self.logs_handler.logger.error("Unknown tcp flags in fragment %d, supported flags are FSRPAUEC", k)
                                        return False
                                self.tcp_flags = flags
                        
                        if key == "icmpv6" and len(header["icmpv6"]) > 0 and len(header["icmpv6"]) <= 2:
                            if "id" in header["icmpv6"]:
                                id = header["icmpv6"]["id"]  
                                if type(id) != int or id < 0 or id > 65535:
                                    self.logs_handler.logger.error("icmpv6 id must be an integer between [0, 65535] in fragment %d ", k)
                                    return False
                                self.icmpv6_id = id  
                            if "seq" in header["icmpv6"]:
                                seq = header["icmpv6"]["seq"]  
                                if type(seq) != int or seq < 0 or seq > 65535:
                                    self.logs_handler.logger.error("icmpv6 seq must be an integer between [0, 65535] in fragment %d ", k)
                                    return False
                                self.icmpv6_seq = seq  
                        
                        if key != "tcp" and key != "udp" and key != "icmpv6":        
                            header_value = self.header_value(key)
                            headers.append([header_value, nh])
                            
                        printable_headers.append([key, nh])
                    else:
                        self.logs_handler.logger.error("Can not process 'HeaderChain' field in fragment %d ", k)
                        return False
                self.fragments_headerchain.append(headers)
                fragments_printable_headers.append(printable_headers)
                k += 1
        
        # show the input on command line
        if self.dstPort < 0:
            self.logs_handler.logger.info("table=%s, chain=%s, protocol=%s, dstPort=%s, ipv6Dest=%s, type=%s", \
            "filter" if self.table == "" else self.table, "OUTPUT" if self.chain == "" else self.chain, \
            "any" if self.protocol == "" else self.protocol, "any", "any" if self.ipv6Dest == "" else self.ipv6Dest, self.type)
        else:
             self.logs_handler.logger.info("table=%s, chain=%s, protocol=%s, dstPort=%d, ipv6Dest=%s, type=%s", \
            "filter" if self.table == "" else self.table, "OUTPUT" if self.chain == "" else self.chain, \
            "any" if self.protocol == "" else self.protocol, self.dstPort, "any" if self.ipv6Dest == "" else self.ipv6Dest, self.type)
        
        if "regular" in self.type:
            self.logs_handler.logger.info("fragmentSize=%d", self.fragmentSize)
        
        if "overlapping" in self.type:
            self.logs_handler.logger.info("singleTest=%d", self.singleTest)
            k = 1
            for frag in self.fragments:
                self.logs_handler.logger.info("Fragment %d\n src=%s, dst=%s, plen=%d, PayloadLenght=%d, HopLimit=%d, FO=%d, M=%d, indexes=%s, payload=%s", \
                    k, frag["src"], frag["dst"],  frag["plen"], frag["PayloadLenght"], frag["HopLimit"], frag["FO"], frag["M"], frag["indexes"], frag["payload"])
                k+=1
        
        if "headerchain" in self.type:
            if "tcp" in self.protocol and len(self.tcp_handshake_headerchain) > 0:
                self.logs_handler.logger.info("Headerchain of tcp handshake packets \n%s", self.tcp_handshake_headerchain)
            k = 1
            for chain in fragments_printable_headers:
                self.logs_handler.logger.info("Headerchain of fragment %d\n%s", k, chain)
                k += 1
    
        return True
    
    
    
    
    
    