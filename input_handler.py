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
        self.fragmentSize = 1280
        self.fragments = None
        self.headerchain = []
        self.udp_sport = None
        self.udp_dport = None
        self.tcp_sport = None
        self.tcp_dport = None
        self.tcp_flags = None


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
        keys = obj.keys()
        
        # table check
        if "table" not in keys:
            self.logs_handler.logger.error("'table' field not found")
            return False
        
        self.table = str(obj["table"]).lower()
        if self.table != "":
            if self.table != "mangle" and self.table != "nat" and self.table != "filter":
                self.logs_handler.logger.error("Invalid table")
                return False
        
        # chain check
        if "chain" not in keys:
            self.logs_handler.logger.error("'chain' field not found")
            return False
        
        self.chain = str(obj["chain"]).upper()
        if self.table == "":
            self.chain = ""
            
        if self.chain == "" and self.table != "":
            self.logs_handler.logger.error("Invalid chain")
            return False
        
        if self.chain != "": 
            if self.table == "nat" and (self.chain != "OUTPUT" and self.chain != "POSTROUTING"):
                self.logs_handler.logger.error("Invalid chain")
                return False
            if self.table == "mangle" and (self.chain != "OUTPUT" and self.chain != "POSTROUTING" and self.chain != "FORWARD"):
                self.logs_handler.logger.error("Invalid chain")
                return False
            if self.table == "filter" and (self.chain != "OUTPUT" and self.chain != "FORWARD"):
                self.logs_handler.logger.error("Invalid chain")
                return False
        
        # protocol check
        if "protocol" not in keys:
            self.logs_handler.logger.error("'protocol' field not found")
            return False
        
        obj["protocol"] = str(obj["protocol"]).lower().strip()
        if obj["protocol"] == "":
            self.protocol = ["tcp", "udp", "icmpv6", "ah", "esp"]
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
        
        if (self.protocol != "udp" and self.protocol != "tcp") or (type(obj["dstPort"]) != int):
            self.dstPort = -1
        else:
            self.dstPort = obj["dstPort"]
        
        if self.dstPort < 0:
            self.logs_handler.logger.warning("dst port not specified")
        
        # ipv6Dest check
        if "ipv6Dest" not in keys:
            self.logs_handler.logger.error("'ipv6Dest' field not found in input.json")
            return False
        
        obj["ipv6Dest"] = str(obj["ipv6Dest"])
        try: 
            self.ipv6Dest = obj["ipv6Dest"] if type(ip_address(obj["ipv6Dest"])) is IPv6Address else ""
        except ValueError: 
            self.logs_handler.logger.warning("ipv6Dest not specified")
        
        # type check
        if "type" not in keys:
            self.logs_handler.logger.error("'type' field not found in input.json")
            return False
        
        obj["type"] = str(obj["type"]).lower()
        if obj["type"] == "regular" or obj["type"] == "overlapping" or obj["type"] == "headerchain" \
            or obj["type"] == "overlapping-headerchain" or obj["type"] == "regular-headerchain":
            self.type = obj["type"]
        else:
            self.logs_handler.logger.error("Invalid fragmentation type")
            return False
        
        # fragment size check   
        if "fragmentSize" not in keys:
            self.logs_handler.logger.error("'fragmentSize' field not found in input.json")
            return False
        
        if "regular" in self.type:
            if type(obj["fragmentSize"]) == int and obj["fragmentSize"] >= 56:
                self.fragmentSize = obj["fragmentSize"]
            else:
                self.logs_handler.logger.warning("fragmentSize not specified, default is 1280")
        
        # fragments check
        if "fragments" not in keys:
            self.logs_handler.logger.error("'fragments' field not found in input.json")
            return False
        
        if type(obj["fragments"]) != list:
            self.logs_handler.logger.error("fragments filed must be a list")
            return False
        
        fragments = obj["fragments"]
        if "overlapping" in self.type:
            k = 1
            for frag in fragments:
                frag_keys = frag.keys()
            
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
                if type(frag["HopLimit"]) != int or frag["HopLimit"] < 0 or frag["HopLimit"] > 255:
                    self.logs_handler.logger.warning("'HopLimit' must be an integer between [0,255] in fragment %d in order to be set", k)
                    frag["HopLimit"] = -1
            
                # fragment offset check
                if "FO" not in frag_keys:
                    self.logs_handler.logger.error("'FO' field misses in fragment %d ", k)
                    return False
                if type(frag["FO"]) != int or frag["FO"] < 0:
                    self.logs_handler.logger.error("'FO' must be a positive integer in fragment %d ", k)
                    return False
                
                if "M" not in frag_keys:
                    self.logs_handler.logger.error("'M' field misses in fragment %d ", k)
                    return False
                if type(frag["M"]) != int or (frag["M"] != 0 and frag["M"] != 1):
                    self.logs_handler.logger.error("'M' must be either 0 or 1 in fragment %d ", k)
                    return False
                if frag["PayloadLenght"] % 8 != 0 and frag["M"] != 0:
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
                    
                k+=1
            
        self.fragments = fragments

        if "headerchain" in self.type:
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
                for header in frag["HeaderChain"]:
                    if type(header) == str and header.lower() == "payload":
                        headers.append(header.lower())
                    elif type(header) == dict:
                        key = list(header.keys())
                        if len(key) != 1 or key[0].lower() not in ["hopbyhop", "destination", "routing", "ah", "esp", "fragment", "mobility", "tcp", "udp"]:
                            self.logs_handler.logger.error("Can not process 'HeaderChain' field in fragment %d ", k)
                            return False
                        if key[0].lower() == "udp" and len(header["udp"]) > 0 and len(header["udp"]) <= 2:
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
                        
                        if key[0].lower() == "tcp" and len(header["tcp"]) > 0 and len(header["tcp"]) <= 3:
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
                                        self.logs_handler.logger.error("Unknown tcp flag in fragment %d, only F S R P A U E C are known", k)
                                        return False
                                self.tcp_flags = flags
                                      
                        header_value = self.header_value(key[0].lower())
                        headers.append(header_value)
                    else:
                        self.logs_handler.logger.error("Can not process 'HeaderChain' field in fragment %d ", k)
                        return False
                self.headerchain.append(headers)
                k += 1
        #print("//////////////////")
        #print(self.headerchain)
        #print(self.udp_sport, self.udp_dport)
        
        if self.dstPort < 0:
            self.logs_handler.logger.info("protocol %s, dstPort %s, ipv6Dest %s, type %s, fragmentSize %d", \
            "any" if self.protocol == "" else self.protocol, "any", \
                "any" if self.ipv6Dest == "" else self.ipv6Dest, self.type, self.fragmentSize)
        else:
             self.logs_handler.logger.info("protocol %s, dstPort %d, ipv6Dest %s, type %s, fragmentSize %d", \
            "any" if self.protocol == "" else self.protocol, self.dstPort, \
                "any" if self.ipv6Dest == "" else self.ipv6Dest, self.type, self.fragmentSize)
        
        if "overlapping" in self.type:
            k = 1
            for frag in self.fragments:
                self.logs_handler.logger.info("fragment %d\n%s", k, frag)
                k+=1
    
        return True
    
    
    
    
    
    