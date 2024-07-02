from json import load
from ipaddress import ip_address, IPv6Address 
from log import log


class inputHandler:
    
    def __init__(self, file, logs_handler):
        
        self.file = file
        self.logs_handler = logs_handler
        self.protocol = ""    
        self.dstPort = ""
        self.ipv6Dest = "" 
        self.type = "regular" 
        self.fragmentSize = 1280
        self.fragments = None
        
    
    def parse_input(self):
        
        try:
            obj = load(self.file)
        except:
            self.logs_handler.logger.error("json decoding error")
            return False
        keys = obj.keys()
        
        # protocol check
        if "protocol" not in keys:
            self.logs_handler.logger.error("protocol not found")
            return False
        
        obj["protocol"] = str(obj["protocol"]).lower()
        if obj["protocol"] == "icmpv6" or obj["protocol"] == "tcp" or obj["protocol"] == "udp" or obj["protocol"] == "ipv6":
            self.protocol = obj["protocol"]
        else:
            self.logs_handler.logger.warning("protocol not specified")
        
        #dstPort check
        if "dstPort" not in keys:
            self.logs_handler.logger.error("dstPort not found in input.json")
            return False
        
        if (self.protocol != "udp" and self.protocol != "tcp") or (type(obj["dstPort"]) != int):
            self.dstPort = -1
        else:
            self.dstPort = obj["dstPort"]
        
        if self.dstPort < 0:
            self.logs_handler.logger.warning("dst port not specified")
        
        # ipv6Dest check
        if "ipv6Dest" not in keys:
            self.logs_handler.logger.error("ipv6Dest not found in input.json")
            return False
        
        obj["ipv6Dest"] = str(obj["ipv6Dest"])
        try: 
            self.ipv6Dest = obj["ipv6Dest"] if type(ip_address(obj["ipv6Dest"])) is IPv6Address else ""
        except ValueError: 
            self.logs_handler.logger.warning("ipv6Dest not specified")
        
        # type check
        if "type" not in keys:
            self.logs_handler.logger.error("type not found in input.json")
            return False
            
        obj["type"] = str(obj["type"]).lower()
        if obj["type"] == "regular" or obj["type"] == "overlapping" or obj["type"] == "overlapping-headerchain" \
            or obj["type"] == "regular-headerchain":
            self.type = obj["type"]
        else:
            self.logs_handler.logger.warning("type not specified")
        
        # fragment size check   
        if "fragmentSize" not in keys:
            self.logs_handler.logger.error("fragmentSize not found in input.json")
            return False
        if "regular" in self.type:
            if type(obj["fragmentSize"]) == int and obj["fragmentSize"] >= 56:
                self.fragmentSize = obj["fragmentSize"]
            else:
                self.logs_handler.logger.warning("fragmentSize not specified, default is 1280")
        
        # fragments check
        if "fragments" not in keys:
            self.logs_handler.logger.error("fragments not found in input.json")
            return False
        
        if type(obj["fragments"]) != list:
            self.logs_handler.logger.error("fragments filed must be a list")
            return False

        if "overlapping" in self.type or "headerchain" in self.type:
            fragments = obj["fragments"]
            k = 1
            for frag in fragments:
                frag_keys = frag.keys()
            
                # payload lenght check
                if "PayloadLenght" not in frag_keys:
                    self.logs_handler.logger.error("'PayloadLenght' misses in fragment %d ", k)
                    return False
                if type(frag["PayloadLenght"]) != int:
                    self.logs_handler.logger.error("'PayloadLenght' must be a positive integer in fragment %d ", k)
                    return False
            
                # hop limit check
                if "HopLimit" not in frag_keys:
                    self.logs_handler.logger.error("'HopLimit' misses in fragment %d ", k)
                    return False
                if type(frag["HopLimit"]) != int or frag["HopLimit"] < 0 or frag["HopLimit"] > 255:
                    self.logs_handler.logger.warning("'HopLimit' must be an integer between [0,255] in fragment %d in order to be set", k)
                    frag["HopLimit"] = -1
            
                # fragment offset check
                if "FO" not in frag_keys:
                    self.logs_handler.logger.error("'FO' misses in fragment %d ", k)
                    return False
                if type(frag["FO"]) != int or frag["FO"] < 0:
                    self.logs_handler.logger.error("'FO' must be a positive integer in fragment %d ", k)
                    return False
                
                if "M" not in frag_keys:
                    self.logs_handler.logger.error("'M' misses in fragment %d ", k)
                    return False
                if type(frag["M"]) != int or (frag["M"] != 0 and frag["M"] != 1):
                    self.logs_handler.logger.error("'M' must be either 0 or 1 in fragment %d ", k)
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
                    key = list(header.keys())
                    if len(key) != 1 or key[0].lower() not in ["hopbyhop", "destination", "routing", "ah", "esp", "fragment", "mobility"]:
                        self.logs_handler.logger.error("Can not process 'HeaderChain' field in fragment %d ", k)
                        return False
                    headers.append(key[0])
                k += 1
        
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
    
    
    
    
    
    