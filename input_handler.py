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
        self.fragments = []
        
    
    def parse_input(self):
        
        obj = load(self.file)
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
            self.logs_handler.logger.warning("negative port will not be used")
        
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
            or obj["type"] == "headerchain" or obj["type"] == "regular-headerchain":
            self.type = obj["type"]
        else:
            self.logs_handler.logger.warning("type not specified")
        
        # fragment size check   
        if "fragmentSize" not in keys:
            self.logs_handler.logger.error("fragmentSize not found in input.json")
            return False
        
        if type(obj["fragmentSize"]) == int and obj["fragmentSize"] >= 56:
            self.fragmentSize = obj["fragmentSize"]
        else:
            self.logs_handler.logger.warning("fragmentSize not specified, default is 1280")
        
        # fragments check
        if "fragments" not in keys:
            self.logs_handler.logger.error("fragments not found in input.json")
            return False
        
        if type(obj["fragments"]) != list:
            self.logs_handler.logger.error("invalid fragments")
            return False

        if self.dstPort < 0:
            self.logs_handler.logger.info("protocol %s, dstPort %s, ipv6Dest %s, type %s, fragmentSize %d", \
            "any" if self.protocol == "" else self.protocol, "any", \
                "any" if self.ipv6Dest == "" else self.ipv6Dest, self.type, self.fragmentSize)
        else:
             self.logs_handler.logger.info("protocol %s, dstPort %d, ipv6Dest %s, type %s, fragmentSize %d", \
            "any" if self.protocol == "" else self.protocol, self.dstPort, \
                "any" if self.ipv6Dest == "" else self.ipv6Dest, self.type, self.fragmentSize)
    
        return True
    
    
    
    
    
    