import json

class inputHandler:
    
    def __init__(self, file):
        
        self.file = file
        self.protocol = ""    
        self.dstPort = ""
        self.ipv6Dest = "" 
        self.type = "" 
        self.fragmentSize = ""
        self.fragments = []
    
    
    def parse_input(self):
        
        obj = json.load(self.file)
        keys = obj.keys()
        values = obj.values()
        
        # protocol check
        if "protocol" not in keys:
            print("error: protocol not found in input.json")
            return False
        
        obj["protocol"] = str(obj["protocol"]).lower()
        if obj["protocol"] != "" and obj["protocol"] != "icmpv6" and obj["protocol"] != "tcp" and obj["protocol"] != "udp":
            print("error: protocol not valid\navailable protocols are tcp, udp, icmpv6 or empty string")
            return False
        
        self.protocol = obj["protocol"]
        
        #dstPort check
        if "dstPort" not in keys:
            print("error: dstPort not found in input.json")
            return False
        
        if (self.protocol != "udp" and self.protocol != "tcp") or (type(obj["dstPort"]) != int):
            self.dstPort = -1
        else:
            self.dstPort = obj["dstPort"] # negative ports will not be used
        
        # ipv6 dest check
        if "ipv6Dest" not in keys:
            print("error: ipv6Dest not found in input.json")
            return False
        
        if "type" not in keys:
            print("error: type not found in input.json")
            return False
            
        if "fragmentSize" not in keys:
            print("error: fragmentSize not found in input.json")
            return False
        
        if "fragments" not in keys:
            print("error: fragments not found in input.json")
            return False
    
        return True
    
    
    
    
    
    