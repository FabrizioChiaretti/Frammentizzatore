
import logging, sys

class log:
    
    def __init__(self, name):
        logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
        self.logger = logging.getLogger(name)
        
        