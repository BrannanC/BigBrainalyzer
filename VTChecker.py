from config import vt_keys
from vt_parser import VT_Hashes, VT_URL, VT_IPv4

MOD_TABLE = {
    "HASH": VT_Hashes, 
    "URL": VT_URL, 
    "IPv4": VT_IPv4
}

class VTChecker:
    def __init__(self, filename, out_file, keys, modules):
        self.keys = keys
        self.filename = filename
        self.out_file = out_file
        self.VT_Objects = []
        self.modules = modules

    def drive(self):
        for m in self.modules:
            self.VT_Objects.append(MOD_TABLE[m](self.filename, self.keys))


        for vts in self.VT_Objects:
            if self.out_file:
                vts.save_out(self.out_file)
            vts.post_process()
