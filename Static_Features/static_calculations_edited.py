# https://www.researchgate.net/publication/3437909_Using_Entropy_Analysis_to_Find_Encrypted_and_Packed_Malware

import math
import argparse
import sys
import pefile
import tlsh as pytlsh
import pyssdeep
import hashlib
import os
import json

class Mode:
    def __init__(self,_all,entropy,section_info,imports,base,_hash):
        self.all = _all
        self.entropy = entropy
        self.section_info = section_info
        self.imports = imports
        self.base = base
        self.hash = _hash

class Helpers:

    def calc_entropy(vals_dict,length):
        probs = [val/length for val in vals_dict.values()]
        entropy = sum([-prob * math.log2(prob) if prob != 0 else 0 for prob in probs])
        return entropy
    
    def map_charact_to_perm(charact):
        # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header

        perms = ["-"]*3
        parsed_charact = charact >> 28
        if parsed_charact >= 0x8:
            parsed_charact -= 0x8
            perms[1] = "w"
        if parsed_charact >= 0x4:
            parsed_charact -= 0x4
            perms[0] = "r"
        if parsed_charact >= 0x2:
            parsed_charact -= 0x2
            perms[2] = "x"

        try:
            assert parsed_charact == 0
        except:
            print("Not Correctly Implemented or Other error")
            exit(1)

        return ''.join(perms) 


class Measurements:

    def __init__(self,file_path,file):
        self.file = file
        self.file_len = len(file)
        self.results = {}
        self.file_path = file_path
        self.peobj = pefile.PE(self.file_path)


    def measure_entropy(self):
        bytes_dict = {byte:0 for byte in range(0,256)}

        for byte in self.file:
            bytes_dict[byte] += 1

        entropy = Helpers.calc_entropy(bytes_dict,self.file_len)

        self.results["Entropy"] = entropy

    def find_base(self):
        self.results["Image Base"] = hex(self.peobj.OPTIONAL_HEADER.ImageBase)
        self.results["Address EP"] = hex(self.peobj.OPTIONAL_HEADER.AddressOfEntryPoint + self.peobj.OPTIONAL_HEADER.ImageBase)

    def find_sec_info(self):        
        res_json = []
        for section in self.peobj.sections:
            res_json.append((section.Name.decode().replace("\x00",""),Helpers.map_charact_to_perm(int(section.Characteristics))))
        
        self.results["Sections"]  = res_json
        return

    def find_imp_names(self):
        res_json = {}
        for entry in self.peobj.DIRECTORY_ENTRY_IMPORT:
            res_json[entry.dll.decode()] = []
            for imp in entry.imports:
                res_json[entry.dll.decode()].append(imp.name.decode()) 

        self.results["Imports"] =res_json

    def compute_hashes(self):
        ssdeep = pyssdeep.get_hash_buffer(self.file)
        tlsh = pytlsh.hash(self.file)
        imphash = self.peobj.get_imphash()

        self.results["SSDEEP"] = ssdeep
        self.results["TLSH"] = tlsh
        self.results["ImpHash"] = imphash

        sec_ssdeep = []
        sec_tlsh = []
        sec_md5 = []

        for section in self.peobj.sections:
            sec_ssdeep.append((section.Name.decode().replace("\x00",""),pyssdeep.get_hash_buffer(section.get_data())))
            sec_tlsh.append((section.Name.decode().replace("\x00",""),pytlsh.hash(section.get_data())))
            sec_md5.append((section.Name.decode().replace("\x00",""),hashlib.md5(section.get_data()).hexdigest()))
        
        self.results["Per Section SSDEEP"] = sec_ssdeep
        self.results["Per Section TLSH"] = sec_tlsh
        self.results["Per Section MD5"] = sec_md5

    def measure_all(self):
        self.measure_entropy()
        self.find_base()
        self.find_sec_info()
        self.find_imp_names()
        self.compute_hashes()

def process(packer,file,mode,output):

    
    # ADD IMPHASH AND PER SECTION SSDEEP / TLSH. Also add MD5 per section.

    with open(file,"rb") as f:
        measure = Measurements(file,f.read())
        if mode.all:
            measure.measure_all()
        else:
            if mode.entropy:
                measure.measure_entropy()
            if mode.section_info:
                measure.find_sec_info()
            if mode.imports:
                measure.find_imp_names()
            if mode.base:
                measure.get_base()
            if mode.hash:
                measure.compute_hashes()

    filename = file.split('\\')[-1].split("_out")[0].removesuffix(".exe")
    out_dir = f"static_results/{filename}_out-{packer}.exe"

    if not os.path.isdir(out_dir):
        os.mkdir(out_dir)
    
    f = open(f"{out_dir}/{output}.json","w")
    json.dump(measure.results,f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='static_calculations',description='Calculate Static Features (e.g. entropy, segments etc.)')
    parser.add_argument('-p','--packer',help='Packer Used (type None if no packing was used)',required=True)
    parser.add_argument('-f', '--file', help='File to be analyzed',required=True)
    parser.add_argument('-a', '--all', help='Perform all static measurements',action='store_true',required=False)
    parser.add_argument('-e', '--entropy', help='Calculate the entropy of the executable',action='store_true',required=False)
    parser.add_argument('-s', '--section_info', help='Get the section names of the executable',action='store_true',required=False)
    parser.add_argument('-i', '--imports', help='Get the imports of the executable',action='store_true',required=False)
    parser.add_argument('-b', '--base', help='Get the base address and EP address of the executable',action='store_true',required=False)
    parser.add_argument('-H', '--hash', help='Calculate TLSH and SSDEEP hashes of the executables',action='store_true',required=False)
    parser.add_argument('-o','--output',help="Output file name",required=True)

    args = parser.parse_args()

    mode = Mode(args.all,args.entropy,args.section_info,args.imports,args.base,args.hash)

    process(args.packer,args.file,mode,args.output)