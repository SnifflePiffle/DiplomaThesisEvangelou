# https://www.researchgate.net/publication/3437909_Using_Entropy_Analysis_to_Find_Encrypted_and_Packed_Malware

import math
import argparse
import sys
import pefile

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
        self.results = []
        self.labels = []
        self.file_path = file_path
        self.peobj = pefile.PE(self.file_path)


    def measure_entropy(self):
        bytes_dict = {byte:0 for byte in range(0,256)}

        for byte in self.file:
            bytes_dict[byte] += 1

        entropy = Helpers.calc_entropy(bytes_dict,self.file_len)
        if 6.677 <= entropy <= 7.267:
            self.labels.append("Packed")
        else:
            self.labels.append("Not Packed")

        self.results.append(f"Entropy: {entropy}")

    def find_base(self):
        self.results.append("Image Base: " + hex(self.peobj.OPTIONAL_HEADER.ImageBase))
        self.results.append("Address of EntryPoint: " + hex(self.peobj.OPTIONAL_HEADER.AddressOfEntryPoint + self.peobj.OPTIONAL_HEADER.ImageBase))

    def find_sec_info(self):        
        packed = False
        res_str = ""
        for section in self.peobj.sections:
            if "UPX" in section.Name.decode():
                packed = True
            res_str += f"\t{section.Name.decode()}: {Helpers.map_charact_to_perm(int(section.Characteristics))}\n" 
        if packed:
            self.labels.append("Packed")
        else:
            self.labels.append("Not Packed")

        
        self.results.append(f"Sections: ->\n{res_str}")
        return

    def find_imp_names(self):
        res_str = ""
        import_count = 0
        for entry in self.peobj.DIRECTORY_ENTRY_IMPORT:
            res_str += f"\t{entry.dll.decode()}\n"
            for imp in entry.imports:
                res_str += f"\t\t{imp.name.decode()}\n" 
                import_count += 1

        if import_count < 10:
            self.labels.append("Packed")
        else:
            self.labels.append("Not Packed")

        self.results.append(f"Imports: ->\n{res_str}")

    def measure_all(self):
        self.measure_entropy()
        self.find_base()
        self.find_sec_info()
        self.find_imp_names()

def main():

    parser = argparse.ArgumentParser(prog='static_calculations',description='Calculate Static Features (e.g. entropy, segments etc.)')
    parser.add_argument('-f', '--file', help='File to be analyzed',required=True)
    parser.add_argument('-a', '--all', help='Perform all static measurements',action='store_true',required=False)
    parser.add_argument('-e', '--entropy', help='Calculate the entropy of the executable',action='store_true',required=False)
    parser.add_argument('-s', '--section_info', help='Get the section names of the executable',action='store_true',required=False)
    parser.add_argument('-i', '--imports', help='Get the imports of the executable',action='store_true',required=False)
    parser.add_argument('-b', '--base', help='Get the base address and EP address of the executable',action='store_true',required=False)

    args = parser.parse_args()
    if len(sys.argv) < 4:
        print('You have to provide the File and the Mode')
        exit(1)

    with open(args.file,"rb") as f:
        measure = Measurements(args.file,f.read())
        if args.all:
            measure.measure_all()
        else:
            if args.entropy:
                measure.measure_entropy()
            if args.section_info:
                measure.find_sec_info()
            if args.imports:
                measure.find_imp_names()
            if args.base:
                measure.get_base()

    for r in measure.results:
        print(r)

    if measure.labels.count("Packed") >= measure.labels.count("Not Packed"):
        print("Packed")
    else:
        print("Not Packed")

if __name__ == "__main__":
    main()