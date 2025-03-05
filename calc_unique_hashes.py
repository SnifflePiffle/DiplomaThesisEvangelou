import os
import hashlib


file_count = 0
unique_hashes = set()
for root,_,files in os.walk('results'):
    sub_count = 0
    len_file = None
    for file in files:

        if os.path.isdir(file) or "injector" in file or "enigma" not in file:
            continue
        else:
            f = open(root + '/' + file,"rb").read()

            if not len_file:
                len_file = len(f)
            #hashh = hashlib.md5(f).hexdigest()
            #if hashh in unique_hashes:
            #    print(file)
            #else:
            #    unique_hashes.add(hashh)
            sub_count += 1
            if len_file -1000 < len(f) < len_file + 1000:
                continue
            print(len_file,len(f))
            len_file = max(len_file,len(f))

            file_count += 1



print(file_count) # results --> 3402
                  # static_results --> 3491

                  
