import Packer_Unpacker.SelfUnpack as dyn
import Static_Features.static_calculations_edited as sta
import sys
import os
import subprocess
import time
import shutil

INJECTOR_PATH = r"C:\Users\mixlh\Diploma_Toolset\Injector-master\Injector\bin\Release\netcoreapp3.1\Injector.exe"
CONFIG_PATH = r"C:\Users\mixlh\Diploma_Toolset\Injector-master\Injector\bin\Release\netcoreapp3.1\config.ini"
FILE_NUM = 10

def execute_injector(packer,out_name,out_dir):
    if not os.path.exists(f"results/{out_name}-{packer}.exe"):
        os.mkdir(f"results/{out_name}-{packer}.exe")
    os.chdir(f"results/{out_name}-{packer}.exe")
    if packer == "nopacker":
        print(f"{out_dir + out_name.split('.exe')[0] + f'-{packer}_0.exe'}")
        subprocess.check_output(f"{INJECTOR_PATH} -s {out_dir + out_name.split('.exe')[0] + f'-{packer}_0.exe'} -c {CONFIG_PATH} dll_path")
    else:
        for i in range(FILE_NUM):
            print(f"{out_dir + out_name.split('.exe')[0] + f'-{packer}_{i}.exe'}")
            subprocess.check_output(f"{INJECTOR_PATH} -s {out_dir + out_name.split('.exe')[0] + f'-{packer}_{i}.exe'} -c {CONFIG_PATH} dll_path")

def dynamic(argv):
    if argv[1] == "nopacker":
        out_name = argv[3].split(".exe")[0]
        outdir = f"{out_name}_{argv[1]}_notpacked"
        if not os.path.exists(outdir):
            os.mkdir(outdir)
        shutil.copyfile(argv[2],f"{outdir}/{out_name}-{argv[1]}_0.exe")
        execute_injector(argv[1],out_name,os.path.abspath(outdir)+ '\\')
    else:
        outdir = dyn.prepare_and_pack(argv,FILE_NUM)
        os.chdir(os.getcwd())
        out_name = argv[3].split(".exe")[0]
        execute_injector(argv[1],out_name,os.path.abspath(outdir)+ '\\')

def static(argv):
    mode = sta.Mode(1,0,0,0,0,0)
    file_inp = argv[3]
    packer = argv[2]
    if packer == "nopacker":
        file_out = argv[4].strip(".exe") + f"-{packer}_0"
        try:
            sta.process(packer,file_inp,mode,file_out)
        except Exception as e:
            print(e)
    else:
        for i in range(FILE_NUM):
            file_inp = f"{argv[4].split('.exe')[0]}_{packer}_packed/{argv[4].split('.exe')[0]}-{packer}_{i}.exe"
            file_out = argv[4].strip(".exe") + f"-{packer}_{i}"
            try:
                sta.process(packer,file_inp,mode,file_out)
            except Exception as e:
                print(e)

if __name__ == "__main__":

    if sys.argv[1] == "static":
        # Static version
        print("Correct format: static, packer,input_file_path, output_file")
        static(sys.argv)
    else:
        # Dynamic version
        print("Correct format: packer, input_file_path, output_name_WITH_EXT_.EXE")
        print(sys.argv)
        dynamic(sys.argv)