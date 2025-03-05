
# TODO: Change paths to relative paths

import sys
import os
import subprocess
import time
import shutil
# Add options for protect-my-tools
sys.path.insert(0, r'C:\Users\mixlh\Diploma_Toolset\Packer_Unpacker\ProtectMyTooling')

from ProtectMyTooling import main as pack

VERSION = '0.19'

options = {}
logger = None
packersloader = None
av_enable_status = -1

def clean_options():
    global options
    options = {
    'debug': False,
    'verbose': False,
    'silent': False,
    'colors': True,
    'config': '',
    'timeout': 60,
    'arch': '',
    'log': None,
    'packers': '',
    'packer_class_name': 'Packer\\w+',
    'watermark': [],
    'ioc': False,
    'custom_ioc': '',
    'ioc_path': '',
    }
    global logger
    global packersloader
    global av_enable_status
    logger = None
    packersloader = None
    av_enable_status = -1

def exec_file_and_clean(program,i):
    subprocess.run([program,"../pd64.exe","."])

    for file in os.listdir():
        if '.dll' in file:
            os.remove(file)
    while os.path.isfile(program):
        try:
            os.remove(program)
        except:
            pass
    
    unprocessed_list = []

    for file in os.listdir():
        if 'UNPROCESSED' in file:
            unprocessed_list.append(file)

    for j,file in enumerate(unprocessed_list):        
        os.rename(file,program.split('_UNPROCESSED')[0]+f'_PROCESSED_{i}_{j}.exe')

def check_args(argv):
    if ('enigma' in argv[1]):
        argv.append('--enigma-path-x86')
        argv.append('C:\\Program Files (x86)\\The Enigma Protector\\enigma64.exe')
        argv.append('--enigma-path-x64')
        argv.append('C:\\Program Files (x86)\\The Enigma Protector\\enigma64.exe')
        argv.append('--enigma-project-file')
        argv.append('C:\\Users\\mixlh\\Diploma_Toolset\\Packer_Unpacker\\enigma_conf.enigma64')

    elif ('themida' in argv[1]):
        argv.append('--themida-path-x86')
        argv.append('C:\\Users\\mixlh\\source\\repos\\Unpack-Diploma\\x64\\Release\\ProtectMyTooling\\contrib\\Themida\\Themida.exe')
        argv.append('--themida-path-x64')
        argv.append('C:\\Users\\mixlh\\source\\repos\\Unpack-Diploma\\x64\\Release\\ProtectMyTooling\\contrib\\Themida\\Themida64.exe')
        argv.append('--themida-project-file')
        argv.append('C:\\Users\\mixlh\\source\\repos\\Unpack-Diploma\\x64\\Release\\ProtectMyTooling\\contrib\\Themida\\themida_conf.tmd')

    elif ('vmprotect' in argv[1]):
        argv.append('--vmprotect-path')
        argv.append('C:\\Users\\mixlh\\source\\repos\\Unpack-Diploma\\x64\\Release\\ProtectMyTooling\\contrib\\VMProtect Demo\\VMProtect_Con.exe')

    return argv

def packunpack(argv): 

    if len(argv) < 4:
        print('Usage: SelfUnpack.py <packers> <infile> <outfile> (outfile should contain the string "_UNPROCESSED" before the extension)')
        sys.exit(1)
        
    outdir = f"out_{sys.argv[3].split('_UNPROCESSED')[0]}"

    if not os.path.exists(f"{outdir}"):
        os.mkdir(outdir)

    sys.argv = check_args(sys.argv)

    for i in range(10):
        clean_options()
        pack()
        print(sys.argv[3])
        os.replace(sys.argv[3],f"{outdir}/{sys.argv[3]}")
        os.chdir(outdir)
        exec_file_and_clean(sys.argv[3],i)
        os.chdir('..')

def prepare_and_pack(argv,file_num):

    if len(argv) < 4:
        print('Usage: SelfUnpack.py <packers> <infile> <outfile>')
        sys.exit(1)
    sys.argv = check_args(sys.argv)

    outdir = f"{argv[3].split('.exe')[0]}_{argv[1]}_packed/"
    if not os.path.exists(f"{outdir}"):
        os.mkdir(f"{outdir}")
    for i in range(file_num):
        clean_options()
        pack()
        shutil.copyfile(argv[3], outdir + argv[3].split(".exe")[0] + f'-{argv[1]}' + f'_{i}.exe')       
    return outdir 

if __name__ == '__main__':
    packunpack(sys.argv)