import hashlib
import bcrypt
import os
import sys

appData_dir = os.getenv("APPDATA")

def pass_gen(raw_pass):
    enc = hashlib.sha3_512(hashlib.sha256(raw_pass).digest()).digest()
    bcr = bcrypt.hashpw(enc, bcrypt.gensalt())
    return bcr

def read_pass(dir):
    dat = ""
    with open(dir, "rb") as read_file:
        dat = read_file.read()

    return dat

DIR = input("Enter directory path (unhidden) >> ").rstrip("/")
dir_list = DIR.split("/")

if not os.path.exists(f"{DIR}/Locker"):
    if not os.path.exists(DIR + "/Locker.{645ff040-5081-101b-9f08-00aa002f954e}"):
        with open(f"{appData_dir}\\shadows.enc", "wb") as write_file:
            inp = input("Create new password >> ").encode()
            write_file.write(pass_gen(hashlib.md5(inp).hexdigest().encode()))
            os.mkdir(f"{DIR}/Locker")
    else:
        pw = read_pass(f"{appData_dir}\\shadows.enc")
        inp = input("Enter the Password to unhide >> ").encode()
        enc = hashlib.sha3_512(hashlib.sha256(hashlib.md5(inp).hexdigest().encode()).digest()).digest()

        if(bcrypt.checkpw(enc, pw)):
            os.popen(f"attrib -h {DIR}/Locker" + '.{645ff040-5081-101b-9f08-00aa002f954e}')
            os.rename(f"{DIR}/Locker" + ".{645ff040-5081-101b-9f08-00aa002f954e}", f"{DIR}/Locker")

        else:
            print("Wrong Password!")
            sys.exit()

else:
    pw = read_pass(f"{appData_dir}\\shadows.enc")
    inp = input("Enter the Password to hide >> ").encode()
    enc = hashlib.sha3_512(hashlib.sha256(hashlib.md5(inp).hexdigest().encode()).digest()).digest()

    if(bcrypt.checkpw(enc, pw)):
        os.rename(f"{DIR}/Locker", f"{DIR}/Locker" + ".{645ff040-5081-101b-9f08-00aa002f954e}")
        os.popen(f"attrib +h {DIR}/Locker" + '.{645ff040-5081-101b-9f08-00aa002f954e}')

    else:
        print("Wrong Password!")
        sys.exit()