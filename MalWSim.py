import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding



def create_setup():
    directory_name = "test_directory"
    file_name = "test_file"

    for i in range(1,6):
        if not os.path.exists(directory_name):
            create_dir = directory_name + "_" + str(i)
            os.makedirs(create_dir)
            for j in range(1,11):
                with open(os.path.join(create_dir, f"{file_name}_{j}.txt"), "w") as f:
                    f.write("Random test data for ransomware simulator " + str(i) + " " + str(j) )

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



def additional_commands():
    pass


create_setup()
encrypt_file()
