# AES cryptor for shellcode

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

data = input("Enter your shellcode: ")
data = bytes.fromhex(data)

key = "Sixteen byte key".encode()
cipher = AES.new(key, AES.MODE_CBC)
ciphertext = cipher.iv + cipher.encrypt(pad(data, cipher.block_size))
print(cipher.iv.hex())

print(ciphertext.hex())
print(key.hex())
