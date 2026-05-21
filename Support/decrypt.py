import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando"

try:
    dec = bytearray(base64.b64decode(enc_password))
    for i in range(len(dec)):

        dec[i] = dec[i] ^ ord(key[i % len(key)]) ^ 223
        

    password = dec.decode('latin-1')
    

    print("\n[+] Success! Decrypted Password:")
    print(f"    {password}\n")

except Exception as e:
    print(f"[-] Error decrypting password: {e}")