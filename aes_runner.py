from aes import AES

def run(keypath, keysize, inputfile, outputfile, mode):
    with open(keypath, 'rb') as key_content:
        key = key_content.read()

    aes = AES(key, keysize)

    if mode == 'encrypt':
        with open(inputfile, 'rb') as plaintext, open(outputfile, 'w+b') as encrypted:
            aes.encrypt_file(plaintext, encrypted)

    elif mode == 'decrypt':
        with open(inputfile, 'rb') as encrypted, open(outputfile, 'w+b') as plaintext:
            aes.decrypt_file(encrypted, plaintext)
            
    else:
        raise Exception('invalid mode provided')
