from aes import AES

def run(keypath, keysize, inputfile, outputfile, mode, operation):
    with open(keypath, 'rb') as key_content:
        key = key_content.read()

    aes = AES(key, keysize)

    if mode == 'encrypt':
        with open(inputfile, 'rb') as plaintext, open(outputfile, 'w+b') as encrypted:
            aes.encrypt_file(plaintext, encrypted, operation)

    elif mode == 'decrypt':
        with open(inputfile, 'rb') as encrypted, open(outputfile, 'w+b') as plaintext:
            aes.decrypt_file(encrypted, plaintext, operation)
            
    else:
        raise Exception('invalid mode provided')
