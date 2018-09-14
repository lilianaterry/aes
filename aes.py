
class AES:
    def __init__(self, key, keysize):
        self.key = key
        self.keysize = keysize
        for byte in self.key:
            print(byte)


    def encrypt_file(self, inputfile, outfile):
        pass


    def decrypt_file(self, inputfile, outfile):
        pass


    def __sub_bytes(self):
        pass


    def __shift_rows(self):
        pass


    def __mix_columns(self):
        pass


    def __add_roundkey(self):
        pass
