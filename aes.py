import numpy as np

class AES:
    ROW_COUNT = 4
    SUB_BYTES = [   
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]

    SUB_BYTES_INVERSE = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d               
    ]

    BITS_PER_BYTE = 8
    ROUNDS_PER_KEYSIZE = {
        128: 11,
        192: 13,
        256: 15
    }

    # Coefficients of an element of the finite field (from wikipedia)
    RC = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


    def __init__(self, key, keysize):
        # TODO: do we need the key??? :)
        self.key = key
        self.keysize = keysize                 
        self.state = []
        self.col_count = self.keysize // AES.BITS_PER_BYTE // AES.ROW_COUNT
        self.__generate_key_array(key)

        self.round_subkeys = self.__generate_round_subkeys()
        np.set_printoptions(formatter={'int':hex})
        mat = np.matrix(self.round_subkeys)
        print('original key')
        print(mat[0:4, 0:4])
        print('first round key')
        print(mat[0:4, 4:8])
        # print(self.round_subkeys)


    def encrypt_file(self, inputfile, outfile):
        last_block = False
        while not last_block:
            self.state = AES.__create_matrix(4, 4)
            byte_count = self.__read_chunk_into_state(inputfile, 16)

            last_block = (byte_count < 16)
            
            if last_block:
                # fill the rest of the block with 0's and add count at end
                self.state[3][3] = 16 - byte_count

            print("Before anything")
            print(np.matrix(self.state))

            current_roundkey = 0
            self.__add_roundkey(current_roundkey)
            print("After roundkey: " + str(current_roundkey))
            print(np.matrix(self.state))

            # do algorithm
            for _ in range(AES.ROUNDS_PER_KEYSIZE[self.keysize] - 2):
                current_roundkey += 1
                self.__sub_bytes(AES.SUB_BYTES)
                print("After sub: " + str(current_roundkey))
                print(np.matrix(self.state))

                self.__shift_rows()
                print("After shift: " + str(current_roundkey))
                print(np.matrix(self.state))

                self.__mix_columns()
                print("After mix: " + str(current_roundkey))
                print(np.matrix(self.state))

                self.__add_roundkey(current_roundkey)
                print("After roundkey: " + str(current_roundkey))
                print(np.matrix(self.state))

            current_roundkey += 1
            self.__sub_bytes(AES.SUB_BYTES)
            print("After sub: " + str(current_roundkey))

            print(np.matrix(self.state))
            self.__shift_rows()
            print("After shift: " + str(current_roundkey))

            print(np.matrix(self.state))
            self.__add_roundkey(current_roundkey)
            print("After roundkey: " + str(current_roundkey))

            print(np.matrix(self.state))

            print("Final:")
            print(np.matrix(self.state))

        self.__write_chunk_to_file(outfile, self.state)
            

    def decrypt_file(self, inputfile, outfile):
        while True:
            self.state = AES.__create_matrix(4, 4)
            byte_count = self.__read_chunk_into_state(inputfile, 16)
            
            if byte_count == 0:
                outfile.seek(-1, os.SEEK_END)
                bytes_to_remove = outfile.read(1)
                outfile.seek(-1 * bytes_to_remove, os.SEEK_END)
                outfile.truncate()
                return

            print("Before anything")
            print(np.matrix(self.state))

            current_roundkey = 0
            self.__add_roundkey(current_roundkey)
            print("After roundkey: " + str(current_roundkey))
            print(np.matrix(self.state))

            # do algorithm
            for _ in range(AES.ROUNDS_PER_KEYSIZE[self.keysize] - 2):
                current_roundkey += 1
                self.__inv_shift_rows()
                print("After shift: " + str(current_roundkey))
                print(np.matrix(self.state))
                
                self.__sub_bytes(AES.SUB_BYTES_INVERSE)
                print("After sub: " + str(current_roundkey))
                print(np.matrix(self.state))

                self.__add_roundkey(current_roundkey)
                print("After roundkey: " + str(current_roundkey))
                print(np.matrix(self.state))

                self.__inv_mix_columns()
                print("After mix: " + str(current_roundkey))
                print(np.matrix(self.state))

            current_roundkey += 1
            self.__inv_shift_rows()
            print("After shift: " + str(current_roundkey))
            print(np.matrix(self.state))

            self.__sub_bytes(AES.SUB_BYTES_INVERSE)
            print("After sub: " + str(current_roundkey))
            print(np.matrix(self.state))

            self.__add_roundkey(current_roundkey)
            print("After roundkey: " + str(current_roundkey))
            print(np.matrix(self.state))

            print("Final:")
            print(np.matrix(self.state))

        self.__write_chunk_to_file(outfile, self.state)


    def __read_chunk_into_state(self, input, chunk_size):
        chunk = input.read(chunk_size)
        byte_count = len(chunk)  
        for byte_idx in range(byte_count):
            self.state[byte_idx % 4][byte_idx // 4] = chunk[byte_idx]
        return byte_count

    def __write_chunk_to_file(self, output, chunk):
        to_write = []
        for row in range(4):
            for col in range(4):
                to_write.append(chunk[col][row])

        output.write(bytearray(to_write))


    def __generate_key_array(self, key):
        self.key_array = AES.__create_matrix(AES.ROW_COUNT, self.col_count)

        key_bytes = bytearray(key)

        index = 0
        for col in range(self.col_count):
            for row in range(AES.ROW_COUNT):
                self.key_array[row][col] = key_bytes[index]
                index = index + 1
           

    def __sub_bytes(self, sub_bytes_array):
        for row in range(AES.ROW_COUNT):
            for col in range (self.col_count):
                curr_val = self.state[row][col]
                self.state[row][col] = sub_bytes_array[curr_val]


    def __shift_rows(self):
        for row_idx in range(1, AES.ROW_COUNT):
            row = self.state[row_idx]
            for _ in range(row_idx):
                row.append(row.pop(0))


    def __inv_shift_rows(self):
        for row_idx in range(1, AES.ROW_COUNT):
            row = self.state[row_idx]
            for _ in range(row_idx):
                row.insert(0, row.pop())


    def __mix_columns(self):
        for i in range(AES.ROW_COUNT):
            col = AES.__get_col(self.state, i)
            mixed_col = AES.__gen_modular_product(col)
            for r in range(len(mixed_col)):
                self.state[r][i] = mixed_col[r][0]


    def __add_roundkey(self, round_idx):
        key_column_start_idx = round_idx * self.col_count
        for row in range(4):
            for col in range(4):
                self.state[row][col] ^= self.round_subkeys[row][key_column_start_idx + col]


    def __generate_round_subkeys(self):
        word_size = 32
        key_words = self.keysize // word_size
        total_col = 4 * AES.ROUNDS_PER_KEYSIZE[self.keysize]

        round_subkeys = AES.__create_matrix(AES.ROW_COUNT, total_col)

        for current_col in range(total_col):
            if current_col < key_words:
                AES.__put_col(round_subkeys, current_col, AES.__get_col(self.key_array, current_col))
            elif current_col >= key_words and current_col % key_words == 0:
                previous_key_col = AES.__get_col(round_subkeys, current_col - key_words)

                col_to_sub = AES.__get_col(round_subkeys, current_col - 1)
                col_to_rotate = AES.__sub_word(col_to_sub)
                rotated_col = AES.__rot_word(col_to_rotate)

                rcon_col = [[AES.RC[current_col // key_words]], [0], [0], [0]]

                finished_col = AES.__xor_word(previous_key_col, AES.__xor_word(rotated_col, rcon_col))

                AES.__put_col(round_subkeys, current_col, finished_col)
            elif current_col >= key_words and key_words > 6 and current_col % key_words == 4:
                previous_key_col = AES.__get_col(round_subkeys, current_col - key_words)

                col_to_sub = AES.__get_col(round_subkeys, current_col - 1)
                subbed_col = AES.__sub_word(col_to_sub)

                finished_col = AES.__xor_word(previous_key_col, subbed_col)

                AES.__put_col(round_subkeys, current_col, finished_col)
            else:
                previous_key_col = AES.__get_col(round_subkeys, current_col - key_words)

                other_previous_key_col = AES.__get_col(round_subkeys, current_col - 1)

                finished_col = AES.__xor_word(previous_key_col, other_previous_key_col)

                AES.__put_col(round_subkeys, current_col, finished_col)

        return round_subkeys


    @staticmethod
    def __rot_word(col):
        col.append(col.pop(0))
        return col


    @staticmethod
    def __sub_word(col):
        for row in col:
            row[0] = AES.SUB_BYTES[row[0]]
        return col

    
    @staticmethod
    def __xor_word(col_a, col_b):
        for i in range(len(col_a)):
            col_a[i][0] ^= col_b[i][0]
        
        return col_a


    # @staticmethod
    # def __matrix_multiply(mat_a, mat_b):
    #     out_m = len(mat_a)
    #     out_n = len(mat_b[0])

    #     out_mat = AES.__create_matrix(out_m, out_n)

    #     for out_r in range(out_m):
    #         for out_c in range(out_n):
    #             for other_val in range(len(mat_a[0])):
    #                 out_mat[out_r][out_c] ^= AES.__mult(mat_a[out_r][other_val], mat_b[other_val][out_c])

    #     return out_mat


    @staticmethod 
    def __create_matrix(num_rows, num_cols):
        out_mat = []
        for _ in range(num_rows):
            row = []
            for _ in range(num_cols):
                row.append(0)
            out_mat.append(row)
        return out_mat


    @staticmethod
    def __get_col(mat_a, col_idx):
        col = []

        for row in mat_a:
            col.append([row[col_idx]])

        return col


    @staticmethod
    def __put_col(mat_a, col_idx, col):
        for row_idx in range(len(mat_a)):
            mat_a[row_idx][col_idx] = col[row_idx][0]

        return mat_a


    @staticmethod
    def __gen_modular_product(byteList):
        a0b0 = AES.__pow_2_shift(byteList[0][0], 0x02)
        a0b1 = AES.__pow_2_shift(byteList[1][0], 0x02)
        a0b2 = AES.__pow_2_shift(byteList[2][0], 0x02)
        a0b3 = AES.__pow_2_shift(byteList[3][0], 0x02)

        a1b0 = AES.__pow_2_shift(byteList[0][0], 0x01)
        a1b1 = AES.__pow_2_shift(byteList[1][0], 0x01)
        a1b2 = AES.__pow_2_shift(byteList[2][0], 0x01)
        a1b3 = AES.__pow_2_shift(byteList[3][0], 0x01)
        
        a2b0 = AES.__pow_2_shift(byteList[0][0], 0x01)
        a2b1 = AES.__pow_2_shift(byteList[1][0], 0x01)
        a2b2 = AES.__pow_2_shift(byteList[2][0], 0x01)
        a2b3 = AES.__pow_2_shift(byteList[3][0], 0x01)
        
        a3b0 = AES.__pow_2_shift(byteList[0][0], 0x02) ^ AES.__pow_2_shift(byteList[0][0], 0x01)
        a3b1 = AES.__pow_2_shift(byteList[1][0], 0x02) ^ AES.__pow_2_shift(byteList[1][0], 0x01)
        a3b2 = AES.__pow_2_shift(byteList[2][0], 0x02) ^ AES.__pow_2_shift(byteList[2][0], 0x01)
        a3b3 = AES.__pow_2_shift(byteList[3][0], 0x02) ^ AES.__pow_2_shift(byteList[3][0], 0x01)

        result = []

        # 03 01 01 02
        # d0 =        a0b0 + a3b1 + a2b2 + a1b3
        result.append([a0b0 ^ a3b1 ^ a2b2 ^ a1b3])
        # d1 =        a1b0 + a0b1 + a3b2 + a2b3
        result.append([a1b0 ^ a0b1 ^ a3b2 ^ a2b3])
        # d2 =        a2b0 + a1b1 + a0b2 + a3b3
        result.append([a2b0 ^ a1b1 ^ a0b2 ^ a3b3])
        # d3 =        a3b0 + a2b1 + a1b2 + a0b3
        result.append([a3b0 ^ a2b1 ^ a1b2 ^ a0b3])
        return result


    @staticmethod
    def __pow_2_shift(byte, shift):
        if shift == 1:
            return byte
        byte = byte << 1
        # print "Byte after shift: %x" % byte
        # printBinary(byte)
        if (byte & 0x100):
            # print "There is a 1 in the 8th position"
            byte = byte ^ 0x11b
        # print "Byte after adjustment: %x" % byte
        return AES.__pow_2_shift(byte, shift >> 1)
